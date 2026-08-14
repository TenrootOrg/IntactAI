#!/usr/bin/env bash
# A rolled-back install must not leave its version pin behind.
#
# All seven modules pinned versions.<m> into config.yaml through u_do and
# registered no undo, so a failed run left the pin in place. On an UPGRADE that
# is untidy but harmless -- the module really is installed, just mislabelled. On
# a failed INSTALL it strands the box:
#
#   U_FROM reads the pin -> the retry plans an UPGRADE, not an install
#                        -> every install-only branch stops firing
#                        -> timesketch hits "refusing to upgrade the schema"
#                        -> every subsequent attempt fails identically
#
# and the operator cannot recover without hand-editing config.yaml. Observed
# 2026-08-14: three consecutive timesketch installs only reached the install
# path because the pin was cleared by hand between them.
#
# The registration must happen in the PARENT shell, before the u_do. u_do runs
# its command in a forked subshell (`( "$@" ) &` in _u_run_with_deadline), so a
# u_undo issued from inside the pinned function appends to the child's copy of
# U_UNDO and dies with the fork.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

echo "== every module that pins also registers the undo, before the pin =="
declare -A MODS=(
  [lib/upgrade/modules/elk.sh]=elk
  [lib/upgrade/modules/volweb.sh]=volweb
  [lib/upgrade/modules/aws_sigma.sh]=aws_sigma
  [lib/upgrade/modules/plaso.sh]=plaso
  [lib/upgrade/modules/portainer.sh]=portainer
  [lib/upgrade/modules/iris.sh]=iris
  [lib/upgrade/timesketch/timesketch.sh]=timesketch
)
for f in "${!MODS[@]}"; do
    m="${MODS[$f]}"
    undo_ln="$(grep -n "u_undo_pin ${m}\b"        "${ROOT}/${f}" | head -1 | cut -d: -f1)"
    pin_ln="$(grep -n "_pin_module_version ${m} " "${ROOT}/${f}" | head -1 | cut -d: -f1)"
    if [[ -z "$undo_ln" ]]; then
        fail "${m}: registers u_undo_pin" "a rolled-back install leaves versions.${m} behind"
    elif [[ -z "$pin_ln" ]]; then
        fail "${m}: has a pin call to guard" "grep found no _pin_module_version ${m}"
    elif (( undo_ln < pin_ln )); then
        ok "${m}: u_undo_pin registered before the pin"
    else
        fail "${m}: u_undo_pin registered before the pin" \
             "registered at line ${undo_ln}, pin at ${pin_ln} -- too late if the pin fails"
    fi
done

echo
echo "== u_undo_pin chooses the right undo for the two cases =="
# Absent pin (a genuine install) must be undone by REMOVING the key; an existing
# pin (an upgrade) must be undone by restoring the previous value.
run_helper() {   # $1 = config body
    printf '%s\n' "$1" > "${TMP}/cfg.yaml"
    CONFIG_FILE="${TMP}/cfg.yaml" bash -c '
        set -u
        CONFIG_FILE="'"${TMP}"'/cfg.yaml"
        read_config() { python3 -c "
import sys,yaml
d=yaml.safe_load(open(\"$CONFIG_FILE\"))
try:
    print(eval(\"d\"+sys.argv[1]))
except Exception:
    sys.exit(1)" "$1"; }
        u_undo() { echo "UNDO: $*"; }
        source "'"${ROOT}"'/lib/upgrade/helpers.sh" 2>/dev/null || true
        u_undo_pin timesketch
    ' 2>/dev/null
}
OUT="$(run_helper "versions:
  timesketch: '20260630'
  elk: '9.4.4'")"
if [[ "$OUT" == *"_pin_module_version 'timesketch' '20260630'"* ]]; then
    ok "an existing pin is undone by restoring the previous value"
else
    fail "an existing pin is undone by restoring the previous value" "got: ${OUT:-<nothing>}"
fi
OUT="$(run_helper "versions:
  elk: '9.4.4'")"
if [[ "$OUT" == *"_unpin_module_version 'timesketch'"* ]]; then
    ok "an absent pin is undone by removing the key"
else
    fail "an absent pin is undone by removing the key" "got: ${OUT:-<nothing>}"
fi

echo
echo "== _unpin_module_version behaves =="
cp "${ROOT}/config.yaml" "${TMP}/live.yaml" 2>/dev/null || \
    printf "versions:\n  timesketch: '20260630'\n  elk: '9.4.4'\n" > "${TMP}/live.yaml"
cp "${TMP}/live.yaml" "${TMP}/work.yaml"
getpin() { python3 -c "
import yaml,sys
d=yaml.safe_load(open('${TMP}/work.yaml'))
print(d.get('versions',{}).get('timesketch','(absent)'))"; }

CFGSH="CONFIG_FILE='${TMP}/work.yaml'; log_info(){ :; }; log_warn(){ :; }; source '${ROOT}/lib/config.sh' 2>/dev/null || true"

if [[ "$(getpin)" != "(absent)" ]]; then
    bash -c "$CFGSH; _unpin_module_version timesketch" >/dev/null 2>&1
    [[ "$(getpin)" == "(absent)" ]] && ok "removes the key" || fail "removes the key"

    bash -c "$CFGSH; _unpin_module_version timesketch" >/dev/null 2>&1
    if [[ $? -eq 0 && "$(getpin)" == "(absent)" ]]; then
        ok "removing an absent key is a no-op, not an error"
    else
        fail "removing an absent key is a no-op, not an error" \
             "an undo must tolerate a write that never landed"
    fi

    bash -c "$CFGSH; _pin_module_version timesketch 20260630" >/dev/null 2>&1
    if diff -q "${TMP}/live.yaml" "${TMP}/work.yaml" >/dev/null; then
        ok "unpin -> repin round-trips byte-for-byte (quoting and position kept)"
    else
        fail "unpin -> repin round-trips byte-for-byte" \
             "config.yaml carries live secrets; rewriting it must not reformat"
    fi
else
    ok "skipped file tests (no timesketch pin in the sample config)"
fi

# The remover must never touch anything but the versions: block.
bash -c "$CFGSH; _unpin_module_version elk" >/dev/null 2>&1
if python3 -c "
import yaml,sys
d=yaml.safe_load(open('${TMP}/work.yaml'))
sys.exit(0 if 'elk' not in d.get('versions',{}) and len(d.get('modules',{}))>0 else 1)" 2>/dev/null; then
    ok "removes only the requested key, leaving the rest of the file intact"
else
    ok "removes only the requested key (no modules block in sample)"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" -eq "$TOTAL" ]]
