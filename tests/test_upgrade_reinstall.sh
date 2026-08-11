#!/bin/bash
# Two things that both looked fine and both did nothing:
#
#   1. The GUI's "reinstall" tick on a module already at the target version.
#      It was forwarded as --only, and --only is checked BEFORE the version
#      comparison, so plan.sh still classified the module noop and skipped it.
#      The operator ticked a box, the request succeeded, and the module was
#      never touched (found 2026-08-11).
#
#   2. Fixing (1) by adding --reinstall immediately broke something worse: the
#      stage-0 hop forwards the operator's arguments verbatim to the TARGET
#      package's own upgrade.sh, whose parser rejects unknown options with
#      exit 2. So a new backend importing any older package died before
#      touching anything -- verified against a real intact-20260817 package,
#      which is exactly the "sat on a USB stick for a month" case that has no
#      way to fetch a newer one.
#
# Both are silent-failure shapes, which is why they get a suite rather than a
# line in a run log.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

echo "== plan.sh: --reinstall promotes a noop to an upgrade =="

# plan.sh's classification, exercised directly. Sourcing the whole engine
# would drag in docker, the config loader and a real package; the branch under
# test is a string comparison against one global.
_classify() {
    # $1 = module, $2 = current, $3 = target, $4 = UPGRADE_REINSTALL
    local m="$1" current="$2" target="$3" UPGRADE_REINSTALL="$4"
    if [[ "$current" == "$target" ]]; then
        if [[ -n "${UPGRADE_REINSTALL:-}" && ",${UPGRADE_REINSTALL}," == *",${m},"* ]]; then
            echo "upgrade"; return
        fi
        echo "noop"; return
    fi
    echo "upgrade"
}

check "same version, not requested -> noop" \
      "$(_classify portainer 2.39.5 2.39.5 "")" "noop"
check "same version, requested -> upgrade" \
      "$(_classify portainer 2.39.5 2.39.5 "portainer")" "upgrade"
check "same version, requested among others -> upgrade" \
      "$(_classify portainer 2.39.5 2.39.5 "elk,portainer,iris")" "upgrade"
check "same version, a DIFFERENT module requested -> still noop" \
      "$(_classify portainer 2.39.5 2.39.5 "elk,iris")" "noop"
check "substring must not match ('portainer' vs 'porta')" \
      "$(_classify porta 1 1 "portainer")" "noop"
check "version gap is an upgrade regardless" \
      "$(_classify portainer 2.39.4 2.39.5 "")" "upgrade"

echo
echo "== the real plan.sh carries this branch =="
if grep -q 'UPGRADE_REINSTALL' "${ROOT}/lib/upgrade/plan.sh"; then
    ok "plan.sh consults UPGRADE_REINSTALL"
else
    fail "plan.sh consults UPGRADE_REINSTALL" "the branch is gone; the tick is dead again"
fi
if grep -q -- '--reinstall)' "${ROOT}/lib/upgrade/args.sh"; then
    ok "args.sh parses --reinstall"
else
    fail "args.sh parses --reinstall"
fi
if grep -q -- '_validate_module_list "$UPGRADE_REINSTALL" --reinstall' "${ROOT}/lib/upgrade/args.sh"; then
    ok "a typo'd --reinstall module is rejected, not silently ignored"
else
    fail "a typo'd --reinstall module is rejected"
fi

echo
echo "== the routes actually send it =="
R="${ROOT}/modules/backend/routes/upgrade_routes.py"
if grep -q '"--reinstall", ",".join(reinstall)' "$R"; then
    ok "online route forwards the reinstall opt-ins"
else
    fail "online route forwards the reinstall opt-ins"
fi
if grep -q '"--reinstall", ",".join(reinstall_modules)' "$R"; then
    ok "import route forwards the reinstall opt-ins"
else
    fail "import route forwards the reinstall opt-ins"
fi
# The lists must be DISJOINT. Import briefly sent its whole selected list as
# --reinstall, which the engine tolerated (plan.sh only reads it on the noop
# branch) but which rendered as "reinstall everything" in the log and the
# launch script -- not what was asked for, and not what happened.
if grep -q 'reinstall_modules if m not in selected_modules' "$R"; then
    ok "a reinstall for a module outside the run is rejected"
else
    fail "a reinstall for a module outside the run is rejected"
fi
if grep -q 'reinstall_modules:' "${ROOT}/modules/nginx/html/js/stores/settings.js"; then
    ok "the Import modal sends reinstall_modules"
else
    fail "the Import modal sends reinstall_modules" "backend cannot re-derive which ticks were no-change"
fi

echo
echo "== stage-0 hop: an older packaged engine must not choke on it =="

# The filter from scripts/upgrade.sh, against fabricated target trees: one
# whose args.sh knows --reinstall and one whose does not.
log_warn() { :; }
_U_DROPPABLE_OPTS=" --reinstall "
_u_forwardable_args() {
    local target_sh="$1"; local -n _out="$2"
    local target_args="${target_sh%/scripts/upgrade.sh}"
    [[ "$target_args" == "$target_sh" ]] && target_args="${target_sh%/upgrade.sh}"
    target_args="${target_args}/lib/upgrade/args.sh"
    _out=()
    local i=0 a
    while (( i < ${#_ORIG_ARGS[@]} )); do
        a="${_ORIG_ARGS[$i]}"
        local bare="${a%%=*}"
        if [[ "$_U_DROPPABLE_OPTS" == *" ${bare} "* ]] \
           && ! grep -q -- "${bare})" "$target_args" 2>/dev/null; then
            log_warn "dropping ${bare}"
            [[ "$a" == *=* ]] || i=$((i + 1))
            i=$((i + 1))
            continue
        fi
        _out+=("$a")
        i=$((i + 1))
    done
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for kind in old new; do
    mkdir -p "${TMP}/${kind}/lib/upgrade" "${TMP}/${kind}/scripts"
    touch "${TMP}/${kind}/scripts/upgrade.sh"
done
printf '%s\n' '--only) X ;;' '--skip) Y ;;'       > "${TMP}/old/lib/upgrade/args.sh"
printf '%s\n' '--only) X ;;' '--reinstall) Z ;;'  > "${TMP}/new/lib/upgrade/args.sh"

fwd() { local -n _r=OUT; _ORIG_ARGS=("${@:2}"); _u_forwardable_args "$1" OUT; echo "${OUT[*]}"; }

check "old engine: --reinstall and its value are both dropped" \
      "$(fwd "${TMP}/old/scripts/upgrade.sh" --only intact,portainer --reinstall portainer --dry-run)" \
      "--only intact,portainer --dry-run"
check "old engine: the --reinstall=x form is dropped as one token" \
      "$(fwd "${TMP}/old/scripts/upgrade.sh" --only=intact --reinstall=portainer --dry-run)" \
      "--only=intact --dry-run"
check "new engine: --reinstall survives" \
      "$(fwd "${TMP}/new/scripts/upgrade.sh" --only intact --reinstall portainer)" \
      "--only intact --reinstall portainer"
check "nothing else is ever dropped" \
      "$(fwd "${TMP}/old/scripts/upgrade.sh" --only intact --expect-sha256 abc123 --dry-run)" \
      "--only intact --expect-sha256 abc123 --dry-run"
# The allowlist is the whole point: dropping a digest anchor would turn a
# package that should be REFUSED into one that gets applied.
check "--expect-sha256 is not droppable even though the old engine is fake" \
      "$(fwd "${TMP}/old/scripts/upgrade.sh" --expect-sha256 deadbeef)" \
      "--expect-sha256 deadbeef"

if grep -q '_u_forwardable_args' "${ROOT}/scripts/upgrade.sh"; then
    ok "the hop in scripts/upgrade.sh uses the filter"
else
    fail "the hop in scripts/upgrade.sh uses the filter" "args are forwarded raw again"
fi
# The exec is wrapped across two lines, so this anchors on its last argument
# rather than the whole statement.
if grep -q '__root "\$SCRIPT_DIR" "\${_fwd\[@\]}"' \
        <(sed 's/^ *//; s/^--root/__root/' "${ROOT}/scripts/upgrade.sh"); then
    ok "the hop execs the FILTERED args, not _ORIG_ARGS"
else
    fail "the hop execs the filtered args" "still passing _ORIG_ARGS verbatim"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
