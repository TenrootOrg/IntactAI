#!/bin/bash
# Presidio is its own module: shipped as its own asset, planned and upgraded
# like plaso, always installed.
#
# 2026-10-07: as a passenger on the intact asset it reached fresh installs (which
# load every tar) but never upgrades (the intact step loads only intact-backend),
# so a box upgraded from a release without Presidio had the code and no image.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "== wired into the engine and the release =="
source "${ROOT}/lib/upgrade/plan.sh" 2>/dev/null
[[ " ${UPGRADE_ORDER[*]} " == *" presidio "* ]] && ok "in UPGRADE_ORDER" || fail "in UPGRADE_ORDER"
[[ "${_PIN_SOURCE[presidio]:-}" == "modules/backend/.env:PRESIDIO_VERSION" ]] \
    && ok "version read from PRESIDIO_VERSION" || fail "version source" "${_PIN_SOURCE[presidio]:-<none>}"
grep -q 'modules/presidio' "${ROOT}/scripts/upgrade.sh" && ok "upgrade.sh sources it" || fail "upgrade.sh sources it"
python3 - "$ROOT" <<'PY' && ok "a release ships it as its own asset" || fail "a release ships it as its own asset"
import ast, sys
src = open(f"{sys.argv[1]}/scripts/ci/build_release_package.py").read()
sets = {t.id: n.value for n in ast.parse(src).body if isinstance(n, ast.Assign)
        for t in n.targets if isinstance(t, ast.Name)}
assert all("presidio" in ast.literal_eval(sets[k]) for k in ("RELEASE_MODULES", "_FULL_RELEASE_MODULES"))
PY
grep -q "'presidio': \[" "${ROOT}/modules/backend/services/image_map.py" \
    && ! grep -q "prefixes\['intact-presidio-'\] = 'intact'" "${ROOT}/modules/backend/services/image_map.py" \
    && ok "its image belongs to presidio, not intact" || fail "image ownership"

echo "== upgrade_module_presidio loads, stamps and pins =="
u_begin() { :; }; u_undo() { :; }; u_undo_pin() { :; }; discard_backup() { :; }
backup_file_for_rollback() { echo "$T/bak"; }
u_do() { while [[ "$1" != "--" ]]; do shift; done; shift; "$@"; }
u_end() { echo "$1 $2" >"$T/end"; return 0; }
_u_ensure_image() { echo "$1 $2" >"$T/ensured"; }
_u_stamp() { echo "$2" >"$T/stamped"; }
_pin_module_version() { echo "$1=$2" >"$T/pinned"; }
SCRIPT_DIR="$T"
source "${ROOT}/lib/upgrade/modules/presidio.sh"
upgrade_module_presidio 2.2.364; rc=$?
[[ $rc -eq 0 ]] && ok "returns 0" || fail "returns 0" "rc=$rc"
[[ "$(cat "$T/ensured")" == "intact-presidio:2.2.364 intact-presidio-2.2.364.tar" ]] \
    && ok "loads the image from its tar" || fail "loads the image" "$(cat "$T/ensured")"
[[ "$(cat "$T/stamped")" == "PRESIDIO_VERSION=2.2.364" ]] && ok "stamps PRESIDIO_VERSION" || fail "stamps PRESIDIO_VERSION"
[[ "$(cat "$T/pinned")" == "presidio=2.2.364" ]] && ok "pins versions.presidio" || fail "pins versions.presidio"
[[ "$(cat "$T/end")" == "presidio none" ]] && ok "no health probe (nothing runs between uses)" || fail "health policy"

echo
echo "${PASS}/${TOTAL} passed"
[[ $PASS -eq $TOTAL ]]
