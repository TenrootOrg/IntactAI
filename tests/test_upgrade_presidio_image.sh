#!/bin/bash
# An upgrade must load the Presidio image the package carries.
#
# 2026-10-07: a fresh intact-20261007 install loaded intact-presidio (install
# loads every tar in the package), but the upgrade's intact step loaded only
# intact-backend -- so a box upgraded from a release without Presidio got the
# code that runs the sidecar and never the image. Found by reading the engine
# before the operator's 0915 -> 1007 upgrade test, not by the suite.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

log_info() { :; }; log_warn() { echo "WARN $*" >>"$T/log"; }; log_error() { :; }
source "${ROOT}/lib/upgrade/intact/config.sh"
source "${ROOT}/lib/upgrade/intact/image.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export UPKG_DIR="$T/pkg"; mkdir -p "$UPKG_DIR/images"
ENVF="$T/.env"
_u_image_present() { return 1; }
_u_stamp() { echo "$2" >>"$T/stamped"; }

echo "== the package's Presidio tar is loaded and its version pinned =="
: >"$UPKG_DIR/images/intact-presidio-2.2.364.tar"
_u_ensure_image() { echo "$1 $2" >>"$T/ensured"; return 0; }
_intact_ensure_presidio "$ENVF"; rc=$?
[[ $rc -eq 0 ]] && ok "returns 0" || fail "returns 0" "rc=$rc"
[[ "$(cat "$T/ensured" 2>/dev/null)" == "intact-presidio:2.2.364 intact-presidio-2.2.364.tar" ]] \
    && ok "loads intact-presidio:2.2.364 from its tar" || fail "loads the tar" "$(cat "$T/ensured" 2>/dev/null)"
grep -qx 'PRESIDIO_VERSION=2.2.364' "$T/stamped" 2>/dev/null \
    && ok "pins PRESIDIO_VERSION" || fail "pins PRESIDIO_VERSION"

echo "== a failed load never fails the upgrade =="
rm -f "$T/ensured" "$T/stamped"
_u_ensure_image() { return 1; }
_intact_ensure_presidio "$ENVF"; rc=$?
[[ $rc -eq 0 ]] && ok "load failure is non-fatal" || fail "load failure is non-fatal" "rc=$rc"
[[ ! -f "$T/stamped" ]] && ok "no pin for an image that did not load" || fail "no pin on failure"

echo "== a package without the tar is a warning, not a failure =="
rm -f "$UPKG_DIR/images/"*.tar "$T/log"
_u_ensure_image() { echo called >>"$T/ensured"; return 0; }
_intact_ensure_presidio "$ENVF"; rc=$?
[[ $rc -eq 0 && ! -f "$T/ensured" ]] && ok "no tar: nothing loaded, rc 0" || fail "no tar" "rc=$rc"
grep -q 'no Presidio image' "$T/log" 2>/dev/null && ok "says so" || fail "says so"

echo "== the intact upgrade runs the step =="
grep -q '_intact_ensure_presidio "\$envf"' "${ROOT}/lib/upgrade/intact/intact.sh" \
    && ok "intact.sh calls _intact_ensure_presidio" || fail "intact.sh calls _intact_ensure_presidio"

echo
echo "${PASS}/${TOTAL} passed"
[[ $PASS -eq $TOTAL ]]
