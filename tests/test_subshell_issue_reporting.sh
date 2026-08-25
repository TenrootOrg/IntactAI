#!/usr/bin/env bash
# A warning raised inside $( ) never reaches the final report.
#
# THE BUG THIS EXISTS FOR. log_warn/log_error (lib/common.sh) do two things:
# write the line for the operator, and append to INSTALL_WARNINGS /
# INSTALL_ERRORS, which print_final_issues_report reads at the end of a run.
# Inside a command substitution both are lost -- the array append dies with the
# fork, and the console line is swallowed into the captured variable. Only
# $LOG_FILE survives.
#
# Measured on a real air-gapped upgrade 2026-08-25: "legacy volume
# velociraptor_velociraptor_data has no readable mountpoint" appeared in the
# log file, was absent from the ATTENTION summary, and the summary's own count
# was one short. The worst instance was _stage_system_bundle_from_source, where
# the swallowed line is a log_ERROR and the caller does `|| exit 1` with no EXIT
# trap -- an air-gapped install with a corrupt bundle tar died with status 1 and
# printed nothing about why.
#
# The fix in both cases is an out-variable so the function runs in the caller's
# shell. This test pins that, and demonstrates the failure mode is real rather
# than theoretical.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run=0; failed=0
ok()   { printf '  \033[0;32mok\033[0m   - %s\n' "$1"; }
bad()  { printf '  \033[0;31mFAIL\033[0m - %s\n' "$1"; failed=$((failed+1)); }
pass() { run=$((run+1)); ok "$1"; }
fail() { run=$((run+1)); bad "$1"; }

# Does <pattern> appear on a NON-COMMENT line of any of <files>?
# Comment lines are excluded because the fixes' own explanations quote the
# broken form verbatim, and a naive grep matches the documentation.
code_has() {
    local pat="$1"; shift
    local f
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        if grep -v '^[[:space:]]*#' "$f" | grep -q -- "$pat"; then return 0; fi
    done
    return 1
}
assert_absent() {  # <desc> <pattern> <files...>
    local desc="$1" pat="$2"; shift 2
    if code_has "$pat" "$@"; then fail "$desc"; else pass "$desc"; fi
}
assert_present() { # <desc> <pattern> <file>
    local desc="$1" pat="$2" f="$3"
    if grep -q -- "$pat" "$f" 2>/dev/null; then pass "$desc"; else fail "$desc"; fi
}

echo "== the failure mode is real (non-vacuous) =="
demo="$(mktemp)"; trap 'rm -f "$demo"' EXIT
cat > "$demo" <<'SH'
WARNINGS=()
log_warn() { echo "[WARN] $*"; WARNINGS+=("$*"); }
substituted() { log_warn "lost"; echo "/some/path"; }
outvar()      { OUT=""; log_warn "kept"; OUT="/some/path"; }
p="$(substituted)"; echo "after-substitution=${#WARNINGS[@]}"
outvar;            echo "after-outvar=${#WARNINGS[@]}"
SH
res="$(bash "$demo")"
if [[ "$res" == *"after-substitution=0"* ]]; then
    pass "a warning inside \$( ) is lost from the array"
else fail "a warning inside \$( ) is lost from the array"; fi
if [[ "$res" == *"after-outvar=1"* ]]; then
    pass "the same warning via an out-variable is kept"
else fail "the same warning via an out-variable is kept"; fi

echo
echo "== the two fixed functions use out-variables, not stdout =="
SNAP="$ROOT/lib/upgrade/velociraptor/snapshot.sh"
DEPS="$ROOT/lib/deps.sh"
UHD="$ROOT/scripts/update_host_deps.sh"

assert_present "_velo_volume_path sets _VELO_VOL_MP" '_VELO_VOL_MP="$mp"' "$SNAP"
assert_absent  "its caller does not wrap it in \$( )" 'mp="$(_velo_volume_path' "$SNAP"
assert_present "_stage_system_bundle_from_source sets _STAGED_BUNDLE_DIR" \
               '_STAGED_BUNDLE_DIR="$extract_dir"' "$DEPS"
assert_absent  "no caller wraps _stage_system_bundle_from_source in \$( )" \
               '="$(_stage_system_bundle_from_source' "$DEPS" "$UHD"

echo
echo "== seed_volweb_admin reports the pipeline's real status =="
VW="$ROOT/lib/modules/volweb.sh"
assert_present "it reads PIPESTATUS[0], not \$?" 'PIPESTATUS\[0\]' "$VW"
run=$((run+1))
if sed -n '/^seed_volweb_admin()/,/^}/p' "$VW" | grep -vE '^[[:space:]]*#' | grep -qE '^[[:space:]]*return \$\?[[:space:]]*$'; then
    bad "no bare 'return \$?' left in seed_volweb_admin"
else ok "no bare 'return \$?' left in seed_volweb_admin"; fi
# Its callers must stay warn-only: this function must never fail a run.
assert_present "the install caller only warns" 'if ! seed_volweb_admin; then' "$VW"
assert_present "the upgrade caller only warns" 'seed_volweb_admin || log_warn' \
               "$ROOT/lib/upgrade/modules/volweb.sh"

echo
echo "== an already-extracted package is still an air-gapped run =="
UPG="$ROOT/scripts/upgrade.sh"
run=$((run+1))
# The --package-dir branch must set the air-gap flags; it returns early and
# used to skip the block below that sets them.
if sed -n '/if \[\[ -n "${UPGRADE_PACKAGE_DIR:-}" \]\]; then/,/^    else$/p' "$UPG" \
     | grep -q 'INTACT_AIRGAP=1'; then
    ok "--package-dir sets INTACT_AIRGAP"
else bad "--package-dir sets INTACT_AIRGAP"; fi
run=$((run+1))
if sed -n '/if \[\[ -n "${UPGRADE_PACKAGE_DIR:-}" \]\]; then/,/^    else$/p' "$UPG" \
     | grep -q 'INTACT_UPGRADE_OFFLINE=1'; then
    ok "--package-dir sets INTACT_UPGRADE_OFFLINE"
else bad "--package-dir sets INTACT_UPGRADE_OFFLINE"; fi

echo
echo "== a failed YARA import is reported, not swallowed =="
assert_present "a failing import raises a warning" 'import FAILED' "$VW"
assert_present "the summary names which rulesets failed" 'failed: ${failed_names' "$VW"
run=$((run+1))
# Non-vacuous: the old code logged every response at INFO unconditionally.
if sed -n '/for entry in "${rulesets\[@\]}"/,/^    done$/p' "$VW" | grep -qE 'log_info "      \$\{resp:0:200\}"' \
   && sed -n '/for entry in "${rulesets\[@\]}"/,/^    done$/p' "$VW" | grep -q 'log_warn'; then
    ok "the success path still logs at INFO (only failures warn)"
else bad "the success path still logs at INFO (only failures warn)"; fi

echo
echo "$(basename "$0"): ${run} run, ${failed} failed"
[[ $failed -eq 0 ]]
