#!/bin/bash
# The upgrade lock across the hop, Stop in the module loop, the exit code after
# the post-upgrade gate, and the keep-for-retry marker (QA items B1, B2, B3).
#
#   B1  Dashboard runs enter at bootstrap_upgrade.sh, which execs upgrade.sh with
#       INTACT_UPGRADE_REEXEC=1 and no fd 9 -- and the lock was taken only when
#       that variable was unset, so no dashboard upgrade ever held it.
#   B2  A Stop was re-discovered by each later module and every one of them was
#       "ROLLED_BACK, restored to <from>"; a gate failure still exited 0.
#   B3  The keep marker was cleared only on the no-keep exit, so after one
#       failed image load every later run kept its ~15 GB extraction; Stop after
#       a failed load deleted the very tree the log said it kept.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh
ROOT="$(cd .. && pwd)"
UPGRADE_SH="${ROOT}/scripts/upgrade.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT_DIR="${TMP}/appliance"
mkdir -p "${SCRIPT_DIR}/data/tmp"
LOG_FILE="${SCRIPT_DIR}/data/tmp/upgrade-r1.log"
: > "$LOG_FILE"
DOCKER_BIN=docker
source ../lib/common.sh
source ../lib/upgrade/core.sh
source ../lib/upgrade/package.sh
source ../lib/upgrade/interrupt.sh
source ../lib/upgrade/report.sh
log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }
u_probe_module()  { echo "up test stub"; }
u_containers_of() { echo ""; }
u_crashlooping_of() { echo ""; }
capture_diagnostic_logs() { :; }
_human_size() { echo "${1:-0}B"; }

LOCK="${SCRIPT_DIR}/data/tmp/upgrade.lock"

# ---------------------------------------------------------------------------
# B1: the lock. The open-or-reuse block is lifted out of upgrade.sh itself
# (main() cannot be sourced), so these test the real lines, not a copy.
# ---------------------------------------------------------------------------
_take_sh() {
    {
        echo 'take() {'
        echo '    local _lock="$1"'
        awk '/^        local _fd9 _want$/{p=1} /^        if ! flock -n 9; then$/{exit} p' "$UPGRADE_SH"
        echo '    flock -n 9'
        echo '}'
        echo 'if take "$1"; then echo LOCKED; else echo REFUSED; fi'
        echo 'sleep "${HOLD:-0}"'
    } > "${TMP}/take.sh"
    grep -q 'exec 9>' "${TMP}/take.sh" || _fail "could not lift the lock block out of upgrade.sh"
}
_take_sh
_held() { ! flock -n "$LOCK" true; }

test_a_dashboard_run_takes_the_lock() {
    SCRIPT_DIR="$SCRIPT_DIR" INTACT_UPGRADE_REEXEC=1 HOLD=2 bash "${TMP}/take.sh" "$LOCK" > "${TMP}/out1" &
    local pid=$!
    sleep 0.7
    assert_true _held
    wait "$pid"
    assert_eq "$(cat "${TMP}/out1")" "LOCKED"
}

test_a_second_run_is_refused() {
    flock "$LOCK" sleep 2 &
    local pid=$!
    sleep 0.5
    assert_eq "$(SCRIPT_DIR="$SCRIPT_DIR" INTACT_UPGRADE_REEXEC=1 bash "${TMP}/take.sh" "$LOCK")" "REFUSED"
    wait "$pid"
}

test_the_cli_hop_does_not_deadlock_on_its_own_lock() {
    # The old upgrade.sh holds fd 9, then execs bootstrap -> the target upgrade.sh.
    cat > "${TMP}/cli.sh" <<EOF
exec 9>"$LOCK"
flock -n 9 || { echo PARENT-REFUSED; exit 9; }
SCRIPT_DIR="$SCRIPT_DIR" INTACT_UPGRADE_REEXEC=1 HOLD=2 exec bash "${TMP}/take.sh" "$LOCK"
EOF
    bash "${TMP}/cli.sh" > "${TMP}/out2" &
    local pid=$!
    sleep 0.7
    assert_true _held
    wait "$pid"
    assert_eq "$(cat "${TMP}/out2")" "LOCKED"
}

test_a_foreign_fd9_is_replaced_by_the_lock() {
    cat > "${TMP}/foreign.sh" <<EOF
exec 9>"${TMP}/something-else"
SCRIPT_DIR="$SCRIPT_DIR" INTACT_UPGRADE_REEXEC=1 HOLD=2 exec bash "${TMP}/take.sh" "$LOCK"
EOF
    bash "${TMP}/foreign.sh" > "${TMP}/out3" &
    local pid=$!
    sleep 0.7
    assert_true _held
    wait "$pid"
    assert_eq "$(cat "${TMP}/out3")" "LOCKED"
}

test_only_a_hopped_dry_run_skips_the_lock() {
    assert_true grep -qF 'if [[ -z "${INTACT_UPGRADE_REEXEC:-}" ]] || (( ! UPGRADE_DRY_RUN )); then' "$UPGRADE_SH"
    # u_clear_run_state must run under the lock, i.e. after the flock refusal.
    local block
    block="$(awk '/^        if ! flock -n 9; then$/{p=1} p; /^    # ---.*velo-refresh/{exit}' "$UPGRADE_SH")"
    assert_contains "$block" "u_clear_run_state"
}

# ---------------------------------------------------------------------------
# B2: Stop ends the module loop; the gate counts in the exit code.
# ---------------------------------------------------------------------------
_loop_fn() {
    {
        echo '_loop() {'
        awk '/^    local m fn$/{p=1} p; p && /^    done$/{exit}' "$UPGRADE_SH"
        echo '}'
    } > "${TMP}/loop.sh"
    # shellcheck disable=SC1091
    source "${TMP}/loop.sh"
}
_loop_fn

test_a_stop_skips_every_later_module_instead_of_rolling_it_back() {
    UPGRADE_OK=(); UPGRADE_DEGRADED=(); UPGRADE_ROLLED_BACK=(); UPGRADE_FAILED=(); UPGRADE_SKIPPED=()
    rm -f "${LOG_FILE%.log}.cancel"
    ORDER="${TMP}/order"; : > "$ORDER"
    UPGRADE_ORDER=(a b c)
    declare -gA PLAN_ACTION=([a]=upgrade [b]=upgrade [c]=upgrade)
    declare -gA PLAN_CURRENT=([a]=1 [b]=1 [c]=1)
    declare -gA PLAN_TARGET=([a]=2 [b]=2 [c]=2)
    _u_failed_requirement() { return 1; }
    upkg_extract_deferred() { return 0; }
    _u_prune_old_module_images() { :; }
    _mod() {
        u_begin "$1"
        u_undo "echo undo:$1 >> '$ORDER'"
        [[ "$1" == a ]] && : > "${LOG_FILE%.log}.cancel"     # Stop lands mid-module
        u_do "work" -- bash -c "echo ran:$1 >> '$ORDER'"
        u_end "$1" none
    }
    upgrade_module_a() { _mod a; }
    upgrade_module_b() { _mod b; }
    upgrade_module_c() { _mod c; }
    _loop
    assert_eq "$(tr '\n' ',' < "$ORDER")" "undo:a," "only the module in flight unwinds"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "1"
    assert_contains "${UPGRADE_ROLLED_BACK[*]:-}" "a —"
    assert_contains "${UPGRADE_SKIPPED[*]:-}" "b — cancelled before it started"
    assert_contains "${UPGRADE_SKIPPED[*]:-}" "c — cancelled before it started"
    rm -f "${LOG_FILE%.log}.cancel"
}

test_a_post_gate_error_makes_the_exit_code_non_zero() {
    UPGRADE_OK=("elk 1 -> 2"); UPGRADE_DEGRADED=(); UPGRADE_ROLLED_BACK=(); UPGRADE_FAILED=()
    U_POST_GATE_ERRORS=0
    assert_eq "$(upgrade_exit_code)" "0"
    U_POST_GATE_ERRORS=1
    assert_eq "$(upgrade_exit_code)" "3"
    UPGRADE_ROLLED_BACK=("iris — x")
    assert_eq "$(upgrade_exit_code)" "1" "a rollback still outranks it"
    U_POST_GATE_ERRORS=0; UPGRADE_ROLLED_BACK=()
}

test_the_gate_delta_is_wired_into_upgrade_sh() {
    assert_true grep -q 'U_POST_GATE_ERRORS=\$(( \${#INSTALL_ERRORS\[@\]} - _errs_before ))' "$UPGRADE_SH"
}

# ---------------------------------------------------------------------------
# B3: the keep marker.
# ---------------------------------------------------------------------------
_scratch() {
    local d="${SCRIPT_DIR}/data/tmp/upgrade-pkg-$1"
    mkdir -p "${d}/images"
    UPKG_SCRATCH="$d"; UPKG_DIR="$d"
    printf '%s' "$d"
}

test_the_marker_is_cleared_even_when_the_tree_is_kept() {
    U_KEEP_SCRATCH=0; u_clear_run_state
    local d; d="$(_scratch keep1)"; UPKG_SCRATCH="$d"; UPKG_DIR="$d"
    u_mark_keep_scratch
    echo 100 >> "$(_upkg_tally_file)"
    _u_exit_cleanup
    assert_true test -d "$d"
    assert_false u_keep_scratch_requested
    assert_eq "$(u_tars_freed_bytes)" "0" "the tally must not carry into the next run"
}

test_an_unlocked_dry_run_leaves_the_live_runs_marker_alone() {
    # A dashboard preflight (hopped --dry-run, no lock) exiting beside a live
    # run that already marked its tree for keeping.
    U_KEEP_SCRATCH=0; u_clear_run_state
    u_mark_keep_scratch; U_KEEP_SCRATCH=0
    echo 100 >> "$(_upkg_tally_file)"
    local d; d="$(_scratch dryrun)"
    ( UPKG_SCRATCH="$d"; UPKG_DIR="$d"; U_LOCK_HELD=0; _u_exit_cleanup ) >/dev/null 2>&1
    assert_true u_keep_scratch_requested
    assert_eq "$(u_tars_freed_bytes)" "100" "the live run's tally must survive"
    assert_false test -d "$d"
    assert_true grep -q '^        U_LOCK_HELD=1$' "$UPGRADE_SH"
    u_clear_run_state
}

test_stop_after_a_failed_load_keeps_the_tree() {
    U_KEEP_SCRATCH=0; u_clear_run_state
    local d; d="$(_scratch keep2)"
    ( UPKG_SCRATCH="$d"; UPKG_DIR="$d"; U_MODULE=""; _U_RUNNING_PID=""
      u_mark_keep_scratch; _u_handle_interrupt ) >/dev/null 2>&1
    assert_true test -d "$d"
    u_clear_run_state
}

test_stop_without_keep_still_reclaims() {
    U_KEEP_SCRATCH=0; u_clear_run_state
    local d; d="$(_scratch nokeep)"
    ( UPKG_SCRATCH="$d"; UPKG_DIR="$d"; U_MODULE=""; _U_RUNNING_PID=""
      _u_handle_interrupt ) >/dev/null 2>&1
    assert_false test -d "$d"
}

run_all_tests
