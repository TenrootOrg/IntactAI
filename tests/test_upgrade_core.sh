#!/bin/bash
# lib/upgrade/core.sh — the four primitives every module upgrade is built from.
#
# The properties tested here are the ones that, if they broke, would break
# silently and be discovered only by an operator whose appliance is in a state
# nobody designed: a module half-upgraded because a step ran after an earlier
# one failed, or a rollback that unwound in the wrong order and left a new
# .env beside an old image.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$(cd .. && pwd)"
DOCKER_BIN=docker
source ../lib/common.sh
source ../lib/upgrade/core.sh

# Quiet the primitives: they log through lib/common.sh, which writes to stdout
# as well as $LOG_FILE, and 60 lines of banner per test buries the failures.
log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

_reset_run_state() {
    UPGRADE_OK=(); UPGRADE_DEGRADED=(); UPGRADE_ROLLED_BACK=()
    UPGRADE_FAILED=(); UPGRADE_SKIPPED=()
    U_FROM="1.0"; U_TO="2.0"; U_STEP_N=1; U_STEP_TOTAL=1
    : > "$LOG_FILE"
    ORDER_FILE="$(mktemp)"
}

# Test doubles that record the fact they ran, so "did this step execute?" is
# answerable rather than inferred.
_ok_step()   { echo "ran:$1" >> "$ORDER_FILE"; return 0; }
_bad_step()  { echo "ran:$1" >> "$ORDER_FILE"; echo "boom from $1" >> "$LOG_FILE"; return 7; }
_undo_step() { echo "undo:$1" >> "$ORDER_FILE"; return 0; }
_undo_fail() { echo "undo:$1" >> "$ORDER_FILE"; return 3; }

# u_end consults these; give them harmless defaults so a core test never
# depends on health.sh or on a real docker daemon.
u_probe_module()  { echo "up test stub"; }
u_containers_of() { echo ""; }
capture_diagnostic_logs() { :; }

# ---------------------------------------------------------------------------
# u_do
# ---------------------------------------------------------------------------

test_steps_run_in_order_on_the_happy_path() {
    _reset_run_state
    u_begin demo
    u_do "one" -- _ok_step one
    u_do "two" -- _ok_step two
    u_end demo none
    assert_eq "$(tr '\n' ',' < "$ORDER_FILE")" "ran:one,ran:two,"
    assert_eq "${#UPGRADE_OK[@]}" "1"
}

test_a_failed_step_short_circuits_every_later_step() {
    # The single most important property in this file. Without it a module
    # body would need an `if !` around every call, and the one someone forgets
    # is the one that runs `docker volume rm` after the backup already failed.
    _reset_run_state
    u_begin demo
    u_do "one"   -- _ok_step one
    u_do "two"   -- _bad_step two
    u_do "three" -- _ok_step three
    u_do "four"  -- _ok_step four
    u_end demo none
    assert_not_contains "$(cat "$ORDER_FILE")" "ran:three" \
        "step 3 must not run after step 2 failed"
    assert_not_contains "$(cat "$ORDER_FILE")" "ran:four"
}

test_the_first_failure_is_reported_not_the_last() {
    _reset_run_state
    u_begin demo
    u_do "the real cause" -- _bad_step a
    u_do "later noise"    -- _bad_step b
    u_end demo none
    assert_eq "$U_LABEL" "the real cause"
    assert_eq "$U_RC" "7"
}

test_u_do_returns_nonzero_but_never_exits() {
    _reset_run_state
    u_begin demo
    u_do "boom" -- _bad_step x
    local rc=$?
    assert_eq "$rc" "1" "u_do reports failure via its return code"
    assert_eq "$U_FAILED" "1"
    u_end demo none
}

test_failure_detail_is_scoped_to_what_that_step_logged() {
    # Detail comes from a byte offset taken before the step, not a blind tail,
    # so heartbeat lines written by a concurrent step cannot be misattributed.
    _reset_run_state
    echo "OLD UNRELATED LINE" >> "$LOG_FILE"
    u_begin demo
    u_do "boom" -- _bad_step x
    assert_contains "$U_DETAIL" "boom from x"
    assert_not_contains "$U_DETAIL" "OLD UNRELATED LINE"
    u_end demo none
}

# ---------------------------------------------------------------------------
# u_undo / u_end
# ---------------------------------------------------------------------------

test_undo_stack_unwinds_lifo() {
    # Registration order is coarse-to-fine; unwind must therefore be
    # fine-to-coarse, so files are back before the bring-up that reads them.
    _reset_run_state
    u_begin demo
    u_undo _undo_step bring_up_old
    u_undo _undo_step restore_env
    u_do "boom" -- _bad_step x
    u_end demo none
    assert_eq "$(grep '^undo:' "$ORDER_FILE" | tr '\n' ',')" \
        "undo:restore_env,undo:bring_up_old," \
        "last registered must unwind first"
}

test_a_successful_transaction_never_runs_its_undos() {
    _reset_run_state
    u_begin demo
    u_undo _undo_step bring_up_old
    u_do "one" -- _ok_step one
    u_end demo none
    assert_not_contains "$(cat "$ORDER_FILE")" "undo:"
    assert_eq "${#UPGRADE_OK[@]}" "1"
    assert_eq "${#U_UNDO[@]}" "0" "the stack must be cleared after commit"
}

test_rollback_success_and_rollback_failure_are_different_outcomes() {
    # "we put it back" and "we could not put it back" are different operator
    # situations. Collapsing them into one list is how a half-reverted module
    # gets missed in the report.
    _reset_run_state
    u_begin demo
    u_undo _undo_step restore_env
    u_do "boom" -- _bad_step x
    u_end demo none
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "1"
    assert_eq "${#UPGRADE_FAILED[@]}" "0"

    _reset_run_state
    u_begin demo
    u_undo _undo_fail restore_env
    u_do "boom" -- _bad_step x
    u_end demo none
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "0"
    assert_eq "${#UPGRADE_FAILED[@]}" "1"
    assert_contains "${UPGRADE_FAILED[0]}" "ROLLBACK FAILED"
}

test_every_undo_is_attempted_even_after_one_of_them_fails() {
    # Bailing out of the unwind on the first error would leave the remaining,
    # coarser undos unapplied -- i.e. the container never restarted.
    _reset_run_state
    u_begin demo
    u_undo _undo_step bring_up_old
    u_undo _undo_fail restore_env
    u_do "boom" -- _bad_step x
    u_end demo none
    assert_contains "$(cat "$ORDER_FILE")" "undo:bring_up_old" \
        "a failing undo must not abort the rest of the unwind"
}

test_u_end_never_calls_track_module_success() {
    # The install path's habit is: health poll times out, log a warning, call
    # track_module_success anyway. The upgrade path must not have that escape
    # hatch at all -- so assert the function is never invoked, rather than
    # merely that the outcome happened to be right.
    _reset_run_state
    track_module_success() { echo "track_module_success $*" >> "$STUB_LOG"; }
    u_probe_module() { echo "down stubbed outage"; }
    u_begin demo
    u_do "one" -- _ok_step one
    u_end demo rollback 1
    u_probe_module() { echo "up test stub"; }
    assert_eq "$(stub_call_count track_module_success)" "0"
}

test_state_does_not_leak_between_transactions() {
    _reset_run_state
    u_begin first
    u_undo _undo_step leftover
    u_do "boom" -- _bad_step x
    u_end first none
    u_begin second
    assert_eq "${#U_UNDO[@]}" "0"
    assert_eq "$U_FAILED" "0"
    assert_eq "$U_LABEL" ""
    u_do "one" -- _ok_step one
    u_end second none
    assert_eq "${#UPGRADE_OK[@]}" "1" "the second module must be able to succeed"
}

# ---------------------------------------------------------------------------
# Exit-code mapping
# ---------------------------------------------------------------------------

test_exit_code_zero_when_everything_committed_cleanly() {
    _reset_run_state
    UPGRADE_OK=("elk 1 -> 2")
    assert_eq "$(upgrade_exit_code)" "0"
}

test_exit_code_three_when_something_is_degraded() {
    _reset_run_state
    UPGRADE_OK=("elk 1 -> 2"); UPGRADE_DEGRADED=("volweb — DOWN")
    assert_eq "$(upgrade_exit_code)" "3"
}

test_exit_code_one_when_anything_rolled_back_or_failed() {
    _reset_run_state
    UPGRADE_OK=("elk 1 -> 2"); UPGRADE_ROLLED_BACK=("iris — health gate")
    assert_eq "$(upgrade_exit_code)" "1"

    _reset_run_state
    UPGRADE_DEGRADED=("volweb — DOWN"); UPGRADE_FAILED=("iris — ROLLBACK FAILED")
    assert_eq "$(upgrade_exit_code)" "1" \
        "a failure outranks a degradation"
}

test_exit_code_zero_when_nothing_needed_doing() {
    _reset_run_state
    UPGRADE_SKIPPED=("elk — already at 9.4.4")
    assert_eq "$(upgrade_exit_code)" "0"
}

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

test_backup_and_restore_round_trip_preserves_the_destination_inode() {
    # .env files are env_file: sources for running containers. Restoring by
    # `mv` would swap the inode under the mount and the change would appear to
    # work while the container kept reading the old content.
    _reset_run_state
    local d; d="$(mktemp -d)"
    printf 'A=1\nB=2\n' > "${d}/.env"
    local before bak
    before="$(stat -c %i "${d}/.env")"
    bak="$(backup_file_for_rollback "${d}/.env")"
    printf 'A=999\n' > "${d}/.env"
    assert_true restore_file_from_backup "${d}/.env" "$bak"
    assert_eq "$(cat "${d}/.env")" "$(printf 'A=1\nB=2')"
    assert_eq "$(stat -c %i "${d}/.env")" "$before"
    rm -rf "$d"
}

test_backing_up_a_missing_file_reports_failure_rather_than_a_bogus_path() {
    _reset_run_state
    assert_false backup_file_for_rollback /nonexistent/path/.env
    assert_eq "$(backup_file_for_rollback /nonexistent/path/.env 2>/dev/null)" ""
}

test_read_env_var_distinguishes_absent_from_empty() {
    _reset_run_state
    local d; d="$(mktemp -d)"
    printf 'SET=value\nQUOTED="q"\nEMPTY=\n' > "${d}/.env"
    assert_eq "$(read_env_var "${d}/.env" SET)" "value"
    assert_eq "$(read_env_var "${d}/.env" QUOTED)" "q" "one layer of quotes is stripped"
    assert_true  read_env_var "${d}/.env" EMPTY
    assert_eq "$(read_env_var "${d}/.env" EMPTY)" ""
    assert_false read_env_var "${d}/.env" ABSENT
    rm -rf "$d"
}

test_read_env_var_does_not_match_a_commented_out_key() {
    _reset_run_state
    local d; d="$(mktemp -d)"
    printf '#REAL=commented\nREAL=actual\n' > "${d}/.env"
    assert_eq "$(read_env_var "${d}/.env" REAL)" "actual"
    rm -rf "$d"
}

run_all_tests
rm -f "$LOG_FILE"
