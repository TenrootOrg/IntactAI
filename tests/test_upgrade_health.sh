#!/bin/bash
# lib/upgrade/health.sh — the three-verdict gate, and the one regression it
# exists to prevent.
#
# THE REGRESSION. Across the install path the pattern is: poll for readiness,
# time out, log a warning, and then call track_module_success anyway
# (lib/modules.sh:1318-1322, lib/health.sh:161-175). The result is a module
# reported as installed that never came up. The upgrade path must make that
# outcome structurally impossible, not merely discouraged -- so the assertion
# below is that a timeout lands the module in UPGRADE_ROLLED_BACK, and that
# no combination of verdicts can put an unproven module in UPGRADE_OK.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$(cd .. && pwd)"
DOCKER_BIN=docker
U_PROBE_INTERVAL=0          # do not pay real seconds for the timeout paths
source ../lib/common.sh
source ../lib/upgrade/core.sh
source ../lib/upgrade/health.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }
capture_diagnostic_logs() { echo "capture_diagnostic_logs $*" >> "$STUB_LOG"; }

_reset_run_state() {
    UPGRADE_OK=(); UPGRADE_DEGRADED=(); UPGRADE_ROLLED_BACK=()
    UPGRADE_FAILED=(); UPGRADE_SKIPPED=()
    U_FROM="1.0"; U_TO="2.0"; U_STEP_N=1; U_STEP_TOTAL=1
    U_ELK_BASELINE_STATUS=""
    : > "$LOG_FILE"
    # Re-source to restore the REAL probe functions. Tests override
    # _u_probe_<module> to drive a verdict, and run_all_tests dispatches in
    # alphabetical order (declare -F sorts), so without this an override from
    # test_down_* leaks forward into test_green_* and the later test silently
    # asserts against the earlier one's stub.
    source ../lib/upgrade/health.sh
    # Then re-apply the shared default: the container exists and is running,
    # so the fast-fail does not fire and each test controls the verdict
    # through its _u_probe_<module> override alone.
    _u_container_state() { echo running; }
}

# grep -c prints "0" AND exits 1 when there is no match, so the usual
# `|| echo 0` fallback appends a SECOND zero and the comparison sees "0\n0".
_probe_was_consulted() { grep -qF 'probe ran' "$STUB_LOG"; }

# ---------------------------------------------------------------------------
# The verdict -> outcome mapping
# ---------------------------------------------------------------------------

test_up_commits_the_module() {
    _reset_run_state
    _u_probe_elk() { echo "up cluster green"; }
    u_begin elk; u_end elk rollback 1
    assert_eq "${#UPGRADE_OK[@]}" "1"
    assert_eq "${#UPGRADE_DEGRADED[@]}" "0"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "0"
}

test_degraded_commits_the_module_but_is_reported() {
    # Degraded means applied and running. Rolling back a working-but-imperfect
    # module would be worse than the imperfection.
    _reset_run_state
    _u_probe_elk() { echo "degraded cluster yellow"; }
    u_begin elk; u_end elk rollback 1
    assert_eq "${#UPGRADE_OK[@]}" "0"
    assert_eq "${#UPGRADE_DEGRADED[@]}" "1"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "0"
    assert_contains "${UPGRADE_DEGRADED[0]}" "cluster yellow"
}

test_down_under_rollback_policy_unwinds() {
    _reset_run_state
    _u_probe_elk() { echo "down cluster red"; }
    u_begin elk
    u_undo true
    u_end elk rollback 1
    assert_eq "${#UPGRADE_OK[@]}" "0"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "1"
    assert_contains "${UPGRADE_ROLLED_BACK[0]}" "health gate"
}

test_down_under_report_policy_stays_applied() {
    # VolWeb ships with policy 'report': a DOWN verdict is named loudly but
    # the module is left in place rather than reverted.
    _reset_run_state
    _u_probe_volweb() { echo "down volweb-backend not running"; }
    u_begin volweb
    u_undo true
    u_end volweb report 1
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "0"
    assert_eq "${#UPGRADE_DEGRADED[@]}" "1"
    assert_contains "${UPGRADE_DEGRADED[0]}" "DOWN"
    assert_eq "${#UPGRADE_OK[@]}" "0" \
        "'report' must not launder a DOWN verdict into a clean success"
}

test_policy_none_skips_the_probe_entirely() {
    # plaso/aws_sigma/o365rc have no service to probe. The probe must not run
    # at all -- their stub probes deliberately return 'down' so that a policy
    # typo shows up as a failure instead of passing silently.
    _reset_run_state
    _u_probe_plaso() { echo "probe ran" >> "$STUB_LOG"; echo "down should not be consulted"; }
    u_begin plaso; u_end plaso none
    assert_eq "${#UPGRADE_OK[@]}" "1"
    assert_false _probe_was_consulted
}

# ---------------------------------------------------------------------------
# The regression this file exists for
# ---------------------------------------------------------------------------

test_a_timeout_is_down_and_never_a_success() {
    _reset_run_state
    _u_probe_elk() { echo "down still starting"; }
    u_begin elk
    u_undo true
    u_end elk rollback 1
    assert_eq "${#UPGRADE_OK[@]}" "0" \
        "a module that never came up must NEVER appear in UPGRADE_OK"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "1"
}

test_a_timeout_that_only_ever_saw_degraded_stays_degraded() {
    # Not every timeout is an outage. If the best verdict observed was
    # 'degraded', the honest answer is degraded -- neither promoted to up nor
    # demoted to a rollback.
    _reset_run_state
    _u_probe_elk() { echo "degraded cluster yellow"; }
    u_begin elk; u_end elk rollback 1
    assert_eq "${#UPGRADE_DEGRADED[@]}" "1"
    assert_eq "${#UPGRADE_ROLLED_BACK[@]}" "0"
    assert_eq "${#UPGRADE_OK[@]}" "0"
}

test_a_module_that_becomes_healthy_mid_poll_is_up() {
    _reset_run_state
    local counter; counter="$(mktemp)"; echo 0 > "$counter"
    _u_probe_elk() {
        local n; n=$(( $(cat "$counter") + 1 )); echo "$n" > "$counter"
        (( n >= 3 )) && { echo "up cluster green"; return; }
        echo "down still starting"
    }
    u_begin elk; u_end elk rollback 30
    assert_eq "${#UPGRADE_OK[@]}" "1" "the poll must keep trying, not judge on the first attempt"
    rm -f "$counter"
}

test_diagnostics_are_captured_only_when_the_gate_is_not_up() {
    _reset_run_state
    _u_probe_elk() { echo "up cluster green"; }
    u_begin elk; u_end elk rollback 1
    assert_eq "$(stub_call_count capture_diagnostic_logs)" "0"

    _reset_run_state
    _u_probe_elk() { echo "down cluster red"; }
    u_begin elk; u_end elk rollback 1
    assert_eq "$(stub_call_count capture_diagnostic_logs)" "1"
}

# ---------------------------------------------------------------------------
# Fast-fail on container state
# ---------------------------------------------------------------------------

test_a_crash_looping_container_fails_immediately_without_polling() {
    # Waiting out a 150s poll on a container that is restarting only delays
    # the rollback; it is never going to settle.
    _reset_run_state
    _u_container_state() { echo restarting; }
    _u_probe_elk() { echo "probe ran" >> "$STUB_LOG"; echo "up should not be consulted"; }
    local out; out="$(u_probe_module elk 30)"
    assert_contains "$out" "down"
    assert_contains "$out" "crash-looping"
    assert_false _probe_was_consulted
}

test_an_exited_container_fails_immediately() {
    _reset_run_state
    _u_container_state() { echo exited; }
    assert_contains "$(u_probe_module elk 30)" "has exited"
}

test_an_absent_container_fails_immediately() {
    _reset_run_state
    _u_container_state() { echo absent; }
    assert_contains "$(u_probe_module elk 30)" "does not exist"
}

# ---------------------------------------------------------------------------
# ELK's yellow-is-not-automatically-degraded rule
# ---------------------------------------------------------------------------

test_yellow_matching_the_pre_upgrade_baseline_is_up() {
    # A single-node cluster with any replicated index sits yellow forever and
    # can never reach green. Calling that 'degraded' would mark every ELK
    # upgrade degraded and teach the operator to ignore the word.
    _reset_run_state
    U_ELK_BASELINE_STATUS=yellow
    curl() { echo '{"cluster_name":"intact-cluster","status":"yellow"}'; }
    _u_is_running() { return 0; }
    read_env_var() { echo "x"; }
    assert_contains "$(_u_probe_elk)" "up"
    assert_contains "$(_u_probe_elk)" "unchanged"
    unset -f curl _u_is_running read_env_var
}

test_green_degrading_to_yellow_is_a_real_regression() {
    _reset_run_state
    U_ELK_BASELINE_STATUS=green
    curl() { echo '{"cluster_name":"intact-cluster","status":"yellow"}'; }
    _u_is_running() { return 0; }
    read_env_var() { echo "x"; }
    assert_contains "$(_u_probe_elk)" "degraded"
    unset -f curl _u_is_running read_env_var
}

test_red_is_down_regardless_of_baseline() {
    _reset_run_state
    U_ELK_BASELINE_STATUS=yellow
    curl() { echo '{"cluster_name":"intact-cluster","status":"red"}'; }
    _u_is_running() { return 0; }
    read_env_var() { echo "x"; }
    assert_contains "$(_u_probe_elk)" "down"
    unset -f curl _u_is_running read_env_var
}

test_green_with_kibana_stopped_is_degraded_not_up() {
    _reset_run_state
    curl() { echo '{"status":"green"}'; }
    _u_is_running() { return 1; }
    read_env_var() { echo "x"; }
    local out; out="$(_u_probe_elk)"
    assert_contains "$out" "degraded"
    assert_contains "$out" "kibana"
    unset -f curl _u_is_running read_env_var
}

test_unreachable_elasticsearch_is_down() {
    _reset_run_state
    curl() { echo ''; }
    _u_is_running() { return 1; }
    read_env_var() { echo "x"; }
    assert_contains "$(_u_probe_elk)" "down"
    unset -f curl _u_is_running read_env_var
}

# ---------------------------------------------------------------------------
# Container maps
# ---------------------------------------------------------------------------

test_every_probed_module_has_a_primary_container_and_a_log_set() {
    # A module in the probe table with no primary container would silently
    # skip the fast-fail; one with no log set would produce a rollback with
    # no diagnostics attached.
    _reset_run_state
    local m
    for m in intact elk timesketch iris velociraptor volweb portainer; do
        assert_ne "$(u_primary_container_of "$m")" "" "primary container for $m"
        assert_ne "$(u_containers_of "$m")" "" "diagnostic containers for $m"
        assert_contains "$(u_containers_of "$m")" "$(u_primary_container_of "$m")" \
            "$m's primary container should be in its diagnostic set"
    done
}

test_a_probe_function_exists_for_every_module_in_the_container_map() {
    _reset_run_state
    local m
    for m in intact elk timesketch iris velociraptor volweb portainer plaso aws_sigma o365rc; do
        assert_true declare -F "_u_probe_${m}"
    done
}

run_all_tests
rm -f "$LOG_FILE"
