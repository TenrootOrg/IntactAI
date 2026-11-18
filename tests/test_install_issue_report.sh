#!/bin/bash
# The ATTENTION summary that ends an install and an upgrade
# (lib/health.sh:print_final_issues_report) counts problems, not log lines.
#
# QA, mssp-demo, 2026-11-18: Timesketch took longer than the 90 s wait on its
# first start. That is one warning, and capture_diagnostic_logs attached ~50
# lines of container log to it -- straight into INSTALL_ERRORS, so the summary
# said "install completed with 52 error(s)". The tails now go to their own
# list, are shown under the problems, and are never counted.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

_report() {   # _report <setup commands> -> $OUT (the report, colours stripped)
    local w; w="$(mktemp -d)"
    mkdir -p "$w/bin"
    # docker: the named container exists and has 50 lines of log
    cat > "$w/bin/docker" <<'EOF'
#!/bin/bash
case "$1" in
  ps) echo "${@: -1}" | grep -q . && echo intact_timesketch_web ;;
  logs) for i in $(seq 1 50); do echo "log line $i"; done ;;
esac
EOF
    chmod +x "$w/bin/docker"
    OUT="$(PATH="$w/bin:$PATH" LOG_FILE="$w/install.log" bash -c '
        source "'"$REPO"'/lib/common.sh" >/dev/null 2>&1
        source "'"$REPO"'/lib/health.sh" >/dev/null 2>&1
        '"$1"'
        print_final_issues_report' 2>&1 | sed -r 's/\x1b\[[0-9;]*m//g')"
    LOGTXT="$(cat "$w/install.log" 2>/dev/null)"
    rm -rf "$w"
}

test_a_warning_with_attached_logs_is_one_warning() {
    _report 'log_warn "  TimeSketch API not responding after 90s" >/dev/null
             capture_diagnostic_logs "TimeSketch API (deploy timeout)" intact_timesketch_web'
    assert_contains "$OUT" "install completed with 0 error(s), 1 warning(s)"
    assert_not_contains "$OUT" "ERRORS:"
    assert_contains "$OUT" "TimeSketch API not responding after 90s"
    # a warning's tails go to the log only: on screen they buried the logins
    # (mssp-demo, 2026-11-18)
    assert_not_contains "$OUT" "log line 50"
    assert_contains "$OUT" "Container logs for the warnings: in the full log below"
    assert_contains "$LOGTXT" "CONTAINER LOGS (for the problems above):"
    assert_contains "$LOGTXT" "log line 50"
}

test_a_retry_that_worked_is_one_warning_not_two() {
    # mssp-demo, 2026-11-18: IRIS's first start failed, the retry worked, and
    # its "↳ resolved" line was counted too: "2 warning(s)".
    _report 'log_warn "  IRIS compose up failed; retrying in 15s..." >/dev/null
             INSTALL_WARNINGS+=("  ↳ resolved: IRIS compose up succeeded on attempt 2")'
    assert_contains "$OUT" "install completed with 0 error(s), 1 warning(s)"
    assert_contains "$OUT" "↳ resolved: IRIS compose up succeeded on attempt 2"
}

test_a_real_error_is_counted_once_with_its_logs() {
    _report 'log_error "  TimeSketch web container failed to start" >/dev/null
             capture_diagnostic_logs "TimeSketch web (container start timeout)" intact_timesketch_web'
    assert_contains "$OUT" "install completed with 1 error(s), 0 warning(s)"
    assert_contains "$OUT" "ERRORS:"
    assert_contains "$OUT" "CONTAINER LOGS"
    assert_contains "$OUT" "log line 50"   # an error's tails stay on screen
}

test_errors_the_upgrade_gate_adds_directly_still_count() {
    # lib/upgrade/health/gate.sh appends to INSTALL_ERRORS itself, and
    # scripts/upgrade.sh turns that delta into its exit code: unchanged.
    _report 'INSTALL_ERRORS+=("intact_backend is crash-looping after the upgrade")'
    assert_contains "$OUT" "1 error(s), 0 warning(s)"
    assert_not_contains "$OUT" "CONTAINER LOGS"
}

test_a_clean_run_says_so() {
    _report ':'
    assert_contains "$OUT" "No warnings or errors"
}

test_the_timesketch_wait_is_five_minutes_and_quiet() {
    local f="$REPO/lib/modules/timesketch.sh"
    assert_true grep -q 'local ts_max_wait=300' "$f"
    assert_true grep -q 'ts_wait % 30 == 0' "$f"   # one progress line every 30 s, not every 5
}

run_all_tests
