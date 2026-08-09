#!/bin/bash
# check_network_connectivity() (lib/common.sh): regression coverage for a
# real bug found via a live fresh-VM test (a genuine systemd container, no
# packages pre-installed) -- the old implementation used `ping` for two of
# its three checks and `curl` for the third, but this runs BEFORE
# install_dependencies() ever gets a chance to install either, so on an
# actually fresh Ubuntu 24.04 box (confirmed live: neither ping nor curl
# exist there yet) it reported "No internet connectivity" even though the
# box had working internet the whole time. Fixed to use bash's own
# /dev/tcp, which needs nothing but bash + `timeout` (coreutils,
# priority:required, always present).
#
# These tests exercise the real _tcp_reachable() helper against a real
# local listener -- no mocking of ping/curl, no dependency on outbound
# internet access from CI.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT
source ../lib/common.sh

test_does_not_call_ping_or_curl() {
    # The regression itself: grep the shipped source, not a copy, so this
    # fails again immediately if ping/curl ever creep back in.
    assert_not_contains "$(declare -f check_network_connectivity)" "ping " \
        "check_network_connectivity must not depend on ping (absent on a fresh box)"
    assert_not_contains "$(declare -f check_network_connectivity)" "curl " \
        "check_network_connectivity must not depend on curl (absent on a fresh box, before install_dependencies runs)"
}

test_reachable_local_port_succeeds() {
    # A real listener, not a mock -- proves the /dev/tcp mechanism actually
    # connects, not just that the code compiles.
    python3 -m http.server 18391 --bind 127.0.0.1 &>/dev/null &
    local pid=$!
    sleep 1
    assert_true _tcp_reachable 127.0.0.1 18391 2
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}

test_closed_port_fails_within_timeout() {
    # Port 1 is privileged and essentially never has anything listening in
    # a test sandbox; a closed port must be reported unreachable, not hang.
    local start end
    start=$(date +%s)
    assert_false _tcp_reachable 127.0.0.1 1 2
    end=$(date +%s)
    local elapsed=$(( end - start ))
    assert_true test "$elapsed" -le 4
}

run_all_tests
