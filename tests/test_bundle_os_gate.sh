#!/bin/bash
# _verify_system_bundle_os_match() (lib/deps.sh): a .deb set built for one
# Ubuntu release must never be installed on another, even though the
# package *names* match. Per the "package is the only source" design this
# is a hard failure, not a fall-through.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT
source ../lib/common.sh
source ../lib/deps.sh

test_matching_this_hosts_own_version_passes() {
    # Reads /etc/os-release for real -- so instead of faking the host side
    # (which a unit test shouldn't depend on), feed the bundle side the
    # value the REAL function will compare against: this host's own
    # VERSION_ID. That's the one value guaranteed to match on any box the
    # suite runs on, so this exercises the actual pass path without mocking
    # /etc/os-release at all.
    local this_version; this_version="$(. /etc/os-release && echo "$VERSION_ID")"
    local bundle; bundle="$(mktemp -d)"
    echo "$this_version" > "${bundle}/ubuntu-version"
    assert_true _verify_system_bundle_os_match "$bundle"
    rm -rf "$bundle"
}

test_missing_marker_fails_closed() {
    local bundle; bundle="$(mktemp -d)"
    # no ubuntu-version file at all
    assert_false _verify_system_bundle_os_match "$bundle"
    rm -rf "$bundle"
}

test_empty_marker_fails_closed() {
    local bundle; bundle="$(mktemp -d)"
    : > "${bundle}/ubuntu-version"
    assert_false _verify_system_bundle_os_match "$bundle"
    rm -rf "$bundle"
}

test_mismatched_version_fails() {
    local bundle; bundle="$(mktemp -d)"
    # Whatever this host actually is, a marker claiming a version that is
    # never a valid Ubuntu release number is guaranteed not to match it.
    echo "0.01" > "${bundle}/ubuntu-version"
    assert_false _verify_system_bundle_os_match "$bundle"
    rm -rf "$bundle"
}

run_all_tests
