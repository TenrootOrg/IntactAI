#!/bin/bash
# ensure_core_dependencies() (lib/deps.sh): the extraction target for the
# Core Dependencies block that used to run inline in install.sh's main()
# with 60% confidence -- bash -n only, the branching itself never executed.
# Every scenario in the plan's table, against stubbed collaborators.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

SCRIPT_DIR="$(mktemp -d)"
LOG_FILE="$(mktemp)"
trap 'rm -rf "$SCRIPT_DIR"; rm -f "$LOG_FILE"' EXIT

source ../lib/common.sh
source ../lib/deps.sh

# Collaborators ensure_core_dependencies() touches directly, stubbed so a
# test never reaches the network, apt, or a real docker daemon. Individual
# tests override rc/behaviour by re-stubbing before calling the function
# under test.
_stub_all_collaborators() {
    stub check_network_connectivity 0
    stub prefer_ipv4_dns 0
    stub check_docker_min_version 0
    stub configure_docker_resolver 0
    stub create_network 0
    stub install_dependencies 0
    stub install_docker 0
    stub install_dependencies_from_package 0
    stub install_docker_from_package 0
    stub download_system_bundle 1   # default: "no bundle for this release"
    stub docker 0                   # command -v docker / docker version must both pass
}

_reset() {
    reset_stubs
    _stub_all_collaborators
    INTACT_AIRGAP=0
    INTACT_SYSTEM_BUNDLE_SRC=""
    INTACT_PACKAGE_ARGS=()
}

# ---------------------------------------------------------------------------
# Online, release predates the bundle feature (no VERSION file at all) --
# must fall through to the plain online path with no crash.
# ---------------------------------------------------------------------------
test_online_no_version_file_falls_through() {
    _reset
    rm -f "${SCRIPT_DIR}/VERSION"
    ensure_core_dependencies
    assert_true stub_called_with install_dependencies ""
    assert_true stub_called_with install_docker ""
    assert_eq "$(stub_call_count install_dependencies_from_package)" "0"
    assert_eq "$(stub_call_count install_docker_from_package)" "0"
    assert_eq "$INTACT_BUNDLE_DIR" ""
}

# ---------------------------------------------------------------------------
# Online, VERSION present, download_system_bundle rc=1 (genuinely no
# bundle for this release) -- falls through, not fatal.
# ---------------------------------------------------------------------------
test_online_bundle_rc1_falls_through() {
    _reset
    echo "testtag" > "${SCRIPT_DIR}/VERSION"
    stub download_system_bundle 1
    ensure_core_dependencies
    assert_true stub_called_with install_dependencies ""
    assert_true stub_called_with install_docker ""
    assert_eq "$INTACT_BUNDLE_DIR" ""
}

# ---------------------------------------------------------------------------
# Online, bundle downloads successfully (rc=0) -- installs from it, and
# critically never calls the plain install_docker/install_dependencies.
# ---------------------------------------------------------------------------
test_online_bundle_rc0_installs_from_bundle() {
    _reset
    echo "testtag" > "${SCRIPT_DIR}/VERSION"
    mkdir -p "${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
    stub download_system_bundle 0
    ensure_core_dependencies
    assert_true stub_called_with install_dependencies_from_package \
        "${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
    assert_true stub_called_with install_docker_from_package \
        "${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
    assert_eq "$(stub_call_count install_dependencies)" "0" \
        "must never touch the plain online path once a bundle installed"
    assert_eq "$(stub_call_count install_docker)" "0"
    assert_eq "$INTACT_BUNDLE_DIR" "${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
}

# ---------------------------------------------------------------------------
# Online, bundle advertised but unobtainable (rc=2) -- fatal exit, no
# fallback to install_docker/install_dependencies.
# ---------------------------------------------------------------------------
test_online_bundle_rc2_is_fatal_no_fallback() {
    _reset
    echo "testtag" > "${SCRIPT_DIR}/VERSION"
    stub download_system_bundle 2
    (
        set +e
        ensure_core_dependencies
        echo "SHOULD_NOT_REACH_HERE"
    ) > /tmp/_ecd_out.$$ 2>&1
    local rc=$?
    assert_ne "$rc" "0" "rc=2 (bundle advertised but unobtainable) must abort the install"
    assert_not_contains "$(cat /tmp/_ecd_out.$$)" "SHOULD_NOT_REACH_HERE"
    rm -f /tmp/_ecd_out.$$
    assert_eq "$(stub_call_count install_dependencies)" "0"
    assert_eq "$(stub_call_count install_docker)" "0"
}

# ---------------------------------------------------------------------------
# Air-gap, --package <dir> with no bundle anywhere -- legacy "must already
# be present" check. Docker present -> proceeds; missing -> fatal.
# ---------------------------------------------------------------------------
test_airgap_no_bundle_docker_present_proceeds() {
    _reset
    INTACT_AIRGAP=1
    stub docker 0 "Docker version 24.0.0"   # command -v + `docker compose version` both hit this
    ensure_core_dependencies
    assert_eq "$(stub_call_count install_dependencies)" "0" \
        "air-gap must never touch apt/online install functions"
    assert_eq "$(stub_call_count install_docker)" "0"
    assert_eq "$INTACT_BUNDLE_DIR" ""
}

test_airgap_no_bundle_docker_missing_is_fatal() {
    _reset
    INTACT_AIRGAP=1
    # Un-stubbing the docker FUNCTION is not enough on a dev box that has a
    # real /usr/bin/docker: `command -v docker` finds it right through the
    # unset function, since it still falls back to a normal PATH search.
    # Strip any PATH entry that actually has a docker binary so `command -v
    # docker` genuinely fails, simulating the box this whole air-gap branch
    # exists for.
    unset -f docker 2>/dev/null || true
    local dir clean_path=""
    IFS=: read -ra _dirs <<< "$PATH"
    for dir in "${_dirs[@]}"; do
        [[ -x "${dir}/docker" ]] && continue
        clean_path="${clean_path:+${clean_path}:}${dir}"
    done
    (
        set +e
        PATH="$clean_path"
        ensure_core_dependencies
        echo "SHOULD_NOT_REACH_HERE"
    ) > /tmp/_ecd_out2.$$ 2>&1
    local rc=$?
    assert_ne "$rc" "0" "missing docker with no bundle and no internet must be fatal"
    assert_not_contains "$(cat /tmp/_ecd_out2.$$)" "SHOULD_NOT_REACH_HERE"
    rm -f /tmp/_ecd_out2.$$
}

# ---------------------------------------------------------------------------
# Air-gap, --package <dir> containing an already-extracted system-bundle/
# (set directly here rather than via parse_install_args -- that's
# test_args.sh's job; this file only tests what ensure_core_dependencies
# does once INTACT_SYSTEM_BUNDLE_SRC is set).
# ---------------------------------------------------------------------------
test_airgap_extracted_bundle_dir_installs_from_it() {
    _reset
    INTACT_AIRGAP=1
    local bundle_dir="${SCRIPT_DIR}/pkg/system-bundle"
    mkdir -p "$bundle_dir"
    INTACT_SYSTEM_BUNDLE_SRC="$bundle_dir"
    ensure_core_dependencies
    assert_true stub_called_with install_dependencies_from_package "$bundle_dir"
    assert_true stub_called_with install_docker_from_package "$bundle_dir"
    assert_eq "$INTACT_BUNDLE_DIR" "$bundle_dir"
}

# ---------------------------------------------------------------------------
# Air-gap, --package pointing at a *-system-bundle.tar file -- must extract
# it before installing from it.
# ---------------------------------------------------------------------------
test_airgap_bundle_tar_is_extracted_then_installed() {
    _reset
    INTACT_AIRGAP=1
    local work; work="$(mktemp -d)"
    echo "24.04" > "${work}/ubuntu-version"
    local tar_path="${SCRIPT_DIR}/pkg/testtag-system-bundle.tar"
    mkdir -p "$(dirname "$tar_path")"
    tar -cf "$tar_path" -C "$work" ubuntu-version
    rm -rf "$work"
    INTACT_SYSTEM_BUNDLE_SRC="$tar_path"

    ensure_core_dependencies
    local expected="${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
    # NOTE: assert_true runs its full argument list as the command being
    # tested -- no separate description slot, unlike assert_eq/assert_contains.
    assert_true test -f "${expected}/ubuntu-version"
    assert_true stub_called_with install_dependencies_from_package "$expected"
    assert_true stub_called_with install_docker_from_package "$expected"
}

# ---------------------------------------------------------------------------
# Air-gap, bundle tar fails to extract (corrupt file) -- fatal, no fallback
# to the "must already be present" check.
# ---------------------------------------------------------------------------
test_airgap_corrupt_bundle_tar_is_fatal() {
    _reset
    INTACT_AIRGAP=1
    local tar_path="${SCRIPT_DIR}/pkg/testtag-system-bundle.tar"
    mkdir -p "$(dirname "$tar_path")"
    echo "not actually a tar file" > "$tar_path"
    INTACT_SYSTEM_BUNDLE_SRC="$tar_path"
    (
        set +e
        ensure_core_dependencies
        echo "SHOULD_NOT_REACH_HERE"
    ) > /tmp/_ecd_out3.$$ 2>&1
    local rc=$?
    assert_ne "$rc" "0" "a corrupt/unreadable bundle tar must abort, not fall through"
    assert_not_contains "$(cat /tmp/_ecd_out3.$$)" "SHOULD_NOT_REACH_HERE"
    rm -f /tmp/_ecd_out3.$$
    assert_eq "$(stub_call_count install_dependencies)" "0" \
        "must not silently fall back to the legacy air-gap check"
}

# ---------------------------------------------------------------------------
# The bundle-install failure paths must abort too, not just log an error.
# ---------------------------------------------------------------------------
test_install_dependencies_from_package_failure_is_fatal() {
    _reset
    INTACT_AIRGAP=1
    local bundle_dir="${SCRIPT_DIR}/pkg2/system-bundle"
    mkdir -p "$bundle_dir"
    INTACT_SYSTEM_BUNDLE_SRC="$bundle_dir"
    stub install_dependencies_from_package 1
    (
        set +e
        ensure_core_dependencies
        echo "SHOULD_NOT_REACH_HERE"
    ) > /tmp/_ecd_out4.$$ 2>&1
    local rc=$?
    assert_ne "$rc" "0"
    assert_not_contains "$(cat /tmp/_ecd_out4.$$)" "SHOULD_NOT_REACH_HERE"
    rm -f /tmp/_ecd_out4.$$
}

test_install_docker_from_package_failure_is_fatal() {
    _reset
    INTACT_AIRGAP=1
    local bundle_dir="${SCRIPT_DIR}/pkg3/system-bundle"
    mkdir -p "$bundle_dir"
    INTACT_SYSTEM_BUNDLE_SRC="$bundle_dir"
    stub install_docker_from_package 1
    (
        set +e
        ensure_core_dependencies
        echo "SHOULD_NOT_REACH_HERE"
    ) > /tmp/_ecd_out5.$$ 2>&1
    local rc=$?
    assert_ne "$rc" "0"
    assert_not_contains "$(cat /tmp/_ecd_out5.$$)" "SHOULD_NOT_REACH_HERE"
    rm -f /tmp/_ecd_out5.$$
}

run_all_tests
