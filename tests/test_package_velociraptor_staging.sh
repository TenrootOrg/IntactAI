#!/bin/bash
# An offline install stages the package's Velociraptor Linux binary into the
# image build context. From 0.77.3 a package carries only the static musl build
# (the plain one needs GLIBC_2.38), and the staging looked for the plain name
# only: an air-gapped fresh install found no Linux binary and the image build
# failed. binaries/legacy/ also holds a musl build (0.7.1) that must never win.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh
LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/package.sh
log_info() { :; }; log_success() { :; }; log_warn() { echo "[WARN] $*" >> "$LOG_FILE"; }
read_config() { echo "0.77.3"; }

_pkg() {
    WORK="$(mktemp -d)"; SCRIPT_DIR="$(mktemp -d)"
    mkdir -p "$WORK/binaries/legacy"
    echo legacy > "$WORK/binaries/legacy/velociraptor-v0.7.1-linux-amd64-musl"
    for f in darwin-amd64 windows-amd64.exe windows-amd64.msi; do echo "$f" > "$WORK/binaries/velociraptor-v0.77.3-$f"; done
}

test_a_musl_only_package_stages_its_linux_binary() {
    _pkg; echo musl > "$WORK/binaries/velociraptor-v0.77.3-linux-amd64-musl"
    _pkg_stage_velociraptor_build "$WORK"
    assert_eq "$(cat "$SCRIPT_DIR/modules/velociraptor/clients/linux/velociraptor")" "musl"
    assert_eq "$(cat "$SCRIPT_DIR/modules/velociraptor/clients/linux/velociraptor.version")" "0.77.3"
    assert_eq "$(cat "$SCRIPT_DIR/modules/velociraptor/clients/windows/velociraptor_client.msi")" "windows-amd64.msi"
}

test_an_older_package_with_the_plain_binary_still_works() {
    _pkg; echo plain > "$WORK/binaries/velociraptor-v0.77.3-linux-amd64"
    _pkg_stage_velociraptor_build "$WORK"
    assert_eq "$(cat "$SCRIPT_DIR/modules/velociraptor/clients/linux/velociraptor")" "plain"
}

test_the_legacy_musl_never_stands_in() {
    _pkg
    _pkg_stage_velociraptor_build "$WORK"
    assert_false test -e "$SCRIPT_DIR/modules/velociraptor/clients/linux/velociraptor"
}

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
