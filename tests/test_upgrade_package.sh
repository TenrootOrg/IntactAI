#!/bin/bash
# lib/upgrade/package.sh — everything a package must survive before a single
# container is touched.
#
# These run as an unprivileged user against synthetic packages. The tar-slip
# cases matter most: extraction happens as root, so a member named
# ../../etc/cron.d/x is the difference between a bad package and a rooted host.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$(mktemp -d)"          # a scratch "repo" so data/tmp lands here
mkdir -p "${SCRIPT_DIR}/data/tmp"
DOCKER_BIN=docker
source ../lib/common.sh
source ../lib/upgrade/core.sh
source ../lib/upgrade/package.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

WORK=""
_setup() {
    WORK="$(mktemp -d)"
    UPKG_DIR=""; UPKG_MANIFEST=""; UPKG_SCRATCH=""
    UPKG_VERSIONS=(); UPKG_SHA_ENTRIES=0; UPKG_PINS_SOURCE=""; UPKG_RELEASE_TAG=""
    : > "$LOG_FILE"
}
_teardown() { upkg_cleanup >/dev/null 2>&1; [[ -n "$WORK" ]] && rm -rf "$WORK"; WORK=""; }

# Build a well-formed package tar at $WORK/<name>. $2 is a python dict literal
# of manifest overrides; the sha256 map is always computed for real.
_make_pkg() {
    local name="$1" manifest="${2:-{\}}"
    local root="${WORK}/build/intact-upgrade-test"
    rm -rf "${WORK}/build"; mkdir -p "${root}/source/intact" "${root}/images"
    printf 'hello\n' > "${root}/source/intact/README"
    printf 'not a real image\n' > "${root}/images/elk-9.9.9.tar"
    ( cd "$root" && python3 -c "
import json,hashlib,os,sys
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for c in iter(lambda: f.read(1<<20), b''): h.update(c)
    return h.hexdigest()
shas={}
for r,_,fs in os.walk('.'):
    for f in fs:
        rel=os.path.relpath(os.path.join(r,f),'.')
        if rel!='manifest.json': shas[rel]=sha(os.path.join(r,f))
m={'package_version':'1.0','versions':{'elk':'9.9.9','iris':'v2.4.27'}}
m.update(${manifest})
m.setdefault('contents',{})['sha256']=shas
json.dump(m,open('manifest.json','w'))
" )
    ( cd "${WORK}/build" && tar -cf "${WORK}/${name}" intact-upgrade-test )
}

# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------

test_a_well_formed_package_is_accepted() {
    _setup; _make_pkg good.tar
    assert_true upkg_acquire "${WORK}/good.tar"
    assert_eq "${UPKG_VERSIONS[elk]}" "9.9.9"
    assert_eq "${UPKG_VERSIONS[iris]}" "v2.4.27"
    _teardown
}

# ---------------------------------------------------------------------------
# Tar-slip — the one that is a security bug, not a correctness bug
# ---------------------------------------------------------------------------

test_a_parent_escaping_member_is_refused() {
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-test" "${WORK}/b/payload"
    echo x > "${WORK}/b/intact-upgrade-test/f"
    echo pwned > "${WORK}/b/payload/evil"
    ( cd "${WORK}/b" && tar -cf "${WORK}/slip.tar" intact-upgrade-test \
        --transform 's|^payload/evil|../../etc/cron.d/evil|' payload/evil 2>/dev/null )
    assert_false upkg_check_tar_slip "${WORK}/slip.tar"
    assert_contains "$(cat "$LOG_FILE")" "parent-escaping"
    _teardown
}

test_an_absolute_path_member_is_refused() {
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-test"
    echo x > "${WORK}/b/intact-upgrade-test/f"
    ( cd "${WORK}/b" && tar -cf "${WORK}/abs.tar" intact-upgrade-test \
        --transform 's|^intact-upgrade-test/f|/etc/cron.d/evil|' 2>/dev/null )
    assert_false upkg_check_tar_slip "${WORK}/abs.tar"
    assert_contains "$(cat "$LOG_FILE")" "absolute path"
    _teardown
}

test_a_dotdot_nested_deeper_in_the_path_is_refused() {
    # 'a/../../b' does not start with '..' -- a naive prefix check misses it.
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-test/a"
    echo x > "${WORK}/b/intact-upgrade-test/a/f"
    ( cd "${WORK}/b" && tar -cf "${WORK}/mid.tar" intact-upgrade-test \
        --transform 's|^intact-upgrade-test/a/f|good/../../escaped|' 2>/dev/null )
    assert_false upkg_check_tar_slip "${WORK}/mid.tar"
    _teardown
}

test_an_ordinary_package_passes_the_slip_check() {
    _setup; _make_pkg clean.tar
    assert_true upkg_check_tar_slip "${WORK}/clean.tar"
    _teardown
}

# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

test_a_tampered_file_is_caught_by_the_checksum_map() {
    # The archive is intact; one file inside it was swapped. This is the only
    # check that catches that.
    _setup; _make_pkg tam.tar
    rm -rf "${WORK}/x"; mkdir "${WORK}/x"
    tar -xf "${WORK}/tam.tar" -C "${WORK}/x"
    echo "TAMPERED" > "${WORK}/x/intact-upgrade-test/source/intact/README"
    ( cd "${WORK}/x" && tar -cf "${WORK}/tam2.tar" intact-upgrade-test )
    assert_false upkg_acquire "${WORK}/tam2.tar"
    assert_contains "$(cat "$LOG_FILE")" "verification FAILED"
    _teardown
}

test_an_expected_sha256_that_does_not_match_aborts_before_extraction() {
    _setup; _make_pkg anch.tar
    assert_false upkg_verify_archive "${WORK}/anch.tar" "$(printf 'd%.0s' {1..64})"
    assert_contains "$(cat "$LOG_FILE")" "Checksum mismatch"
    _teardown
}

test_a_matching_expected_sha256_is_accepted() {
    _setup; _make_pkg anch2.tar
    assert_true upkg_verify_archive "${WORK}/anch2.tar" "$(sha256_of "${WORK}/anch2.tar")"
    _teardown
}

test_a_corrupt_gzip_is_rejected() {
    _setup; _make_pkg g.tar
    gzip -c "${WORK}/g.tar" > "${WORK}/g.tar.gz"
    # Corrupt the middle, leaving the gzip magic intact so the sniff still
    # decides to run gzip -t.
    printf 'XXXXXXXX' | dd of="${WORK}/g.tar.gz" bs=1 seek=200 conv=notrunc status=none
    assert_false upkg_verify_archive "${WORK}/g.tar.gz"
    _teardown
}

test_a_plain_tar_is_not_run_through_gzip_t() {
    # Assets became plain tar at 20260805 but kept the .tar.gz name in older
    # releases; a suffix-based test would fail a perfectly good package.
    _setup; _make_pkg plain.tar
    mv "${WORK}/plain.tar" "${WORK}/misleading.tar.gz"
    assert_true upkg_verify_archive "${WORK}/misleading.tar.gz"
    _teardown
}

test_an_empty_asset_is_rejected() {
    _setup; : > "${WORK}/empty.tar"
    assert_false upkg_verify_archive "${WORK}/empty.tar"
    _teardown
}

# ---------------------------------------------------------------------------
# Manifest gates
# ---------------------------------------------------------------------------

test_a_delta_package_is_refused() {
    _setup; _make_pkg delta.tar "{'contents':{'package_kind':'delta'}}"
    assert_false upkg_acquire "${WORK}/delta.tar"
    assert_contains "$(cat "$LOG_FILE")" "DELTA"
    _teardown
}

test_a_newer_package_format_is_refused_not_guessed_at() {
    _setup; _make_pkg v2.tar "{'package_version':'2.0'}"
    assert_false upkg_acquire "${WORK}/v2.tar"
    assert_contains "$(cat "$LOG_FILE")" "newer than this upgrader supports"
    _teardown
}

test_a_newer_minor_of_the_same_format_is_accepted() {
    # Only the MAJOR is a compatibility statement.
    _setup; _make_pkg v11.tar "{'package_version':'1.7'}"
    assert_true upkg_acquire "${WORK}/v11.tar"
    _teardown
}

test_a_missing_manifest_is_fatal() {
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-test"; echo x > "${WORK}/b/intact-upgrade-test/f"
    ( cd "${WORK}/b" && tar -cf "${WORK}/nom.tar" intact-upgrade-test )
    assert_false upkg_acquire "${WORK}/nom.tar"
    assert_contains "$(cat "$LOG_FILE")" "No manifest.json"
    _teardown
}

test_unparseable_json_is_fatal() {
    _setup; _make_pkg bad.tar
    rm -rf "${WORK}/x"; mkdir "${WORK}/x"; tar -xf "${WORK}/bad.tar" -C "${WORK}/x"
    echo 'not json{' > "${WORK}/x/intact-upgrade-test/manifest.json"
    ( cd "${WORK}/x" && tar -cf "${WORK}/bad2.tar" intact-upgrade-test )
    UPKG_DIR="${WORK}/x/intact-upgrade-test"; UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
    assert_false upkg_read_manifest
    _teardown
}

test_the_pre_rename_cloudtrail_pin_is_read_as_aws_sigma() {
    # Packages cut before the rename carry versions.cloudtrail. Without the
    # alias the module is silently never dispatched.
    _setup; _make_pkg ct.tar "{'versions':{'cloudtrail':'2026.01'}}"
    assert_true upkg_acquire "${WORK}/ct.tar"
    assert_eq "${UPKG_VERSIONS[aws_sigma]:-}" "2026.01"
    _teardown
}

test_local_fallback_pins_are_warned_about_but_allowed() {
    _setup; _make_pkg lf.tar "{'contents':{'pins_source':'local-fallback'}}"
    assert_true upkg_acquire "${WORK}/lf.tar"
    assert_contains "$(cat "$LOG_FILE")" "BUILD MACHINE"
    _teardown
}

# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------

test_assets_that_do_not_share_a_root_are_refused() {
    # Per-module assets merge by sharing a top-level directory. Two roots means
    # they came from different releases and each is half a package.
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-AAA" "${WORK}/b/intact-upgrade-BBB"
    echo a > "${WORK}/b/intact-upgrade-AAA/f"
    echo b > "${WORK}/b/intact-upgrade-BBB/f"
    ( cd "${WORK}/b" && tar -cf "${WORK}/m1.tar" intact-upgrade-AAA )
    ( cd "${WORK}/b" && tar -cf "${WORK}/m2.tar" intact-upgrade-BBB )
    assert_false upkg_extract "${WORK}/m1.tar" "${WORK}/m2.tar"
    assert_contains "$(cat "$LOG_FILE")" "Per-module assets merge"
    _teardown
}

test_a_directory_argument_expands_to_the_assets_inside_it() {
    _setup; _make_pkg d1.tar
    mkdir -p "${WORK}/dir"; cp "${WORK}/d1.tar" "${WORK}/dir/"
    # A system bundle in the same directory is a dependency repo, not a module
    # asset, and must never reach the image loader.
    : > "${WORK}/dir/intact-20260101-system-bundle.tar"
    assert_true upkg_expand_args "${WORK}/dir"
    assert_eq "${#UPKG_ASSETS[@]}" "1"
    assert_contains "${UPKG_ASSETS[0]}" "d1.tar"
    _teardown
}

test_a_nonexistent_package_path_is_reported() {
    _setup
    assert_false upkg_expand_args "${WORK}/nope.tar"
    _teardown
}

run_all_tests
rm -f "$LOG_FILE"; rm -rf "$SCRIPT_DIR"
