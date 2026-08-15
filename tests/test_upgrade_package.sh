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
source ../lib/upgrade/helpers.sh
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

test_a_missing_root_manifest_with_sidecars_present_names_the_cause() {
    # A package assembled from per-module assets but missing the CI `index`
    # job's merged manifest.json (predates the index, or the operator only
    # copied some of the release's assets) must not read as a generic
    # "No manifest.json" -- that message sends an operator hunting for a
    # corrupt download when the real fix is "get every asset" or "use an
    # older upgrade.sh".
    _setup
    mkdir -p "${WORK}/b/intact-upgrade-test/manifests"
    echo x > "${WORK}/b/intact-upgrade-test/f"
    echo '{}' > "${WORK}/b/intact-upgrade-test/manifests/elk.json"
    ( cd "${WORK}/b" && tar -cf "${WORK}/nom2.tar" intact-upgrade-test )
    assert_false upkg_acquire "${WORK}/nom2.tar"
    assert_contains "$(cat "$LOG_FILE")" "predates the per-module release"
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

# ---------------------------------------------------------------------------
# Which manifest.json wins (upkg_extract).
#
# One test per row of the precedence table. The shapes here are not invented:
# they were read off a real asset built by scripts/ci/build_release_package.py
# via scripts/dev/build_local_release_assets.sh -- a per-module asset's root
# manifest really does carry contents.package_kind == "module" and exactly one
# entry in `versions`, and the CI index job's merged manifest really does carry
# no package_kind at all.
# ---------------------------------------------------------------------------

# Build a per-module-shaped asset: one module in `versions`, package_kind
# "module", sharing the top-level dir every asset of a release shares.
_make_module_asset() {
    local name="$1" module="$2" version="$3"
    local root="${WORK}/mbuild/intact-upgrade-test"
    rm -rf "${WORK}/mbuild"; mkdir -p "${root}/images" "${root}/manifests"
    printf 'not a real image\n' > "${root}/images/${module}-${version}.tar"
    ( cd "$root" && MOD="$module" VER="$version" python3 -c "
import json, hashlib, os
def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''): h.update(c)
    return h.hexdigest()
mod, ver = os.environ['MOD'], os.environ['VER']
shas = {}
for r, _, fs in os.walk('.'):
    for f in fs:
        rel = os.path.relpath(os.path.join(r, f), '.')
        if rel != 'manifest.json': shas[rel] = sha(os.path.join(r, f))
json.dump({'module': mod}, open('manifests/%s.json' % mod, 'w'))
json.dump({'package_version': '1.0',
           'versions': {mod: ver},
           'contents': {'package_kind': 'module', 'sha256': shas}},
          open('manifest.json', 'w'))
" )
    ( cd "${WORK}/mbuild" && tar -cf "${WORK}/${name}" intact-upgrade-test )
}

# The CI index job's output: every module's pin, and no package_kind.
_write_merged_manifest() {
    local path="$1"
    python3 -c "
import json, sys
json.dump({'package_version': '1.0',
           'created_by': 'build-release-assets.yml/index',
           'versions': {'elk': '9.9.9', 'iris': 'v2.4.27', 'portainer': '2.39.5'},
           'contents': {'release_tag': 'intact-test', 'sha256': {}}},
          open(sys.argv[1], 'w'))
" "$path"
}

test_the_merged_manifest_beats_a_per_module_leftover() {
    # THE per-module regression. N assets share one top-level dir, so their
    # root manifest.json files overwrite each other and one survives at
    # random, describing a single module. Before the fix the merged manifest
    # was never placed over it, so plan_build saw one pin and marked every
    # other module `skip:not in this package` -- a full-release upgrade that
    # silently upgraded one module and reported success.
    _setup
    _make_module_asset a1.tar elk 9.9.9
    mkdir -p "${WORK}/loose"
    cp "${WORK}/a1.tar" "${WORK}/loose/"
    _write_merged_manifest "${WORK}/loose/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/loose"
    assert_true upkg_extract "${UPKG_ASSETS[@]}"
    assert_true upkg_read_manifest

    # All three pins, not just elk's.
    assert_eq "${UPKG_VERSIONS[elk]:-}"       "9.9.9"
    assert_eq "${UPKG_VERSIONS[iris]:-}"      "v2.4.27"
    assert_eq "${UPKG_VERSIONS[portainer]:-}" "2.39.5"
    assert_contains "$(cat "$LOG_FILE")" "replaced a per-module manifest leftover"
    _teardown
}

test_a_legacy_bundles_own_manifest_is_not_overwritten() {
    # The guard the fix must not break. A legacy single bundle's manifest.json
    # is authoritative for the tree it ships in; a loose manifest beside it is
    # for some other release and must never win.
    _setup
    _make_pkg leg.tar "{'contents': {'package_kind': 'bundle'}}"
    mkdir -p "${WORK}/loose"
    cp "${WORK}/leg.tar" "${WORK}/loose/"
    _write_merged_manifest "${WORK}/loose/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/loose"
    assert_true upkg_extract "${UPKG_ASSETS[@]}"
    assert_true upkg_read_manifest

    # _make_pkg's own pins, NOT the loose manifest's portainer entry.
    assert_eq "${UPKG_VERSIONS[elk]:-}" "9.9.9"
    assert_eq "${UPKG_VERSIONS[portainer]:-}" ""
    _teardown
}

test_an_already_merged_manifest_is_not_overwritten() {
    # No package_kind means the extracted manifest is already the merged one
    # (that is what the index job writes). Leave it alone.
    _setup
    _make_pkg mrg.tar
    mkdir -p "${WORK}/loose"
    cp "${WORK}/mrg.tar" "${WORK}/loose/"
    _write_merged_manifest "${WORK}/loose/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/loose"
    assert_true upkg_extract "${UPKG_ASSETS[@]}"
    assert_true upkg_read_manifest
    assert_eq "${UPKG_VERSIONS[portainer]:-}" ""
    _teardown
}

test_an_unreadable_extracted_manifest_does_not_hand_over_precedence() {
    # A corrupt manifest could be a corrupt BUNDLE manifest. Silently replacing
    # it with a loose one would turn a loud failure into a quiet wrong answer,
    # so only an explicit package_kind == "module" concedes precedence.
    _setup
    _make_pkg cor.tar
    rm -rf "${WORK}/x"; mkdir "${WORK}/x"
    tar -xf "${WORK}/cor.tar" -C "${WORK}/x"
    echo 'not json{' > "${WORK}/x/intact-upgrade-test/manifest.json"
    ( cd "${WORK}/x" && tar -cf "${WORK}/cor2.tar" intact-upgrade-test )
    mkdir -p "${WORK}/loose"
    cp "${WORK}/cor2.tar" "${WORK}/loose/"
    _write_merged_manifest "${WORK}/loose/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/loose"
    assert_true upkg_extract "${UPKG_ASSETS[@]}"
    # Still fatal, rather than papered over by the loose manifest.
    assert_false upkg_read_manifest
    _teardown
}

# ---------------------------------------------------------------------------
# upkg_acquire with a partial (--only) fetch
# ---------------------------------------------------------------------------

# A merged manifest naming both elk's and iris's files (real sha256, the
# module asset actually on disk contains only elk's), same shape
# build-release-assets.yml/index publishes.
_write_two_module_manifest() {
    local path="$1"
    python3 -c "
import hashlib, json, sys
def sha(b):
    h = hashlib.sha256(); h.update(b); return h.hexdigest()
shas = {
    'images/elk-9.9.9.tar': sha(b'not a real image\n'),
    'images/iris-v2.4.27.tar': sha(b'not a real iris image\n'),
    'manifests/elk.json': sha(json.dumps({'module': 'elk'}).encode()),
}
json.dump({'package_version': '1.0',
           'created_by': 'build-release-assets.yml/index',
           'versions': {'elk': '9.9.9', 'iris': 'v2.4.27'},
           'contents': {'release_tag': 'intact-test', 'sha256': shas}},
          open(sys.argv[1], 'w'))
" "$path"
}

test_an_only_scoped_fetch_is_verified_against_what_it_extracted() {
    # THE bug this exists to fix. --only trims the DOWNLOAD to fewer modules
    # than the manifest describes (lib/release.sh), but the merged
    # manifest.json it ships still lists every module's files. Before the
    # fix, upkg_acquire always ran the full-manifest check, which treats
    # every manifest path missing from disk as fatal -- so a real --only run
    # (e.g. "upgrade --only intact,velociraptor") always failed here even on
    # a perfectly good fetch, because iris/elk/etc.'s files were never
    # downloaded ON PURPOSE. Observed live on intact-20260813, 2026-08-15.
    _setup
    _make_module_asset elk.tar elk 9.9.9
    mkdir -p "${WORK}/only"
    cp "${WORK}/elk.tar" "${WORK}/only/"
    _write_two_module_manifest "${WORK}/only/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/only"
    INTACT_RELEASE_ONLY_MODULES="elk intact"
    assert_true upkg_acquire "${UPKG_ASSETS[@]}"
    unset INTACT_RELEASE_ONLY_MODULES
    assert_contains "$(cat "$LOG_FILE")" "package contents verified"
    _teardown
}

test_an_only_scoped_fetch_still_catches_a_tampered_file() {
    # Narrowing the SCOPE must not narrow the CHECK: a file the run did
    # extract, that does not match the manifest, is still fatal.
    _setup
    _make_module_asset elk.tar elk 9.9.9
    rm -rf "${WORK}/x"; mkdir "${WORK}/x"
    tar -xf "${WORK}/elk.tar" -C "${WORK}/x"
    echo "TAMPERED" > "${WORK}/x/intact-upgrade-test/images/elk-9.9.9.tar"
    ( cd "${WORK}/x" && tar -cf "${WORK}/elk2.tar" intact-upgrade-test )
    mkdir -p "${WORK}/only"
    cp "${WORK}/elk2.tar" "${WORK}/only/elk.tar"
    _write_two_module_manifest "${WORK}/only/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/only"
    INTACT_RELEASE_ONLY_MODULES="elk intact"
    assert_false upkg_acquire "${UPKG_ASSETS[@]}"
    unset INTACT_RELEASE_ONLY_MODULES
    assert_contains "$(cat "$LOG_FILE")" "do not match the release manifest"
    _teardown
}

test_a_full_fetch_still_refuses_a_module_missing_from_disk() {
    # The safety net --only intentionally turns off must otherwise stay ON:
    # in a FULL (non---only, non-lazy) run, a module the manifest describes
    # but that never landed on disk is a real problem (a dropped asset, a
    # failed extraction) and upkg_acquire must still refuse it, not shrug
    # because some other module's files were present and valid.
    _setup
    _make_module_asset elk.tar elk 9.9.9
    mkdir -p "${WORK}/full"
    cp "${WORK}/elk.tar" "${WORK}/full/"
    _write_two_module_manifest "${WORK}/full/intact-test.manifest.json"

    assert_true upkg_expand_args "${WORK}/full"
    assert_false upkg_acquire "${UPKG_ASSETS[@]}"
    assert_contains "$(cat "$LOG_FILE")" "verification FAILED"
    _teardown
}

run_all_tests
rm -f "$LOG_FILE"; rm -rf "$SCRIPT_DIR"
