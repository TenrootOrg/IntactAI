#!/bin/bash
# parse_install_args() (lib/args.sh): every --package shape, including the
# three system-bundle detection defects found while raising this feature's
# confidence past 85% (see the plan file) --
#   (1) the operator-facing single-file package never carried a bundle at all
#   (2) --package <bundle.tar> pointed at directly was mishandled
#   (3) no sibling lookup next to a file argument
# (1) is a CI/prepare_package.sh fix with its own test; this file covers the
# install.sh-side detection for all three.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

# parse_install_args() needs SCRIPT_DIR, and calls log_info -- stub it so a
# real log line isn't required and LOG_FILE doesn't need to exist.
SCRIPT_DIR="$(mktemp -d)"
trap 'rm -rf "$SCRIPT_DIR"' EXIT
stub log_info

source ../lib/args.sh

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# A directory of N module assets, each a real tar with a shared top-level dir
# (what load_images_from_package() requires to "merge").
_make_module_dir() {
    local dir="$1"; shift
    mkdir -p "$dir"
    local mod tag="intact-upgrade-testtag"
    for mod in "$@"; do
        local work; work="$(mktemp -d)"
        mkdir -p "${work}/${tag}"
        echo "fake image data for $mod" > "${work}/${tag}/${mod}.marker"
        tar -cf "${dir}/${tag}-${mod}.tar" -C "$work" "$tag"
        rm -rf "$work"
    done
}

# A system-bundle tar: a couple of fake .deb-shaped files plus the
# ubuntu-version marker the OS-match gate reads.
_make_bundle_tar() {
    local path="$1"
    local work; work="$(mktemp -d)"
    echo "fake deb" > "${work}/docker-ce_1.0_amd64.deb"
    echo "24.04" > "${work}/ubuntu-version"
    tar -cf "$path" -C "$work" .
    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# Baseline: no --package at all -> online mode, nothing air-gap-shaped.
# ---------------------------------------------------------------------------
test_no_args_is_online_mode() {
    parse_install_args
    assert_eq "$INTACT_AIRGAP" "0" "no --package -> not air-gapped"
    assert_eq "${#INTACT_PACKAGES[@]}" "0" "no --package -> no packages"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "" "no --package -> no bundle"
}

# ---------------------------------------------------------------------------
# Baseline: a plain directory of module assets, no bundle anywhere -> the
# legacy "must already be present" path, unchanged.
# ---------------------------------------------------------------------------
test_dir_with_no_bundle() {
    local dir="${SCRIPT_DIR}/plain"
    _make_module_dir "$dir" velociraptor timesketch
    parse_install_args --package "$dir"
    assert_eq "$INTACT_AIRGAP" "1"
    assert_eq "${#INTACT_PACKAGES[@]}" "2" "both module assets picked up"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "" "no bundle in this dir"
}

# ---------------------------------------------------------------------------
# Baseline: --package <dir> containing an already-extracted system-bundle/
# ---------------------------------------------------------------------------
test_dir_with_extracted_bundle_subdir() {
    local dir="${SCRIPT_DIR}/with-extracted"
    _make_module_dir "$dir" velociraptor
    mkdir -p "${dir}/system-bundle"
    echo "24.04" > "${dir}/system-bundle/ubuntu-version"
    parse_install_args --package "$dir"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "${dir}/system-bundle" \
        "already-extracted system-bundle/ subdir found"
    assert_eq "${#INTACT_PACKAGES[@]}" "1" "bundle dir itself never lands in INTACT_PACKAGES"
}

# ---------------------------------------------------------------------------
# Baseline: --package <dir> containing a *-system-bundle.tar sitting next to
# the module assets.
# ---------------------------------------------------------------------------
test_dir_with_bundle_tar() {
    local dir="${SCRIPT_DIR}/with-tar"
    _make_module_dir "$dir" velociraptor
    _make_bundle_tar "${dir}/testtag-system-bundle.tar"
    parse_install_args --package "$dir"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "${dir}/testtag-system-bundle.tar"
    assert_eq "${#INTACT_PACKAGES[@]}" "1" \
        "the bundle tar must NOT be treated as a module asset (dir-expansion exclusion)"
}

# ---------------------------------------------------------------------------
# Defect (2): --package pointed DIRECTLY at a *-system-bundle.tar file.
# ---------------------------------------------------------------------------
test_bare_file_arg_is_the_bundle_tar() {
    local bundle="${SCRIPT_DIR}/bare/testtag-system-bundle.tar"
    mkdir -p "$(dirname "$bundle")"
    _make_bundle_tar "$bundle"
    parse_install_args --package "$bundle"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "$bundle" \
        "a bare --package <bundle.tar> must be recognised directly"
    assert_eq "${#INTACT_PACKAGES[@]}" "0" \
        "it must not be handed to load_images_from_package as a module asset"
}

# Same, via --package=<bundle.tar> form.
test_bare_file_arg_equals_form() {
    local bundle="${SCRIPT_DIR}/bare-eq/testtag-system-bundle.tar"
    mkdir -p "$(dirname "$bundle")"
    _make_bundle_tar "$bundle"
    parse_install_args --package="$bundle"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "$bundle"
    assert_eq "${#INTACT_PACKAGES[@]}" "0"
}

# ---------------------------------------------------------------------------
# Defect (3): --package points at a single module asset FILE, with the
# bundle sitting beside it in the same directory (the "USB stick" layout).
# ---------------------------------------------------------------------------
test_bundle_beside_a_file_argument() {
    local dir="${SCRIPT_DIR}/sibling"
    _make_module_dir "$dir" velociraptor
    _make_bundle_tar "${dir}/testtag-system-bundle.tar"
    local module_file
    module_file="$(find "$dir" -maxdepth 1 -name '*-velociraptor.tar')"
    parse_install_args --package "$module_file"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "${dir}/testtag-system-bundle.tar" \
        "a bundle beside a file argument must be found"
    assert_eq "${#INTACT_PACKAGES[@]}" "1" "the module file itself is still used"
}

# ---------------------------------------------------------------------------
# Defect (1)'s install.sh-side half: a wrapper tar (what
# scripts/prepare_package.sh produces) carrying the bundle as one of its
# flat members must route it to INTACT_SYSTEM_BUNDLE_SRC, not INTACT_PACKAGES.
# ---------------------------------------------------------------------------
test_wrapper_tar_carries_the_bundle() {
    local work; work="$(mktemp -d)"
    local tag="intact-upgrade-testtag"
    _make_module_dir "$work" velociraptor timesketch
    _make_bundle_tar "${work}/testtag-system-bundle.tar"
    echo '{}' > "${work}/testtag.index.json"

    local wrapper="${SCRIPT_DIR}/wrapper.tar"
    tar -cf "$wrapper" -C "$work" \
        "${tag}-velociraptor.tar" "${tag}-timesketch.tar" \
        "testtag-system-bundle.tar" "testtag.index.json"
    rm -rf "$work"

    parse_install_args --package "$wrapper"
    assert_eq "${#INTACT_PACKAGES[@]}" "2" "both module assets unwrapped"
    assert_ne "$INTACT_SYSTEM_BUNDLE_SRC" "" "bundle must be found inside the wrapper"
    assert_contains "$INTACT_SYSTEM_BUNDLE_SRC" "system-bundle.tar" \
        "the unwrapped bundle path is the extracted copy, not the wrapper itself"
    for pkg in "${INTACT_PACKAGES[@]}"; do
        assert_not_contains "$pkg" "system-bundle" \
            "the bundle must never appear in INTACT_PACKAGES"
    done
    rm -rf "${INTACT_UNWRAP_DIRS[@]}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# First match wins, and a second --package's bundle doesn't override the
# first one found (matches every other "first of N" rule in this file).
# ---------------------------------------------------------------------------
test_first_bundle_found_wins() {
    local dir1="${SCRIPT_DIR}/first" dir2="${SCRIPT_DIR}/second"
    _make_module_dir "$dir1" velociraptor
    _make_module_dir "$dir2" timesketch
    _make_bundle_tar "${dir1}/one-system-bundle.tar"
    _make_bundle_tar "${dir2}/two-system-bundle.tar"
    parse_install_args --package "$dir1" --package "$dir2"
    assert_eq "$INTACT_SYSTEM_BUNDLE_SRC" "${dir1}/one-system-bundle.tar"
}

run_all_tests
