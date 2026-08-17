#!/bin/bash
# lib/state_registry.sh — the per-box state relocation, executed.
#
# The shape that matters: a migrated FILE must be a HARD link at the
# historical path, because containers bind-mount parent DIRECTORIES
# (./config:/etc/timesketch) and a symlink's relative target does not exist
# inside the container. Found live: tsctl ran against no config, "stamped"
# nowhere, and the timesketch upgrade failed its alembic bootstrap.
# Directories cannot be hard-linked and stay symlinks (Docker resolves
# per-path binds on the host).

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

source ../lib/state_registry.sh

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

_fresh_root() {
    rm -rf "$ROOT"; mkdir -p "$ROOT/modules/timesketch/config" "$ROOT/modules/iris/config/certificates"
}

test_a_migrated_file_is_a_hard_link_not_a_symlink() {
    _fresh_root
    local rel="modules/timesketch/config/timesketch.conf"
    echo "SECRET_KEY = 'abc'" > "${ROOT}/${rel}"
    assert_true state_migrate_one "$ROOT" "$rel"
    local canon="${ROOT}/$(state_canonical_path "$rel")"
    [[ -f "$canon" ]] || _fail "canonical copy missing"
    [[ -L "${ROOT}/${rel}" ]] && _fail "historical path is a symlink — dangles inside a dir-mounting container"
    [[ "${ROOT}/${rel}" -ef "$canon" ]] || _fail "historical path is not the same inode as the canonical copy"
    assert_true state_is_migrated "$ROOT" "$rel"
}

test_writing_through_either_name_updates_both() {
    _fresh_root
    local rel="modules/timesketch/config/timesketch.conf"
    echo "v1" > "${ROOT}/${rel}"
    state_migrate_one "$ROOT" "$rel" >/dev/null 2>&1
    # In-place truncate, the way the render/openssl writers work.
    echo "v2" > "${ROOT}/${rel}"
    assert_eq "$(cat "${ROOT}/$(state_canonical_path "$rel")")" "v2" \
        "canonical copy must see a write through the historical name"
}

test_a_migrated_directory_stays_a_symlink() {
    _fresh_root
    local rel="modules/iris/config/certificates/rootCA"
    mkdir -p "${ROOT}/${rel}"; echo key > "${ROOT}/${rel}/ca.key"
    assert_true state_migrate_one "$ROOT" "$rel"
    [[ -L "${ROOT}/${rel}" ]] || _fail "directory entry should be a symlink"
    [[ -f "${ROOT}/${rel}/ca.key" ]] || _fail "directory contents unreachable through the symlink"
    assert_true state_is_migrated "$ROOT" "$rel"
}

test_an_old_file_symlink_is_upgraded_to_a_hard_link() {
    _fresh_root
    # A box migrated by the symlink-era engine: canonical file + symlink.
    local rel="modules/timesketch/config/timesketch.conf"
    local canon_rel; canon_rel="$(state_canonical_path "$rel")"
    mkdir -p "$(dirname "${ROOT}/${canon_rel}")"
    echo "cfg" > "${ROOT}/${canon_rel}"
    ln -s "../../../${canon_rel}" "${ROOT}/${rel}"
    # The half-migrated state must NOT read as done…
    assert_false state_is_migrated "$ROOT" "$rel"
    # …and re-running the migration must land the hard link.
    assert_true state_migrate_one "$ROOT" "$rel"
    [[ -L "${ROOT}/${rel}" ]] && _fail "still a symlink after re-migration"
    [[ "${ROOT}/${rel}" -ef "${ROOT}/${canon_rel}" ]] || _fail "not hard-linked after re-migration"
    assert_eq "$(cat "${ROOT}/${rel}")" "cfg" "content lost in the upgrade"
}

test_unmigrate_restores_the_real_file() {
    _fresh_root
    local rel="modules/timesketch/config/timesketch.conf"
    echo "cfg" > "${ROOT}/${rel}"
    state_migrate_one "$ROOT" "$rel" >/dev/null 2>&1
    assert_true state_unmigrate_one "$ROOT" "$rel"
    [[ -L "${ROOT}/${rel}" ]] && _fail "unmigrate left a symlink"
    assert_eq "$(cat "${ROOT}/${rel}")" "cfg"
    [[ -e "${ROOT}/$(state_canonical_path "$rel")" ]] && _fail "canonical copy still present after unmigrate"
    return 0
}

test_migrate_with_only_a_canonical_copy_relinks_the_historical_path() {
    _fresh_root
    # git clean removed the modules-side name; data/state survived.
    local rel="modules/timesketch/config/timesketch.conf"
    local canon_rel; canon_rel="$(state_canonical_path "$rel")"
    mkdir -p "$(dirname "${ROOT}/${canon_rel}")"
    echo "cfg" > "${ROOT}/${canon_rel}"
    assert_true state_migrate_one "$ROOT" "$rel"
    [[ "${ROOT}/${rel}" -ef "${ROOT}/${canon_rel}" ]] || _fail "historical path not re-linked from the canonical copy"
}

test_a_package_skeleton_never_dethrones_real_state() {
    _fresh_root
    # The live IRIS disaster, reduced: canonical holds the real CA, a
    # delivery step recreated the tracked .gitkeep skeleton at the live path.
    local rel="modules/iris/config/certificates/rootCA"
    local canon_rel; canon_rel="$(state_canonical_path "$rel")"
    mkdir -p "${ROOT}/${canon_rel}"
    echo "REAL-CA-KEY" > "${ROOT}/${canon_rel}/irisRootCAKey.pem"
    mkdir -p "${ROOT}/${rel}"; : > "${ROOT}/${rel}/.gitkeep"
    assert_true state_migrate_one "$ROOT" "$rel"
    [[ -f "${ROOT}/${canon_rel}/irisRootCAKey.pem" ]] || _fail "real CA dethroned by a .gitkeep skeleton"
    ls "${ROOT}/$(dirname "$canon_rel")" | grep -q superseded && _fail "skeleton case must not create .superseded litter"
    assert_eq "$(cat "${ROOT}/${rel}/irisRootCAKey.pem" 2>/dev/null)" "REAL-CA-KEY" \
        "historical path must reach the real CA again"
}

test_a_genuinely_updated_live_copy_still_wins() {
    _fresh_root
    # The timesketch.conf case: live carries newer real content; it must win.
    local rel="modules/timesketch/config/timesketch.conf"
    local canon_rel; canon_rel="$(state_canonical_path "$rel")"
    mkdir -p "$(dirname "${ROOT}/${canon_rel}")"
    echo "stale" > "${ROOT}/${canon_rel}"
    echo "migrated-credential" > "${ROOT}/${rel}"
    assert_true state_migrate_one "$ROOT" "$rel"
    assert_eq "$(cat "${ROOT}/${canon_rel}")" "migrated-credential" "the real live copy wins"
    ls "${ROOT}/$(dirname "$canon_rel")" | grep -q superseded || _fail "the stale copy must be kept as .superseded"
}

run_all_tests
