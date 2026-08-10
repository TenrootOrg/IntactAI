#!/bin/bash
# lib/upgrade/intact/tree.sh — snapshot/restore/mirror of the platform's own
# trees.
#
# Covers Bug 0: upgrade_module_intact used to mirror ONLY modules/backend and
# per-module docker-compose.yaml files. Two consequences, both silent: an
# upgraded box never got a UI update (the frontend is served from
# modules/nginx/html, bind-mounted read-only -- nothing copied a new one in),
# and it never regained scripts/upgrade.sh + lib/upgrade/, so a box upgraded
# by this engine could not use it again to take the NEXT release. _intact_mirror
# is now reused for the frontend and the engine itself, gated on the source
# package actually carrying them (a legacy-shaped package does not), and
# _intact_snapshot/_intact_restore cover the same trees for rollback safety.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/upgrade/intact/tree.sh

# Quiet, matching test_upgrade_core.sh's pattern: these log through
# lib/common.sh in production, but a unit test only needs "did it happen".
log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

_fresh_dirs() {
    : > "$LOG_FILE"
    SCRIPT_DIR="$(mktemp -d)"
    SRC="$(mktemp -d)"
}

# ---------------------------------------------------------------------------
# _intact_mirror -- generalized marker
# ---------------------------------------------------------------------------

test_mirror_defaults_to_app_py_for_backward_compat() {
    _fresh_dirs
    mkdir -p "$SRC/modules/backend" "$SCRIPT_DIR/modules/backend"
    echo "old" > "$SCRIPT_DIR/modules/backend/app.py"
    echo "new" > "$SRC/modules/backend/app.py"
    assert_true _intact_mirror "$SRC/modules/backend" "$SCRIPT_DIR/modules/backend"
    assert_eq "$(cat "$SCRIPT_DIR/modules/backend/app.py")" "new"
}

test_mirror_accepts_a_custom_marker_for_the_frontend() {
    _fresh_dirs
    mkdir -p "$SRC/modules/nginx/html" "$SCRIPT_DIR/modules/nginx/html"
    echo "new ui" > "$SRC/modules/nginx/html/index.html"
    assert_true _intact_mirror "$SRC/modules/nginx/html" "$SCRIPT_DIR/modules/nginx/html" "index.html"
    assert_eq "$(cat "$SCRIPT_DIR/modules/nginx/html/index.html")" "new ui"
}

test_mirror_refuses_when_the_marker_is_missing() {
    # Sanity check must still fire with a non-default marker: a malformed or
    # wrong-shaped source tree must not empty the destination.
    _fresh_dirs
    mkdir -p "$SRC/lib" "$SCRIPT_DIR/lib"
    echo "keep me" > "$SCRIPT_DIR/lib/common.sh"
    # $SRC/lib has no common.sh -- refuse, do not touch the destination.
    assert_false _intact_mirror "$SRC/lib" "$SCRIPT_DIR/lib" "common.sh"
    assert_eq "$(cat "$SCRIPT_DIR/lib/common.sh")" "keep me" \
        "a refused mirror must not modify the destination"
}

test_mirror_prunes_files_the_release_retired() {
    _fresh_dirs
    mkdir -p "$SRC/lib" "$SCRIPT_DIR/lib"
    echo "x" > "$SRC/lib/common.sh"
    echo "x" > "$SCRIPT_DIR/lib/common.sh"
    echo "stale" > "$SCRIPT_DIR/lib/deleted_module.sh"
    assert_true _intact_mirror "$SRC/lib" "$SCRIPT_DIR/lib" "common.sh"
    assert_true test ! -f "$SCRIPT_DIR/lib/deleted_module.sh"
}

test_mirror_never_deletes_downloads_even_when_source_lacks_it() {
    # THE specific safety property the plan calls out: downloads/ under
    # modules/nginx/html is generated per-box (Velociraptor client
    # installers), never shipped in a package. A naive --delete mirror would
    # wipe it the instant a release ships a frontend update.
    _fresh_dirs
    mkdir -p "$SRC/modules/nginx/html" "$SCRIPT_DIR/modules/nginx/html/downloads"
    echo "index" > "$SRC/modules/nginx/html/index.html"
    echo "client.msi" > "$SCRIPT_DIR/modules/nginx/html/downloads/client.msi"
    assert_true _intact_mirror "$SRC/modules/nginx/html" "$SCRIPT_DIR/modules/nginx/html" "index.html"
    assert_true test -f "$SCRIPT_DIR/modules/nginx/html/downloads/client.msi"
}

# ---------------------------------------------------------------------------
# _intact_mirror_install_sh
# ---------------------------------------------------------------------------

test_mirror_install_sh_copies_when_present() {
    _fresh_dirs
    echo "old installer" > "$SCRIPT_DIR/install.sh"
    echo "new installer" > "$SRC/install.sh"
    assert_true _intact_mirror_install_sh "$SRC"
    assert_eq "$(cat "$SCRIPT_DIR/install.sh")" "new installer"
}

test_mirror_install_sh_skips_not_fails_on_legacy_package() {
    # A package built before the full-repo layout existed carries no
    # top-level install.sh at all -- this must degrade gracefully, not fail
    # the module over a legacy package shape.
    _fresh_dirs
    echo "keep me" > "$SCRIPT_DIR/install.sh"
    assert_true _intact_mirror_install_sh "$SRC"
    assert_eq "$(cat "$SCRIPT_DIR/install.sh")" "keep me"
    assert_contains "$(cat "$LOG_FILE")" "legacy package layout"
}

# ---------------------------------------------------------------------------
# _intact_snapshot / _intact_restore round trip
# ---------------------------------------------------------------------------

test_snapshot_and_restore_round_trip_every_tree() {
    _fresh_dirs
    mkdir -p "$SCRIPT_DIR/modules/backend" "$SCRIPT_DIR/modules/nginx/html" \
             "$SCRIPT_DIR/lib" "$SCRIPT_DIR/scripts"
    echo "backend-v1"  > "$SCRIPT_DIR/modules/backend/app.py"
    echo "index-v1"    > "$SCRIPT_DIR/modules/nginx/html/index.html"
    echo "common-v1"   > "$SCRIPT_DIR/lib/common.sh"
    echo "upgrade-v1"  > "$SCRIPT_DIR/scripts/upgrade.sh"
    echo "install-v1"  > "$SCRIPT_DIR/install.sh"

    local snap
    snap="$(mktemp -d)"
    assert_true _intact_snapshot "$snap"

    # Simulate a bad upgrade landing v2 everywhere.
    echo "backend-v2" > "$SCRIPT_DIR/modules/backend/app.py"
    echo "index-v2"   > "$SCRIPT_DIR/modules/nginx/html/index.html"
    echo "common-v2"  > "$SCRIPT_DIR/lib/common.sh"
    echo "upgrade-v2" > "$SCRIPT_DIR/scripts/upgrade.sh"
    echo "install-v2" > "$SCRIPT_DIR/install.sh"

    assert_true _intact_restore "$snap"
    assert_eq "$(cat "$SCRIPT_DIR/modules/backend/app.py")"      "backend-v1"
    assert_eq "$(cat "$SCRIPT_DIR/modules/nginx/html/index.html")" "index-v1"
    assert_eq "$(cat "$SCRIPT_DIR/lib/common.sh")"               "common-v1"
    assert_eq "$(cat "$SCRIPT_DIR/scripts/upgrade.sh")"          "upgrade-v1"
    assert_eq "$(cat "$SCRIPT_DIR/install.sh")"                  "install-v1"
}

test_restore_still_works_when_a_box_predates_the_new_trees() {
    # A box snapshotted by an OLDER version of this engine (pre-Bug-0-fix)
    # only ever has $snap/backend -- restore must not require the new
    # trees to be present in the snapshot, only tolerate their absence.
    _fresh_dirs
    mkdir -p "$SCRIPT_DIR/modules/backend"
    echo "backend-v1" > "$SCRIPT_DIR/modules/backend/app.py"
    local snap
    snap="$(mktemp -d)"
    mkdir -p "$snap/backend"
    echo "backend-v1" > "$snap/backend/app.py"

    echo "backend-v2" > "$SCRIPT_DIR/modules/backend/app.py"
    assert_true _intact_restore "$snap"
    assert_eq "$(cat "$SCRIPT_DIR/modules/backend/app.py")" "backend-v1"
}

run_all_tests
