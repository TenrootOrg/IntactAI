#!/bin/bash
# lib/storage.sh -- the data location (config.yaml data_path).
#
# The trap this guards: three installers in lib/deps.sh WROTE /etc/docker/daemon.json,
# one of them whenever the containerd key was missing. With Docker's data root
# moved to another drive, that rewrite drops "data-root" and Docker starts on an
# empty /var/lib/docker: every case gone from view. Every write is a merge now.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

TMP="$(mktemp -d "${HOME:-/root}/.intact-storage-test.XXXXXX")"   # not /tmp: refused as a data location
trap 'rm -rf "$TMP"' EXIT
export STORAGE_DAEMON_JSON="$TMP/daemon.json" STORAGE_FSTAB="$TMP/fstab"
source ../lib/storage.sh

test_merge_keeps_other_keys_and_sets_the_data_root() {
    printf '{"log-driver": "json-file", "features": {"buildkit": true}}\n' > "$STORAGE_DAEMON_JSON"
    storage_daemon_json_merge "data-root=/mnt/intact-data/docker"
    local j; j="$(cat "$STORAGE_DAEMON_JSON")"
    assert_contains "$j" '"log-driver": "json-file"' "other keys survive"
    assert_contains "$j" '"buildkit": true' "other features survive"
    assert_contains "$j" '"containerd-snapshotter": false' "docker save still works"
    assert_eq "$(storage_docker_root)" "/mnt/intact-data/docker" "the data root is read back"
}

test_a_plain_merge_never_drops_the_data_root() {
    printf '{"data-root": "/mnt/d/docker"}\n' > "$STORAGE_DAEMON_JSON"
    storage_daemon_json_merge                         # what lib/deps.sh does on every install
    assert_eq "$(storage_docker_root)" "/mnt/d/docker" "an install must not drop data-root"
}

test_back_to_the_system_disk_removes_the_data_root() {
    printf '{"data-root": "/mnt/d/docker"}\n' > "$STORAGE_DAEMON_JSON"
    storage_daemon_json_merge "data-root="
    assert_eq "$(storage_docker_root)" "/var/lib/docker" "default again"
}

test_no_daemon_json_means_the_default_root() {
    rm -f "$STORAGE_DAEMON_JSON"
    assert_eq "$(storage_docker_root)" "/var/lib/docker" "default"
}

test_fstab_bind_is_set_once_and_cleared_alone() {
    printf 'UUID=abc / ext4 defaults 0 1\n' > "$STORAGE_FSTAB"
    storage_fstab_set /mnt/d/intact-data /opt/intact/data
    storage_fstab_set /mnt/e/intact-data /opt/intact/data     # a second move replaces it
    assert_eq "$(grep -c 'intact data_path' "$STORAGE_FSTAB")" "1" "one tagged line"
    assert_eq "$(storage_data_src /opt/intact)" "/mnt/e/intact-data" "the latest source"
    storage_fstab_clear /opt/intact/data
    assert_eq "$(cat "$STORAGE_FSTAB")" "UUID=abc / ext4 defaults 0 1" "the rest of fstab untouched"
    assert_eq "$(storage_data_src /opt/intact)" "" "data/ is itself again"
}

test_targets_that_must_be_refused() {
    local t
    for t in "relative/path" "/mnt/a b" "/mnt/../etc" "/" "/etc/intact" "/var/lib/docker/x" "/proc/x" "/tmp" "/var/tmp/x"; do
        assert_ne "$(storage_check_target "$t" /opt/intact)" "" "refuse $t"
    done
    assert_contains "$(storage_check_target /opt/intact/data2 /opt/intact)" "inside the Intact install" "inside install"
    assert_contains "$(storage_check_target "$TMP/nope" /opt/intact)" "does not exist" "missing folder"
}

test_an_existing_writable_folder_on_a_real_filesystem_is_accepted() {
    local fs; fs="$(findmnt -n -o FSTYPE --target "$TMP")"
    case "$fs" in
        ext4|xfs|btrfs) assert_eq "$(storage_check_target "$TMP" /opt/intact)" "" "accepted" ;;
        *) assert_contains "$(storage_check_target "$TMP" /opt/intact)" "filesystem" "tmpfs etc. refused" ;;
    esac
}

# install.sh: make the box match config.yaml's data_path.
_fake_move() { echo "$*" >> "$TMP/moves"; return "${FAKE_MOVE_RC:-0}"; }

test_fresh_install_with_a_data_path_moves_there() {
    rm -f "$STORAGE_DAEMON_JSON" "$TMP/moves"; : > "$STORAGE_FSTAB"
    STORAGE_MOVE_CMD=_fake_move storage_apply_data_path /opt/intact "/mnt/intact-data/" >/dev/null
    assert_eq "$(cat "$TMP/moves")" "/mnt/intact-data --yes" "moved to the configured drive"
}

test_nothing_to_do_when_the_box_already_matches() {
    rm -f "$TMP/moves"
    printf '{"data-root": "/mnt/d/docker"}\n' > "$STORAGE_DAEMON_JSON"
    : > "$STORAGE_FSTAB"; storage_fstab_set /mnt/d/intact-data /opt/intact/data
    STORAGE_MOVE_CMD=_fake_move storage_apply_data_path /opt/intact /mnt/d >/dev/null
    assert_eq "$(cat "$TMP/moves" 2>/dev/null)" "" "a reinstall on the same drive moves nothing"
    rm -f "$STORAGE_DAEMON_JSON"; : > "$STORAGE_FSTAB"
    STORAGE_MOVE_CMD=_fake_move storage_apply_data_path /opt/intact "" >/dev/null
    assert_eq "$(cat "$TMP/moves" 2>/dev/null)" "" "the default box (no data_path) moves nothing"
}

test_clearing_data_path_moves_back_and_a_failure_stops_the_install() {
    rm -f "$TMP/moves"
    printf '{"data-root": "/mnt/d/docker"}\n' > "$STORAGE_DAEMON_JSON"
    STORAGE_MOVE_CMD=_fake_move storage_apply_data_path /opt/intact "" >/dev/null
    assert_eq "$(cat "$TMP/moves")" "--default --yes" "back to the system disk"
    FAKE_MOVE_RC=1 STORAGE_MOVE_CMD=_fake_move storage_apply_data_path /opt/intact "/mnt/e" >/dev/null
    assert_eq "$?" "1" "a failed move fails the install"
}

run_all_tests
