#!/bin/bash
# lib/upgrade/intact/assets.sh — the sidecar compose files and the host-side
# paths they bind-mount.
#
# The case that motivated this suite is the DIRECTORY mount. Delivery only ever
# accepted a regular file, so anything a compose file mounted as a directory --
# elk's ./config/pipeline is the live example -- was frozen at whatever the box
# first installed. A config fix shipped in a later release therefore never
# arrived on an upgraded box, and nothing said so.
#
# It was found on a real 0726 -> current upgrade, not by reading: `main` had
# added `user`/`password` to logstash's elasticsearch output, the upgraded box
# kept 0726's credential-less main.conf, and logstash crash-looped on 401
# "missing authentication credentials for REST request" after an upgrade that
# otherwise reported success.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/upgrade/intact/assets.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

PSRC="" PDST="" COMPOSE=""
_fresh() {
    : > "$LOG_FILE"
    SCRIPT_DIR="$(mktemp -d)"
    PSRC="$(mktemp -d)"     # the module dir as the PACKAGE ships it
    PDST="$(mktemp -d)"     # the module dir as it is on the BOX
    COMPOSE="${PDST}/docker-compose.yaml"
}

# A compose file mounting exactly the paths named, in the form
# _intact_deliver_mount_assets greps for.
_compose_mounting() {
    { echo "services:"; echo "  x:"; echo "    volumes:"
      for m in "$@"; do echo "      - ./${m}:/in/container:ro"; done
    } > "$COMPOSE"
}

# ---------------------------------------------------------------------------
# directory mounts
# ---------------------------------------------------------------------------

test_a_changed_file_inside_a_mounted_directory_is_delivered() {
    # The logstash regression, reduced. Both sides have the file; the package's
    # copy is newer. Before the fix the whole directory was skipped and the box
    # kept its stale copy forever.
    _fresh
    mkdir -p "${PSRC}/config/pipeline" "${PDST}/config/pipeline"
    printf 'output { elasticsearch { user => "elastic" } }\n' \
        > "${PSRC}/config/pipeline/main.conf"
    printf 'output { elasticsearch { } }\n' \
        > "${PDST}/config/pipeline/main.conf"
    _compose_mounting config/pipeline

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_contains "$(cat "${PDST}/config/pipeline/main.conf")" 'user => "elastic"'
    assert_contains "$(cat "$LOG_FILE")" "delivered config/pipeline/main.conf"
}

test_a_new_file_in_a_mounted_directory_is_delivered() {
    # A release adding a file to a directory the box already has.
    _fresh
    mkdir -p "${PSRC}/config/pipeline" "${PDST}/config/pipeline"
    echo old > "${PSRC}/config/pipeline/main.conf"
    echo old > "${PDST}/config/pipeline/main.conf"
    echo new > "${PSRC}/config/pipeline/extra.conf"
    _compose_mounting config/pipeline

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_eq "$(cat "${PDST}/config/pipeline/extra.conf" 2>/dev/null)" "new"
}

test_nested_files_in_a_mounted_directory_are_delivered() {
    _fresh
    mkdir -p "${PSRC}/config/deep/deeper" "${PDST}/config"
    echo v2 > "${PSRC}/config/deep/deeper/thing.yml"
    _compose_mounting config

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_eq "$(cat "${PDST}/config/deep/deeper/thing.yml" 2>/dev/null)" "v2"
}

test_an_overwritten_file_is_backed_up_first() {
    # The overwrite is a judgement call (these directories can hold
    # runtime-written state), so the backup is what makes it recoverable and
    # is part of the contract rather than incidental.
    _fresh
    mkdir -p "${PSRC}/config/pipeline" "${PDST}/config/pipeline"
    echo shipped-new > "${PSRC}/config/pipeline/main.conf"
    echo operator-edit > "${PDST}/config/pipeline/main.conf"
    _compose_mounting config/pipeline

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    local keep="${SCRIPT_DIR}/data/upgrade-backups/$(basename "$PDST")/config/pipeline/main.conf"
    assert_eq "$(cat "$keep" 2>/dev/null)" "operator-edit"
    assert_eq "$(cat "${PDST}/config/pipeline/main.conf")" "shipped-new"
}

test_an_identical_file_in_a_mounted_directory_is_left_alone() {
    # No churn, and nothing logged as delivered -- an upgrade that reports
    # touching files it did not touch is its own kind of misleading.
    _fresh
    mkdir -p "${PSRC}/config/pipeline" "${PDST}/config/pipeline"
    echo same > "${PSRC}/config/pipeline/main.conf"
    echo same > "${PDST}/config/pipeline/main.conf"
    _compose_mounting config/pipeline

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_not_contains "$(cat "$LOG_FILE")" "delivered config/pipeline/main.conf"
}

test_a_directory_the_package_does_not_ship_is_left_alone() {
    # The box has local content and the package has nothing to say about it.
    _fresh
    mkdir -p "${PDST}/config/pipeline"
    echo local-only > "${PDST}/config/pipeline/main.conf"
    _compose_mounting config/pipeline

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_eq "$(cat "${PDST}/config/pipeline/main.conf")" "local-only"
}

# ---------------------------------------------------------------------------
# file mounts — the behaviour that already existed, guarded against the
# directory branch above changing it
# ---------------------------------------------------------------------------

test_a_changed_single_file_mount_is_still_delivered() {
    _fresh
    echo new > "${PSRC}/nginx.conf"
    echo old > "${PDST}/nginx.conf"
    _compose_mounting nginx.conf

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_eq "$(cat "${PDST}/nginx.conf")" "new"
}

test_a_missing_asset_on_both_sides_is_warned_about() {
    _fresh
    _compose_mounting config/absent.conf
    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_contains "$(cat "$LOG_FILE")" "compose may fabricate an empty directory"
}

test_dockers_fabricated_empty_directory_is_replaced_by_the_file() {
    # The exit-126 recovery path: docker made a directory where a FILE belongs.
    _fresh
    echo real > "${PSRC}/nginx.conf"
    mkdir -p "${PDST}/nginx.conf"
    _compose_mounting nginx.conf

    assert_true _intact_deliver_mount_assets "$PSRC" "$PDST" "$COMPOSE"
    assert_eq "$(cat "${PDST}/nginx.conf" 2>/dev/null)" "real"
}

# ---------------------------------------------------------------------------
# module build inputs (_intact_refresh_module_code)
#
# An upgrade replaces the platform's own code but used to leave each module's
# Dockerfile and entrypoint alone -- while lib/upgrade/velociraptor/image.sh
# runs `docker compose build` in that same directory. So a release that fixed
# a module's Dockerfile rebuilt the image on the box from the OLD one.
#
# The safety property is depth 1: everything carrying per-box state lives in a
# subdirectory (config/ has velociraptor's CA, secrets/, clients/,
# bundled_artifacts/), so it cannot be reached from here.
# ---------------------------------------------------------------------------

test_a_changed_module_dockerfile_is_refreshed() {
    _fresh
    printf 'FROM alpine\nRUN echo new\n' > "${PSRC}/Dockerfile"
    printf 'FROM alpine\nRUN echo old\n' > "${PDST}/Dockerfile"
    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_contains "$(cat "${PDST}/Dockerfile")" "echo new"
}

test_a_changed_module_entrypoint_is_refreshed() {
    _fresh
    echo new > "${PSRC}/entrypoint.sh"
    echo old > "${PDST}/entrypoint.sh"
    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_eq "$(cat "${PDST}/entrypoint.sh")" "new"
}

test_per_box_state_in_subdirectories_is_never_touched() {
    # The one that matters: regenerating Velociraptor's config silently orphans
    # every enrolled endpoint, and the generated client installers cannot be
    # recovered from the package.
    _fresh
    mkdir -p "${PSRC}/config" "${PDST}/config" "${PDST}/clients" "${PDST}/secrets"
    echo shipped-default > "${PSRC}/config/server.config.yaml"
    echo THE-REAL-CA     > "${PDST}/config/server.config.yaml"
    echo generated       > "${PDST}/clients/installer.msi"
    echo hunter2         > "${PDST}/secrets/password"

    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_eq "$(cat "${PDST}/config/server.config.yaml")" "THE-REAL-CA"
    assert_eq "$(cat "${PDST}/clients/installer.msi")" "generated"
    assert_eq "$(cat "${PDST}/secrets/password")" "hunter2"
}

test_the_module_env_file_is_never_shipped_over() {
    # .env holds the module's live pin and its credentials.
    _fresh
    echo "VELOCIRAPTOR_VERSION=9.9.9" > "${PSRC}/.env"
    echo "VELOCIRAPTOR_VERSION=0.77.1" > "${PDST}/.env"
    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_contains "$(cat "${PDST}/.env")" "0.77.1"
}

test_a_replaced_module_code_file_is_backed_up() {
    _fresh
    echo new > "${PSRC}/entrypoint.sh"
    echo old > "${PDST}/entrypoint.sh"
    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_eq "$(cat "${SCRIPT_DIR}/data/upgrade-backups/velociraptor/entrypoint.sh" 2>/dev/null)" "old"
}

test_an_unchanged_module_code_file_is_left_alone() {
    _fresh
    echo same > "${PSRC}/entrypoint.sh"
    echo same > "${PDST}/entrypoint.sh"
    assert_true _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_not_contains "$(cat "$LOG_FILE")" "refreshed modules/velociraptor/entrypoint.sh"
}

run_all_tests
rm -f "$LOG_FILE"
