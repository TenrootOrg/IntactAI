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
    # The module dir as it is on the BOX. Named for a real module, not left as
    # a mktemp name: _intact_deliver_mount_assets only warns about a missing
    # mount asset for a module that is actually ENABLED -- a disabled one has no
    # containers and nothing to break, and warning about it trains people to
    # skim the log. It takes that name from this directory's basename, so a
    # `tmp.XXXX` fixture is no module at all and the warning path was
    # unreachable. `nginx` is enabled unconditionally, so no config fixture.
    PDST="$(mktemp -d)/nginx"
    mkdir -p "$PDST"
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

# ---------------------------------------------------------------------------
# A module whose files changed is re-applied even when its version did not
# (2026-11-16: IRIS and Timesketch kept publishing 0.0.0.0 ports their new
# compose files had moved to 127.0.0.1).
# ---------------------------------------------------------------------------
_two_modules() {   # package and box each with iris (compose differs) and elk (identical)
    _fresh
    REFRESH_SRC="$(mktemp -d)"
    mkdir -p "$REFRESH_SRC/modules/iris" "$REFRESH_SRC/modules/elk" "$SCRIPT_DIR/modules/iris" "$SCRIPT_DIR/modules/elk"
    printf 'services:\n  w:\n    ports: ["127.0.0.1:8443:8443"]\n' > "$REFRESH_SRC/modules/iris/docker-compose.yaml"
    printf 'services:\n  w:\n    ports: ["8443:8443"]\n'           > "$SCRIPT_DIR/modules/iris/docker-compose.yaml"
    printf 'services:\n  e: {}\n' | tee "$REFRESH_SRC/modules/elk/docker-compose.yaml" > "$SCRIPT_DIR/modules/elk/docker-compose.yaml"
    _INTACT_REFRESHED="$(mktemp)"
}

test_a_refreshed_compose_names_its_module_and_an_identical_one_does_not() {
    _two_modules
    assert_true _intact_refresh_sidecars "$REFRESH_SRC"
    assert_eq "$(sort -u "$_INTACT_REFRESHED")" "iris"
}

test_a_changed_code_file_names_its_module() {
    _fresh
    _INTACT_REFRESHED="$(mktemp)"
    echo new > "${PSRC}/entrypoint.sh"; echo old > "${PDST}/entrypoint.sh"
    _intact_refresh_module_code "$PSRC" "$PDST" velociraptor
    assert_eq "$(cat "$_INTACT_REFRESHED")" "velociraptor"
}

test_refreshed_modules_that_would_be_left_alone_are_re_applied() {
    declare -gA PLAN_ACTION=() PLAN_NOTE=() PLAN_CURRENT=() PLAN_TARGET=()
    local m; for m in iris timesketch volweb elk portainer presidio plaso velociraptor; do
        eval "upgrade_module_${m}() { :; }"; PLAN_CURRENT[$m]=1.0; PLAN_TARGET[$m]=1.0
    done
    _plan_module_enabled() { [[ "$1" != portainer ]]; }
    local f; f="$(mktemp)"
    printf '%s\n' iris timesketch volweb elk portainer presidio plaso velociraptor backend > "$f"
    PLAN_ACTION[iris]="skip:excluded by --only"
    PLAN_ACTION[timesketch]="noop:already at 1.0"
    PLAN_ACTION[volweb]="skip:excluded by --skip"
    PLAN_ACTION[elk]="upgrade"
    PLAN_ACTION[portainer]="skip:excluded by --only"                         # disabled in config.yaml
    PLAN_ACTION[presidio]="skip:excluded by --only"; PLAN_CURRENT[presidio]=""   # not installed
    PLAN_ACTION[plaso]="skip:excluded by --only"; PLAN_TARGET[plaso]=2.0         # a version change left out
    PLAN_ACTION[velociraptor]="skip:excluded by --only"
    U_STEP_TOTAL=1
    _intact_reapply_refreshed "$f"
    assert_eq "${PLAN_ACTION[iris]}" "upgrade" "the dashboard's --only is not a reason to keep old containers"
    assert_eq "${PLAN_ACTION[timesketch]}" "upgrade" "a same-version module is re-applied"
    assert_eq "${PLAN_ACTION[volweb]}" "skip:excluded by --skip" "--skip means hands off"
    assert_eq "${PLAN_ACTION[elk]}" "upgrade"
    assert_eq "${PLAN_ACTION[portainer]}" "skip:excluded by --only" "a switched-off tool is not started"
    assert_eq "${PLAN_ACTION[presidio]}" "skip:excluded by --only" "an unticked install is not installed"
    assert_eq "${PLAN_ACTION[plaso]}" "skip:excluded by --only" "no version change past the downgrade/disk checks"
    assert_eq "${PLAN_ACTION[velociraptor]}" "skip:excluded by --only" "plan.sh owns velociraptor"
    assert_eq "${PLAN_ACTION[backend]:-}" "" "the platform's own dirs are not modules of the loop"
    assert_eq "$U_STEP_TOTAL" "3" "two more steps for the progress count"
    for m in iris timesketch volweb elk portainer presidio plaso velociraptor; do unset -f "upgrade_module_${m}"; done
    unset -f _plan_module_enabled
}

test_nothing_refreshed_changes_no_plan() {
    declare -gA PLAN_ACTION=([iris]="noop:already at v2.4.29") PLAN_NOTE=()
    _intact_reapply_refreshed "$(mktemp)"
    assert_eq "${PLAN_ACTION[iris]}" "noop:already at v2.4.29"
}

# A box already upgraded by an engine without the re-apply has the new compose
# on disk and the old containers running; only comparing the two catches it.
_fake_compose_docker() {   # $1 = HostIp the running container publishes on, $2 = its mounts (JSON list)
    _fresh
    mkdir -p "$SCRIPT_DIR/modules/iris"; : > "$SCRIPT_DIR/modules/iris/docker-compose.yaml"
    DOCKER_BIN="$(mktemp)"; chmod +x "$DOCKER_BIN"
    cat > "$DOCKER_BIN" <<EOF
#!/bin/bash
case "\$*" in
  "compose config --format json") echo '{"services":{"w":{"ports":[{"host_ip":"127.0.0.1","published":"8443","target":8443,"protocol":"tcp"}],"volumes":[{"type":"bind","target":"/data"}]}}}' ;;
  "compose ps -a -q w") echo c1 ;;
  "inspect c1") echo '[{"HostConfig":{"PortBindings":{"8443/tcp":[{"HostIp":"$1","HostPort":"8443"}]}},"Mounts":$2}]' ;;
  *) exit 1 ;;
esac
EOF
}

test_a_container_matching_its_compose_has_not_drifted() {
    _fake_compose_docker 127.0.0.1 '[{"Destination":"/data"},{"Destination":"/anon"}]'
    assert_false _intact_compose_drifted iris
}

test_a_container_publishing_a_port_its_compose_moved_has_drifted() {
    _fake_compose_docker "" '[{"Destination":"/data"}]'
    assert_true _intact_compose_drifted iris
}

test_a_container_missing_a_mount_its_compose_added_has_drifted() {
    _fake_compose_docker 127.0.0.1 '[]'
    assert_true _intact_compose_drifted iris
}

test_a_module_without_compose_or_with_a_broken_one_has_not_drifted() {
    _fresh
    DOCKER_BIN=false
    assert_false _intact_compose_drifted presidio
    mkdir -p "$SCRIPT_DIR/modules/presidio"; : > "$SCRIPT_DIR/modules/presidio/docker-compose.yaml"
    assert_false _intact_compose_drifted presidio
}

test_a_drifted_module_is_re_applied_though_no_file_changed() {
    _fake_compose_docker "" '[{"Destination":"/data"}]'
    declare -gA PLAN_ACTION=([iris]="noop:already at v2.4.29") PLAN_NOTE=() PLAN_CURRENT=() PLAN_TARGET=()
    upgrade_module_iris() { :; }
    _intact_reapply_refreshed "$(mktemp)"
    assert_eq "${PLAN_ACTION[iris]}" "upgrade"
    assert_contains "${PLAN_NOTE[iris]:-}" "no longer match"
    unset -f upgrade_module_iris
}

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

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
