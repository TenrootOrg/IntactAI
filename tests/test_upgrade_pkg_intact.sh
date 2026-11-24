#!/bin/bash
# The intact module's offline-package path: what a rolled-back intact must put
# back, and what it must read from the package.
#
#   - the config.yaml pin merge writes only the pins of modules that move, and
#     a rollback restores every pin it changed (versions.backend included);
#   - a re-cut intact-backend:<tag> already on the box is replaced from the
#     package's tar, and the old image comes back on rollback;
#   - image_map.py is read from source/intact/ where the packager puts it;
#   - volweb's env-var-keyed transitive_versions are found;
#   - the sidecar refresh and data/ mirror are undone by _intact_restore.
#
# Docker is faked as functions; nothing here reaches a daemon.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/config.sh
source ../lib/upgrade/helpers.sh
source ../lib/upgrade/modules/shared.sh
source ../lib/upgrade/intact/config.sh
source ../lib/upgrade/intact/image.sh
source ../lib/upgrade/intact/assets.sh
source ../lib/upgrade/intact/tree.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

_fresh() {
    : > "$LOG_FILE"
    SCRIPT_DIR="$(mktemp -d)"; UPKG_DIR="$(mktemp -d)"
    mkdir -p "${SCRIPT_DIR}/modules/backend" "${SCRIPT_DIR}/data/tmp" "${UPKG_DIR}/images"
    CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
    printf "versions:\n  backend: 'intact-old'\n  elk: '9.5.6'\n  iris: v2.4.27\n  nginx: '1.31.3-alpine'\n" > "$CONFIG_FILE"
    UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
    printf '{"versions": {"intact": "intact-new", "elk": "9.6.0", "iris": "v2.4.29", "nginx": "1.31.7-alpine", "volweb": "3.17.0"}}\n' > "$UPKG_MANIFEST"
    PLAN_ACTION=()
}
_pin() { read_config "['versions']['$1']" 2>/dev/null; }

# ---- fix 1: pin merge -----------------------------------------------------

test_merge_moves_only_the_pins_of_modules_that_move() {
    _fresh
    PLAN_ACTION=([intact]=upgrade [elk]="skip:excluded by --only" [iris]=upgrade [volweb]="skip:disabled in config.yaml")
    _intact_merge_versions "$UPKG_DIR"
    assert_eq "$(_pin backend)" "intact-new" "intact maps to versions.backend"
    assert_eq "$(_pin iris)" "v2.4.29"
    assert_eq "$(_pin elk)" "9.5.6" "an --only-excluded module keeps its pin"
    # ...but one with no pin at all gets the package's: _intact_validate_config_pins
    # fails an enabled module without one, and a skipped row is no reason to.
    assert_eq "$(_pin volweb)" "3.17.0" "a skipped module with no pin gets one"
    assert_eq "$(_pin nginx)" "1.31.7-alpine" "a key no module owns moves with intact"
}

test_merge_heals_a_noop_modules_lagging_pin() {
    _fresh
    # .env already runs 9.6.0 (that is what noop means); config.yaml lags.
    PLAN_ACTION=([intact]=upgrade [elk]="noop:already at 9.6.0" [iris]=upgrade [volweb]=install)
    _intact_merge_versions "$UPKG_DIR"
    assert_eq "$(_pin elk)" "9.6.0" "a no-op module's lagging config.yaml pin is healed"
}

test_merge_without_a_plan_merges_every_pin_as_before() {
    _fresh
    _intact_merge_versions "$UPKG_DIR"
    assert_eq "$(_pin elk)" "9.6.0"
    assert_eq "$(_pin volweb)" "3.17.0"
}

test_unmerge_restores_every_changed_pin_and_removes_added_ones() {
    _fresh
    PLAN_ACTION=([intact]=upgrade [elk]=upgrade [iris]=upgrade [volweb]=install)
    _intact_merge_versions "$UPKG_DIR"
    assert_eq "$(_pin backend)" "intact-new"
    _intact_unmerge_versions
    assert_eq "$(_pin backend)" "intact-old" "the rollback puts versions.backend back"
    assert_eq "$(_pin elk)" "9.5.6"
    assert_eq "$(_pin iris)" "v2.4.27"
    assert_eq "$(_pin nginx)" "1.31.3-alpine"
    assert_eq "$(_pin volweb)" "" "a pin the merge added is removed again"
}

test_intact_registers_the_unmerge_before_the_merge() {
    local f=../lib/upgrade/intact/intact.sh undo pin
    undo="$(grep -n 'u_undo "_intact_unmerge_versions"' "$f" | cut -d: -f1)"
    pin="$(grep -n '_intact_merge_versions "\$src"' "$f" | cut -d: -f1)"
    assert_true test -n "$undo"
    assert_true test "${undo:-0}" -lt "${pin:-0}"
}

# ---- fix 2: re-cut backend image -------------------------------------------

# A fake image store: one "ref=id" per line. Loading a tar writes the ref it
# carries with the tar's content as the id.
STORE=""
_u_image_present() { grep -q "^$1=" "$STORE"; }
_img_id() { grep "^$1=" "$STORE" | cut -d= -f2; }
run_with_heartbeat() { shift 2; "$@"; }
upkg_release_loaded_tar() { :; }
u_mark_keep_scratch() { echo "KEEP" >> "$LOG_FILE"; }
declare -gA _U_TAR_FREED=()
fake_docker() {
    case "$1" in
        tag)   local id; id="$(_img_id "$2")"; grep -v "^$3=" "$STORE" > "$STORE.n"; echo "$3=$id" >> "$STORE.n"; mv "$STORE.n" "$STORE" ;;
        image) [[ "$2" == rm ]] && { grep -v "^$3=" "$STORE" > "$STORE.n"; mv "$STORE.n" "$STORE"; } ;;
        load)  local ref="intact-backend:intact-new"; grep -v "^${ref}=" "$STORE" > "$STORE.n"; echo "${ref}=$(cat "$3")" >> "$STORE.n"; mv "$STORE.n" "$STORE" ;;
    esac
    return 0
}
DOCKER_BIN=fake_docker
export -f fake_docker _img_id 2>/dev/null

_image_fresh() {
    _fresh
    STORE="$(mktemp)"; export STORE
    echo "intact-backend:intact-new=first-cut" > "$STORE"
}

test_a_present_tag_is_reloaded_from_the_package_and_kept_for_rollback() {
    _image_fresh
    echo "second-cut" > "${UPKG_DIR}/images/intact-backend-intact-new.tar"
    assert_true _intact_ensure_image intact-new
    assert_eq "$(_img_id intact-backend:intact-new)" "second-cut" "the package's cut wins"
    assert_eq "$(_img_id intact-backend:intact-new-pre-upgrade)" "first-cut"
    assert_true _intact_put_back_image intact-new
    assert_eq "$(_img_id intact-backend:intact-new)" "first-cut" "rollback puts the old cut back"
    assert_false _u_image_present intact-backend:intact-new-pre-upgrade
}

test_a_present_tag_without_a_tar_is_kept_as_before() {
    _image_fresh
    assert_true _intact_ensure_image intact-new
    assert_eq "$(_img_id intact-backend:intact-new)" "first-cut"
    assert_contains "$(cat "$LOG_FILE")" "already present"
    assert_false _u_image_present intact-backend:intact-new-pre-upgrade
}

test_a_successful_run_drops_the_kept_image() {
    _image_fresh
    echo "second-cut" > "${UPKG_DIR}/images/intact-backend-intact-new.tar"
    _intact_ensure_image intact-new
    _intact_drop_kept_image intact-new
    assert_false _u_image_present intact-backend:intact-new-pre-upgrade
}

# ---- fix 3 and 4: package reads ---------------------------------------------

test_image_map_is_read_from_source_intact_first() {
    _fresh
    mkdir -p "${UPKG_DIR}/source/intact/modules/backend/services" "${SCRIPT_DIR}/modules/backend/services"
    touch "${UPKG_DIR}/source/intact/modules/backend/services/image_map.py" \
          "${SCRIPT_DIR}/modules/backend/services/image_map.py"
    assert_eq "$(_u_image_map_file)" "${UPKG_DIR}/source/intact/modules/backend/services/image_map.py"
    rm -rf "${UPKG_DIR}/source"
    mkdir -p "${UPKG_DIR}/modules/backend/services"; touch "${UPKG_DIR}/modules/backend/services/image_map.py"
    assert_eq "$(_u_image_map_file)" "${UPKG_DIR}/modules/backend/services/image_map.py" "the old layout still works"
    rm -rf "${UPKG_DIR}/modules"
    assert_eq "$(_u_image_map_file)" "${SCRIPT_DIR}/modules/backend/services/image_map.py" "then the box's copy"
}

test_transitive_versions_keyed_by_env_var_are_found() {
    _fresh
    printf '{"contents": {"transitive_versions": {"volweb": {"VOLWEB_POSTGRES_VERSION": "14.1", "VOLWEB_REDIS_VERSION": "7.4.9"}, "timesketch": {"POSTGRES_VERSION": "13.0-alpine"}}}}\n' > "$UPKG_MANIFEST"
    assert_eq "$(_u_manifest_transitive volweb postgres VOLWEB_POSTGRES_VERSION)" "14.1"
    assert_eq "$(_u_manifest_transitive volweb redis VOLWEB_REDIS_VERSION)" "7.4.9"
    assert_eq "$(_u_manifest_transitive volweb postgres)" "" "the dep name alone never matched volweb's keys"
    assert_eq "$(_u_manifest_transitive timesketch postgres)" "13.0-alpine" "the prefix match still works"
    assert_true grep -q '_u_manifest_transitive "\$module" "\$man_key" "\$env_var"' ../lib/upgrade/modules/shared.sh
    assert_true grep -q '_u_manifest_transitive "\$m" "\$man_key" "\$env_var"' ../lib/upgrade/intact/config.sh
}

# ---- fix 5 and the data/ mirror: undone by _intact_restore ------------------

test_sidecar_refresh_and_data_mirror_are_undone_by_the_restore() {
    _fresh
    local snap="${SCRIPT_DIR}/data/tmp/intact-rollback-test" src="${UPKG_DIR}/source/intact"
    mkdir -p "${SCRIPT_DIR}/modules/nginx" "${SCRIPT_DIR}/data/custom_artifacts" \
             "${src}/modules/nginx" "${src}/data/custom_artifacts" "${src}/modules/backend"
    echo "app" > "${SCRIPT_DIR}/modules/backend/app.py"
    echo "old compose" > "${SCRIPT_DIR}/modules/nginx/docker-compose.yaml"
    echo "old conf"    > "${SCRIPT_DIR}/modules/nginx/nginx.conf"
    echo "old inv"     > "${SCRIPT_DIR}/data/tools_inventory.yaml"
    echo "box edit"    > "${SCRIPT_DIR}/data/custom_artifacts/Mine.yaml"
    printf 'services:\n  n:\n    volumes:\n      - ./nginx.conf:/etc/nginx/nginx.conf:ro\n      - ./new.inc:/etc/new.inc:ro\n' \
        > "${src}/modules/nginx/docker-compose.yaml"
    echo "new conf" > "${src}/modules/nginx/nginx.conf"
    echo "new inc"  > "${src}/modules/nginx/new.inc"
    echo "new inv"  > "${src}/data/tools_inventory.yaml"
    echo "release copy" > "${src}/data/custom_artifacts/Mine.yaml"
    echo "added"        > "${src}/data/custom_artifacts/New.yaml"

    assert_true _intact_snapshot "$snap"
    _INTACT_SIDECAR_SNAP="${snap}/sidecars"
    assert_true _intact_mirror_data "$src"
    assert_eq "$(cat "${SCRIPT_DIR}/data/tools_inventory.yaml")" "new inv" "release content is replaced"
    assert_eq "$(cat "${SCRIPT_DIR}/data/custom_artifacts/Mine.yaml")" "box edit" "a box's own artifact is never overwritten"
    assert_eq "$(cat "${SCRIPT_DIR}/data/custom_artifacts/New.yaml")" "added" "a new artifact arrives"
    assert_true _intact_refresh_sidecars "$src"
    assert_eq "$(cat "${SCRIPT_DIR}/modules/nginx/nginx.conf")" "new conf"
    assert_true test -f "${SCRIPT_DIR}/modules/nginx/new.inc"

    assert_true _intact_restore "$snap"
    assert_eq "$(cat "${SCRIPT_DIR}/modules/nginx/docker-compose.yaml")" "old compose"
    assert_eq "$(cat "${SCRIPT_DIR}/modules/nginx/nginx.conf")" "old conf" "nginx.conf copied in place comes back"
    assert_false test -e "${SCRIPT_DIR}/modules/nginx/new.inc" "a file the run created is removed"
    assert_eq "$(cat "${SCRIPT_DIR}/data/tools_inventory.yaml")" "old inv"
    assert_false test -e "${SCRIPT_DIR}/data/custom_artifacts/New.yaml"
    assert_eq "$(cat "${SCRIPT_DIR}/data/custom_artifacts/Mine.yaml")" "box edit"
    _INTACT_SIDECAR_SNAP=""
}

test_added_env_keys_are_recorded_for_the_rollback() {
    _fresh
    local snap="${SCRIPT_DIR}/data/tmp/intact-rollback-env"
    mkdir -p "${SCRIPT_DIR}/modules/elk" "$snap"
    echo "A=1" > "${SCRIPT_DIR}/modules/elk/.env"
    update_env_files() { echo "B=2" >> "${SCRIPT_DIR}/modules/elk/.env"; echo "C=3" > "${SCRIPT_DIR}/modules/backend/.env"; }
    _INTACT_SIDECAR_SNAP="${snap}/sidecars"
    _intact_add_missing_env_keys
    assert_true _intact_restore_sidecars "$snap"
    assert_eq "$(cat "${SCRIPT_DIR}/modules/elk/.env")" "A=1"
    assert_false test -e "${SCRIPT_DIR}/modules/backend/.env" "a .env the run created is removed"
    unset -f update_env_files
    _INTACT_SIDECAR_SNAP=""
}

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
