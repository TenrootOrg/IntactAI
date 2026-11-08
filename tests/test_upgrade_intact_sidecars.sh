#!/bin/bash
# tusd and the platform nginx move to the versions the package ships.
#
# The bug this guards: the packager states those two versions ONLY in the tar
# names (images/tusd-<v>.tar, images/intact-nginx-<v>.tar) -- not in the
# manifest -- and the box's config.yaml holds the old pin. So the upgrade never
# saw a new value, never loaded either tar, and recreated both on the old pin
# with --pull never. A release bumping nginx to 1.31.7 (five CVEs) would have
# left every upgraded box on 1.31.3 with a clean log.
#
# Docker is faked: a tar "contains" the image refs written into it, and loading
# it appends them to the fake image store.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/config.sh
source ../lib/upgrade/helpers.sh
source ../lib/upgrade/intact/config.sh
source ../lib/upgrade/intact/image.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

STORE=""
_u_image_present() { grep -qxF "$1" "$STORE"; }
_u_load_tars_matching() {
    local p f
    for p in "$@"; do
        for f in "${UPKG_DIR}"/images/${p}*.tar; do
            [[ -f "$f" ]] && { cat "$f" >> "$STORE"; echo "loaded $(basename "$f")" >> "$LOG_FILE"; }
        done
    done
    return 0
}

_fresh() {
    : > "$LOG_FILE"
    SCRIPT_DIR="$(mktemp -d)"; UPKG_DIR="$(mktemp -d)"; STORE="$(mktemp)"
    mkdir -p "${SCRIPT_DIR}/modules/backend" "${SCRIPT_DIR}/modules/nginx" "${UPKG_DIR}/images"
    printf 'BACKEND_VERSION=intact-old\nTUSD_VERSION=v2.10.0\n' > "${SCRIPT_DIR}/modules/backend/.env"
    printf 'NGINX_VERSION=1.31.3-alpine\n' > "${SCRIPT_DIR}/modules/nginx/.env"
    CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
    printf "versions:\n  nginx: '1.31.3-alpine'\n  backend_tusd: 'v2.10.0'\n" > "$CONFIG_FILE"
    printf 'tusproject/tusd:v2.10.0\nnginx:1.31.3-alpine\n' > "$STORE"
}
_ship() { echo "$2" > "${UPKG_DIR}/images/$1"; }
_env()  { read_env_var "${SCRIPT_DIR}/modules/$1/.env" "$2"; }

test_both_sidecars_move_to_the_shipped_versions() {
    _fresh
    _ship tusd-v2.10.1.tar tusproject/tusd:v2.10.1
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    assert_true _intact_move_sidecars
    assert_eq "$(_env backend TUSD_VERSION)" "v2.10.1"
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.7-alpine"
    assert_contains "$(cat "$CONFIG_FILE")" "nginx: '1.31.7-alpine'" "config.yaml pin, so a reinstall does not revert it"
    assert_contains "$(cat "$CONFIG_FILE")" "backend_tusd: 'v2.10.1'"
    assert_contains "$(cat "$LOG_FILE")" "loaded intact-nginx-1.31.7-alpine.tar"
}

test_a_package_without_the_tar_leaves_the_pin_alone() {
    _fresh
    _ship tusd-v2.10.1.tar tusproject/tusd:v2.10.1
    assert_true _intact_move_sidecars
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.3-alpine"
    assert_eq "$(_env backend TUSD_VERSION)" "v2.10.1"
}

test_an_image_that_does_not_appear_keeps_the_old_pin_and_says_so() {
    _fresh
    _ship intact-nginx-1.31.7-alpine.tar nginx:something-else
    assert_false _intact_move_sidecars
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.3-alpine" "a pin on an absent image fails the next compose up"
    assert_contains "$(cat "$CONFIG_FILE")" "nginx: '1.31.3-alpine'"
    assert_contains "$(cat "$LOG_FILE")" "[ERROR]   nginx:1.31.7-alpine is not present"
}

test_an_already_current_box_loads_nothing() {
    _fresh
    _ship tusd-v2.10.0.tar tusproject/tusd:v2.10.0
    _ship intact-nginx-1.31.3-alpine.tar nginx:1.31.3-alpine
    assert_true _intact_move_sidecars
    assert_not_contains "$(cat "$LOG_FILE")" "loaded"
}

# The dashboard, and the upgrade dialog in it, are served by nginx. A new nginx
# that does not come up must not leave the box with no UI: the old pins go back.
# Fake docker: nginx answers 200 unless its .env names the image marked BAD.
BAD=""; RECREATES=/dev/null; RUNNING_NGINX=""
fakedocker() {
    case "$1" in
        inspect) [[ "$*" == *Config.Image*intact_nginx* ]] && echo "$RUNNING_NGINX" || echo running ;;
        exec)    [[ -n "$BAD" && "$(_env nginx NGINX_VERSION)" == "$BAD" ]] && echo 502 || echo 200 ;;
        compose) echo x >> "$RECREATES" ;;
    esac
}
DOCKER_BIN=fakedocker U_SIDECAR_WAIT=1 U_PROBE_INTERVAL=0

test_a_new_nginx_that_serves_is_kept() {
    _fresh; BAD=""
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    _intact_move_sidecars
    assert_true _intact_sidecars_or_revert
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.7-alpine"
}

test_a_new_nginx_that_does_not_serve_is_put_back() {
    _fresh; BAD="1.31.7-alpine"; RECREATES="$(mktemp)"
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    _ship tusd-v2.10.1.tar tusproject/tusd:v2.10.1
    _intact_move_sidecars
    assert_false _intact_sidecars_or_revert
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.3-alpine"
    assert_eq "$(_env backend TUSD_VERSION)" "v2.10.0" "both moved together, both go back"
    assert_contains "$(cat "$CONFIG_FILE")" "nginx: '1.31.3-alpine'"
    assert_eq "$(wc -l < "$RECREATES")" "2" "recreated again on the old pins"
    assert_contains "$(cat "$LOG_FILE")" "the old nginx/tusd serve again"
}

test_nothing_moved_means_nothing_probed() {
    _fresh; BAD="1.31.3-alpine"
    assert_true _intact_move_sidecars
    assert_true _intact_sidecars_or_revert
}

# A box installed before 20261021 has no modules/nginx/.env at all: nginx ran a
# floating nginx:alpine and config.yaml had no versions.nginx. update_env_var
# refuses a missing file, so the upgrade loaded 1.31.7 and left nginx on
# nginx:alpine with "Env file not found". Observed 2026-10-28.
_no_nginx_env() {
    _fresh; BAD=""; RUNNING_NGINX="nginx:alpine"
    rm -f "${SCRIPT_DIR}/modules/nginx/.env"
    printf "versions:\n  backend_tusd: 'v2.10.0'\n" > "$CONFIG_FILE"
    echo nginx:alpine >> "$STORE"
}

test_a_box_without_a_nginx_env_moves_nginx() {
    _no_nginx_env
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    assert_true _intact_move_sidecars
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.7-alpine"
    assert_contains "$(cat "$CONFIG_FILE")" "nginx: '1.31.7-alpine'"
    assert_contains "$(cat "$LOG_FILE")" "NGINX_VERSION: alpine -> 1.31.7-alpine" \
        "the old version is the tag the running container had"
    assert_not_contains "$(cat "$LOG_FILE")" "Env file not found"
}

test_a_created_nginx_env_reverts_to_the_image_that_served() {
    _no_nginx_env; BAD="1.31.7-alpine"; RECREATES="$(mktemp)"
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    _intact_move_sidecars
    assert_false _intact_sidecars_or_revert
    assert_eq "$(_env nginx NGINX_VERSION)" "alpine" "compose then runs nginx:alpine, what served before"
}

test_a_created_nginx_env_is_removed_when_nothing_is_known_to_revert_to() {
    _no_nginx_env; RUNNING_NGINX=""; BAD="1.31.7-alpine"; RECREATES="$(mktemp)"
    _ship intact-nginx-1.31.7-alpine.tar nginx:1.31.7-alpine
    _intact_move_sidecars
    assert_false _intact_sidecars_or_revert
    assert_false test -e "${SCRIPT_DIR}/modules/nginx/.env"
}

test_no_nginx_env_is_created_when_the_image_does_not_appear() {
    _no_nginx_env
    _ship intact-nginx-1.31.7-alpine.tar nginx:something-else
    assert_false _intact_move_sidecars
    assert_false test -e "${SCRIPT_DIR}/modules/nginx/.env"
}

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
