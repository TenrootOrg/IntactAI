#!/bin/bash
# The codex mount stamp works where a dashboard upgrade runs it: inside the
# backend container, with no operator account and no host /home.
#
# The bug: there it stamped the empty placeholder. A box where codex worked lost
# it at the next recreate; a box installed before codex never mounted ~/.codex,
# so installing codex the documented way was never seen by Re-check.
#
# getent, su and docker are faked; the "host" is a temp dir.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/config.sh
log_info() { :; }; log_warn() { :; }
read_config() { echo ""; }
su() { return 1; }                       # the operator cannot be switched to
export PATH="/usr/bin:/bin"              # no codex on this PATH

HOST_HOME=""; DOCKER_OK=1; GETENT_HOME=""
getent() { [[ -n "$GETENT_HOME" ]] && echo "op:x:1000:1000::${GETENT_HOME}:/bin/bash"; [[ -n "$GETENT_HOME" ]]; }
docker() {
    [[ "$DOCKER_OK" == 1 ]] || return 1
    case "$1" in
        inspect) echo "intact-backend:test" ;;
        run) if [[ "$*" == *hostpasswd* ]]; then echo "$HOST_HOME"; else mkdir -p "${HOST_HOME}/.codex"; fi ;;
    esac
}

_fresh() {
    SCRIPT_DIR="$(mktemp -d)"; HOST_HOME="$(mktemp -d)"; GETENT_HOME=""; DOCKER_OK=1
    ENV="${SCRIPT_DIR}/backend.env"; : > "$ENV"
}
_env() { sed -n "s/^$1=//p" "$ENV" | tail -1; }

test_inside_the_container_the_home_comes_from_the_host() {
    _fresh
    _stamp_host_codex_paths "$ENV"
    assert_eq "$(_env INTACT_HOST_CODEX_HOME)" "${HOST_HOME}/.codex"
    assert_true test -d "${HOST_HOME}/.codex"
}

test_a_good_earlier_stamp_is_never_replaced_by_the_placeholder() {
    _fresh; DOCKER_OK=0
    printf 'INTACT_HOST_CODEX_HOME=/home/op/.codex\nINTACT_HOST_CODEX_PKG=/home/op/.codex/packages/standalone/releases\nINTACT_HOST_CODEX_NPM=/usr/lib/node_modules\n' > "$ENV"
    _stamp_host_codex_paths "$ENV"
    assert_eq "$(_env INTACT_HOST_CODEX_HOME)" "/home/op/.codex"
    assert_eq "$(_env INTACT_HOST_CODEX_PKG)" "/home/op/.codex/packages/standalone/releases"
    assert_eq "$(_env INTACT_HOST_CODEX_NPM)" "/usr/lib/node_modules"
}

test_nothing_known_anywhere_falls_back_to_the_placeholder() {
    _fresh; DOCKER_OK=0
    _stamp_host_codex_paths "$ENV"
    assert_eq "$(_env INTACT_HOST_CODEX_HOME)" "${SCRIPT_DIR}/data/agentic_cli/host-home"
}

test_on_the_host_the_operators_home_is_used_as_before() {
    _fresh; GETENT_HOME="$HOST_HOME"; mkdir -p "${HOST_HOME}/.codex"; DOCKER_OK=0
    _stamp_host_codex_paths "$ENV"
    assert_eq "$(_env INTACT_HOST_CODEX_HOME)" "${HOST_HOME}/.codex"
}

run_all_tests; _rc=$?
exit $_rc
