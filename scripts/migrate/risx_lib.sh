#!/bin/bash
# risx_lib.sh — what risx_to_intact.sh shares: messages, finding risx, and
# stopping its Velociraptor gracefully. Sourced; not meant to be executed.
#
# The deployed Velociraptor clients pin the legacy CA + nonce and dial the
# legacy server_urls. Those three things, plus the datastore, are the only
# sacred state on the box (docs/RISX_MIGRATION.md).
# 2026-11-17: the phases of the old migrate_from_risx.sh (copy backup, remove,
# download, install) are gone with it: risx_to_intact.sh does all of it.

MIG_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# logging / prompting
# ---------------------------------------------------------------------------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_off=$'\e[0m'
say()  { echo "${c_grn}[migrate]${c_off} $*"; }
warn() { echo "${c_yel}[migrate] WARN:${c_off} $*"; }
die()  { echo "${c_red}[migrate] ERROR:${c_off} $*" >&2; exit 1; }

confirm() {  # confirm "question" -> returns 0 on yes
    local ans
    read -r -p "$1 [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" || "$ans" == "yes" ]]
}

# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
discover_risx() {
    # Sets: RISX_ROOT (setup_platform), VELO_DIR (compose dir), VELO_DATA
    # (the bind dir = config + datastore + filestore, all in one).
    if [[ -n "${RISX_ROOT:-}" ]]; then
        [[ -d "$RISX_ROOT" ]] || die "RISX_ROOT=$RISX_ROOT does not exist"
    else
        local cands=(/home/*/setup_platform)
        local matches=()
        local c
        for c in "${cands[@]}"; do
            [[ -f "$c/workdir/velociraptor/velociraptor/server.config.yaml" ]] \
                && matches+=("$c")
        done
        if [[ ${#matches[@]} -eq 0 ]]; then
            die "no risx-mssp install found (looked for \
/home/*/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml); \
set RISX_ROOT=... to point at it"
        fi
        if [[ ${#matches[@]} -gt 1 ]]; then
            die "multiple risx-mssp candidates found under /home/*/setup_platform \
(${matches[*]}) — refusing to guess which one is trusted; set RISX_ROOT=... \
after verifying the correct one yourself"
        fi
        RISX_ROOT="${matches[0]}"
        local owner
        owner="$(stat -c %U "$RISX_ROOT")" \
            || die "cannot stat $RISX_ROOT to verify ownership"
        if [[ "$owner" != "$(id -un)" && "$owner" != "root" ]]; then
            die "$RISX_ROOT is owned by '$owner', not by you ($(id -un)) or \
root — refusing to trust a risx-mssp install planted by another local user; \
verify it yourself and set RISX_ROOT=... to override"
        fi
    fi
    VELO_DIR="$RISX_ROOT/workdir/velociraptor"
    VELO_DATA="$VELO_DIR/velociraptor"
    [[ -f "$VELO_DATA/server.config.yaml" ]] \
        || die "no server.config.yaml under $VELO_DATA"
    say "risx-mssp found at $RISX_ROOT"
}

# ---------------------------------------------------------------------------
# stop risx's Velociraptor so the fleet list is saved
# ---------------------------------------------------------------------------
graceful_stop_legacy_velo() {
    # Velociraptor keeps the fleet records — hostname, OS, agent version,
    # last seen — in an in-memory client_info cache that is flushed to
    # <datastore>/client_info/snapshot.json periodically and on a GRACEFUL
    # shutdown. The risx entrypoint starts the server as a CHILD of the shell
    # script (no exec), so `docker stop` sends SIGTERM to the shell and the
    # server is SIGKILLed when the grace period expires — snapshot never
    # written. Collections all survive either way, but the migrated GUI would
    # show an EMPTY fleet until every endpoint happens to re-enroll (which
    # only occurs when the client process restarts). So signal the server
    # itself and wait for the snapshot to land.
    docker ps --format '{{.Names}}' | grep -qx velociraptor || {
        say "legacy velociraptor container is not running"; return 0; }

    say "stopping risx's Velociraptor (it saves its client list first)"
    # A snapshot from an EARLIER stop must not count as this one's flush.
    # sudo: client_info/ is root's. Read as the user, every stat failed and a
    # snapshot that WAS written was reported missing (QA, 2026-11-17).
    local snap="$VELO_DATA/client_info/snapshot.json" before
    before=$(sudo stat -c %Y "$snap" 2>/dev/null || echo 0)
    # the container restarts itself when the server exits — disable that first
    docker update --restart=no velociraptor >/dev/null 2>&1 || true
    # Match on /proc/<pid>/comm (the executable name) rather than the command
    # line: this helper's own shell carries the search words in its argv and
    # would otherwise match — and kill — itself instead of the server.
    local signalled
    signalled=$(docker exec velociraptor sh -c \
        'for p in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
             [ "$p" = "$$" ] && continue
             case "$(cat /proc/$p/comm 2>/dev/null)" in
                 velociraptor*) kill -TERM "$p" && echo "$p" ;;
             esac
         done' 2>/dev/null) || true
    if [[ -z "$signalled" ]]; then
        warn "could not locate the velociraptor server process inside the \
container; falling back to docker stop"
    fi

    # Poll for the snapshot regardless of container state: the server writes
    # it during shutdown, and the container can disappear a moment BEFORE the
    # file lands — bailing out on container-exit alone reports a false miss.
    local t=0 gone=0
    while (( t < 120 )); do
        (( $(sudo stat -c %Y "$snap" 2>/dev/null || echo 0) > before )) && break
        if ! docker ps --format '{{.Names}}' | grep -qx velociraptor; then
            ((gone+=1))
            (( gone > 5 )) && break      # ~15s of grace after the exit
        fi
        sleep 3; ((t+=3))
    done
    docker stop velociraptor >/dev/null 2>&1 || true

    if (( $(sudo stat -c %Y "$snap" 2>/dev/null || echo 0) > before )); then
        say "client list saved (${t}s)"
    else
        warn "no client_info snapshot was written. All collections and client \
keys still migrate, but the fleet list in intact will start EMPTY and fill in \
as endpoints re-enroll (on client/service restart). See \
docs/RISX_MIGRATION.md."
    fi
}
