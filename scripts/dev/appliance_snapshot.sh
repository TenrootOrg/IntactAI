#!/usr/bin/env bash
# DEV-ONLY TOOL. Not shipped, not run by CI, not run by install.sh or upgrade.
#
# Freeze the whole appliance, then put it back — so an upgrade can be tested
# from the SAME starting point over and over.
#
#   appliance_snapshot.sh save    <name>
#   appliance_snapshot.sh restore <name>
#   appliance_snapshot.sh list
#
# WHY. Testing "can a 0726 box take this package?" means having a 0726 box
# again after every attempt, and rebuilding one from scratch is a ~40 minute
# install. This makes the second and every later attempt a few minutes.
#
# WHAT IT CAPTURES, and why each part is needed:
#   the checkout      code, config.yaml, modules/*/.env, VERSION -- an upgrade
#                     rewrites all of these, so a re-test needs them back
#   docker volumes    the databases and datastores. Elasticsearch will refuse
#                     to start against a data directory a NEWER version wrote,
#                     so restoring the tree without the volumes gives a box
#                     that cannot boot
#   the backend image the one the box actually runs. Rebuilding it is minutes,
#                     and for a 0726 baseline it cannot be rebuilt from the
#                     current checkout at all
#
# NOT a backup tool. It stops containers, writes to a scratch directory, and
# assumes it is the only thing touching the box.
set -uo pipefail

ACTION="${1:-}"
NAME="${2:-}"
# The appliance to act on. $INTACT_PATH, else the directory this script was
# invoked from if that looks like an appliance, else the dev checkout.
#
# It used to default straight to the dev checkout, which is a trap when more
# than one appliance exists on the box: running it from a 20260726 test
# appliance without exporting INTACT_PATH stopped THAT box's containers (docker
# is global), then read the DEV box's .env for the backend image tag and
# restarted the DEV box's compose files. The result was two appliances' worth of
# containers sharing one set of volumes, a snapshot carrying the wrong backend
# image, and a canary row written into the wrong appliance's intact.db.
# Observed 2026-08-12.
if [ -n "${INTACT_PATH:-}" ]; then
    ROOT="$INTACT_PATH"
elif [ -f "$PWD/VERSION" ] && [ -d "$PWD/modules/backend" ]; then
    ROOT="$PWD"
else
    # A HARDCODED PATH USED TO LIVE HERE, and it is how a restore aimed at the
    # appliance landed on a dev checkout instead: containers stopped, docker
    # volumes removed (they are global, so the REAL appliance lost its data),
    # and the checkout moved aside with its .git. Observed 2026-08-13, one day
    # after the comment above was written about the same hazard.
    #
    # Refuse instead of guessing. This subcommand destroys volumes; a default
    # that is right on one machine and catastrophic on another is not a default
    # worth having.
    # `err` is defined further down; this runs before it exists.
    echo "appliance_snapshot: cannot tell which appliance to act on." >&2
    echo "  \$INTACT_PATH is unset and \$PWD is not an appliance root." >&2
    echo "  This script REMOVES DOCKER VOLUMES. Say which box explicitly:" >&2
    echo "    INTACT_PATH=/path/to/appliance $0 $*" >&2
    exit 2
fi
STORE="${APPLIANCE_SNAPSHOT_DIR:-$HOME/appliance-snapshots}"
MODULES=(portainer volweb velociraptor iris timesketch elk nginx backend)

log() { printf '[snapshot] %s\n' "$1"; }
err() { printf '[snapshot][ERROR] %s\n' "$1" >&2; }

_down() {
    local m
    for m in "${MODULES[@]}"; do
        [ -f "$ROOT/modules/$m/docker-compose.yaml" ] || continue
        ( cd "$ROOT/modules/$m" && sudo docker compose down --remove-orphans ) >/dev/null 2>&1
    done
}

# Only what config.yaml says is enabled.
#
# `docker compose up` in a module directory does not care whether the operator
# enabled that module -- the compose file is on disk either way, because it
# ships with the checkout. Bringing every directory up therefore started elk,
# timesketch, iris, volweb, velociraptor and portainer on a box deliberately
# installed with all of them DISABLED, complete with fresh volumes that were
# never in the snapshot. Restoring a baseline has to reproduce the baseline,
# not the maximal set the tree happens to describe.
#
# backend and nginx are always brought up: they are the platform itself, not a
# module, and config.yaml has no entry for them.
_enabled_modules() {
    python3 - "$ROOT/config.yaml" <<'PY' 2>/dev/null || true
import sys, yaml
try:
    doc = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    raise SystemExit(0)
for name, mod in (doc.get("modules") or {}).items():
    if isinstance(mod, dict) and mod.get("enabled"):
        print(name)
PY
}

_UP_FAILED=()
_up() {
    local m enabled
    _UP_FAILED=()
    enabled=" $(_enabled_modules | tr '\n' ' ') "
    # Reverse order: backend and nginx last, so the dashboard only comes back
    # once what it talks to is already up.
    for (( i=${#MODULES[@]}-1 ; i>=0 ; i-- )); do
        m="${MODULES[$i]}"
        [ -f "$ROOT/modules/$m/docker-compose.yaml" ] || continue
        case "$m" in
            backend|nginx) ;;                      # the platform, always
            *) [[ "$enabled" == *" $m "* ]] || continue ;;
        esac
        if ! ( cd "$ROOT/modules/$m" && sudo docker compose up -d ) >/dev/null 2>&1; then
            _UP_FAILED+=("$m")
        fi
    done

    # Say so. This discarded the exit status as well as the output, so a module
    # that could not start was completely silent -- and the very next line said
    # "saved", which reads as success. Found 2026-08-12: timesketch and
    # portainer both failed on a missing secrets/*.env (the files had been gone
    # since an earlier rolled-back upgrade; their containers were still running
    # from before, so stopping them for the snapshot is what exposed it), and
    # the tool reported a clean save over a half-dead appliance.
    #
    # Reported, not fatal: the snapshot on disk is still valid and the other
    # modules did come up. What must not happen is silence.
    if (( ${#_UP_FAILED[@]} )); then
        err "these module(s) did NOT come back up: ${_UP_FAILED[*]}"
        err "  the appliance is only partly running. To see why, run:"
        for m in "${_UP_FAILED[@]}"; do
            err "    ( cd $ROOT/modules/$m && sudo docker compose up -d )"
        done
        return 1
    fi
    return 0
}

case "$ACTION" in
save)
    [ -n "$NAME" ] || { err "usage: appliance_snapshot.sh save <name>"; exit 2; }
    DEST="$STORE/$NAME"
    if [ -e "$DEST" ]; then
        err "$DEST already exists -- pick another name or remove it"
        exit 1
    fi
    mkdir -p "$DEST/volumes"

    log "stopping containers so nothing is written mid-copy"
    _down

    log "checkout -> $DEST/tree.tar"
    # .git excluded: it is large, unchanged by an upgrade, and the branch is
    # restored by checking the tag out again if it ever matters.
    sudo tar -C "$(dirname "$ROOT")" -cf "$DEST/tree.tar" \
        --exclude="$(basename "$ROOT")/.git" \
        --exclude="$(basename "$ROOT")/data/tmp" \
        "$(basename "$ROOT")" 2>/dev/null

    log "docker volumes"
    _nvol=0
    for v in $(docker volume ls -q 2>/dev/null); do
        mp="$(docker volume inspect -f '{{.Mountpoint}}' "$v" 2>/dev/null)" || continue
        # `sudo test`, not `[ -d ]`. The mountpoint is under /var/lib/docker,
        # which is drwx--x--- root:root, so an unprivileged caller cannot even
        # traverse it and the plain test is FALSE for every volume -- while the
        # `sudo tar` on the next line would have worked fine. Running this
        # script without sudo therefore skipped all 29 volumes, silently, and
        # still wrote a snapshot: right tree, right backend image, 3.0 GB on
        # disk, and not one byte of Elasticsearch, Postgres, OpenSearch or the
        # Velociraptor datastore. Restoring it would have looked like a working
        # appliance that had lost every case. Found 2026-08-12.
        sudo test -d "$mp" || continue
        if sudo tar -C "$mp" -cf "$DEST/volumes/$v.tar" . 2>/dev/null; then
            printf '  %s\n' "$v"
            _nvol=$((_nvol + 1))
        else
            err "  FAILED to archive volume $v"
        fi
    done

    # A snapshot with no volumes is not a snapshot, and the whole danger of the
    # bug above was that it announced success. Refuse to leave one on disk.
    if [ "$_nvol" -eq 0 ]; then
        err "captured 0 volumes -- this snapshot would restore an appliance with"
        err "no data at all. Removing it rather than leaving a convincing decoy."
        err "Run this script with sudo if the volume mountpoints are unreadable."
        rm -rf "$DEST"
        _up
        exit 1
    fi
    log "  $_nvol volume(s) archived"

    log "backend image"
    img="$(grep -E '^BACKEND_VERSION=' "$ROOT/modules/backend/.env" 2>/dev/null | cut -d= -f2-)"
    if [ -n "$img" ] && docker image inspect "intact-backend:$img" >/dev/null 2>&1; then
        sudo docker save -o "$DEST/backend-image.tar" "intact-backend:$img"
        printf '%s\n' "intact-backend:$img" > "$DEST/backend-image.txt"
        log "  saved intact-backend:$img"
    else
        log "  no intact-backend image for '${img:-unset}' -- skipping"
    fi

    { echo "saved:   $(date -Iseconds)"; echo "root:    $ROOT";
      echo "VERSION: $(cat "$ROOT/VERSION" 2>/dev/null)"; } > "$DEST/INFO"
    sudo chown -R "$(id -u):$(id -g)" "$DEST"

    log "bringing the appliance back up"
    _up || true      # reported inside _up; the snapshot itself is still valid
    log "saved -> $DEST  ($(du -sh "$DEST" | cut -f1))"
    ;;

restore)
    [ -n "$NAME" ] || { err "usage: appliance_snapshot.sh restore <name>"; exit 2; }
    SRC="$STORE/$NAME"
    [ -d "$SRC" ] || { err "no snapshot at $SRC"; exit 1; }
    cat "$SRC/INFO" 2>/dev/null | sed 's/^/[snapshot]   /'

    log "stopping containers and removing volumes"
    _down
    docker volume rm $(docker volume ls -q) >/dev/null 2>&1

    log "restoring the checkout"
    # The tree is REPLACED, not merged: a half-upgraded tree with new files the
    # snapshot never had would otherwise survive and quietly change the test.
    #
    # .git is CARRIED ACROSS, not restored from the tar -- save deliberately
    # excludes it (large, and an upgrade never touches it). Replacing the
    # directory wholesale therefore used to DELETE the repository: the checkout
    # came back correct and `git` in it said "not a git repository", taking
    # every worktree pointing at it down too. Nothing was lost because the work
    # was pushed, but recovering meant re-cloning. Excluding something from a
    # backup only works if the restore leaves it alone.
    _keep_git=""
    if [ -d "$ROOT/.git" ]; then
        _keep_git="$(mktemp -d -p "$(dirname "$ROOT")" .git-carry-XXXXXX)"
        sudo mv "$ROOT/.git" "$_keep_git/.git"
    fi
    sudo rm -rf "$ROOT.restoring"
    sudo mkdir -p "$ROOT.restoring"
    sudo tar -C "$ROOT.restoring" -xf "$SRC/tree.tar" 2>/dev/null
    sudo rm -rf "$ROOT.old" && sudo mv "$ROOT" "$ROOT.old" \
        && sudo mv "$ROOT.restoring/$(basename "$ROOT")" "$ROOT" \
        && sudo rm -rf "$ROOT.restoring" "$ROOT.old"

    if [ -n "$_keep_git" ]; then
        sudo mv "$_keep_git/.git" "$ROOT/.git" && sudo rmdir "$_keep_git" \
            && log "carried .git across (the snapshot does not contain one)"
    fi

    log "restoring volumes"
    for t in "$SRC"/volumes/*.tar; do
        [ -f "$t" ] || continue
        v="$(basename "$t" .tar)"
        # Labelled the way compose labels its own, otherwise every later
        # `compose up` says
        #   volume "backend_upload_data" already exists but was not created by
        #   Docker Compose. Use `external: true` to use an existing volume
        # for each one, on every module, forever. Harmless -- compose uses the
        # volume regardless -- but it is noise this tool injects into the logs
        # of the very upgrades it exists to help test. The project name is the
        # volume's own prefix, which is how compose derives it.
        docker volume create \
            --label com.docker.compose.project="${v%%_*}" \
            --label com.docker.compose.volume="${v#*_}" \
            --label com.docker.compose.version=0 \
            "$v" >/dev/null 2>&1
        mp="$(docker volume inspect -f '{{.Mountpoint}}' "$v" 2>/dev/null)" || continue
        sudo tar -C "$mp" -xf "$t" 2>/dev/null && printf '  %s\n' "$v"
    done

    if [ -f "$SRC/backend-image.tar" ]; then
        log "loading the backend image"
        sudo docker load -i "$SRC/backend-image.tar" 2>&1 | tail -1 | sed 's/^/[snapshot]   /'
    fi

    # The marker lives OUTSIDE the tree, so restoring the tree does not restore
    # it -- and install.sh treats its presence as "already initialized",
    # prompts, and exits 0 having done nothing.
    sudo rm -f /etc/intact-initialized

    log "bringing the appliance back up"
    _up || RESTORE_INCOMPLETE=1
    log "restored '$NAME'. VERSION now: $(cat "$ROOT/VERSION" 2>/dev/null)"
    # A restore that did not fully come up is NOT a usable baseline -- a chain
    # test starting from it would attribute the missing stack to whatever it
    # ran next.
    if [ "${RESTORE_INCOMPLETE:-0}" = "1" ]; then
        err "restore incomplete: the appliance is not fully up (see above)"
        exit 1
    fi
    ;;

list)
    for d in "$STORE"/*/; do
        [ -d "$d" ] || continue
        printf '  %-24s %s  %s\n' "$(basename "$d")" "$(du -sh "$d" | cut -f1)" \
               "$(grep -m1 VERSION "$d/INFO" 2>/dev/null)"
    done
    ;;

*)
    err "usage: appliance_snapshot.sh {save|restore|list} [name]"
    exit 2
    ;;
esac
