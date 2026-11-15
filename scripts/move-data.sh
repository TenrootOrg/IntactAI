#!/bin/bash
# Move Intact's data to another drive/folder, or back to the system disk.
#
#   sudo bash scripts/move-data.sh /mnt/intact-data    move there (asks first; --yes skips)
#   sudo bash scripts/move-data.sh --default           back to the system disk
#   sudo bash scripts/move-data.sh --undo              go back to the backup the last move kept
#   sudo bash scripts/move-data.sh --check <path|"">   can it go there? (JSON; changes nothing)
#   sudo bash scripts/move-data.sh --status            the last move (JSON)
#   sudo bash scripts/move-data.sh --cleanup           delete the backup(s) a move kept
#
# What moves (lib/storage.sh): Docker's data root -- every module's volumes and
# the images -- and the install's data/ folder. Every service stops for the copy
# (minutes per 10 GB). The old location is KEPT as the backup until --cleanup: a
# move never deletes evidence. Anything failing before Docker is back up on the
# new location undoes the switch and restarts on the old one. config.yaml's
# data_path is written only when the move succeeded.
#
# --undo is the backup's purpose: it switches straight back to it -- no copy, a
# minute or so -- as it was BEFORE the move, so anything written since is not
# there. The copy the move made becomes the backup instead. --cleanup deletes the
# backups, and with them the undo.
#
# Settings → General → Data storage runs this on the host as a transient systemd
# unit, so it survives Docker -- and the backend -- stopping.
set -uo pipefail

INSTALL="${INTACT_MOVE_INSTALL:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# Run from a private copy. A move restarts Docker, and the backend coming back
# re-syncs scripts/ from the copy baked into its image; bash reads a script as it
# runs, so a rewrite of this file mid-move would corrupt the move itself.
if [[ -z "${INTACT_MOVE_INSTALL:-}" && $EUID -eq 0 ]]; then
    _self="$(mktemp /run/intact-move-data.XXXXXX)" && cp "${BASH_SOURCE[0]}" "$_self" \
        && INTACT_MOVE_INSTALL="$INSTALL" exec bash "$_self" "$@"
fi
# This is the private copy: unlink it now (bash keeps it open while it runs).
[[ "${BASH_SOURCE[0]}" == /run/intact-move-data.* ]] && rm -f "${BASH_SOURCE[0]}"
# shellcheck source=lib/storage.sh
source "$INSTALL/lib/storage.sh"
STATUS="$INSTALL/data-move-status.json"
LOG="$INSTALL/data-move.log"
TS="$(date +%Y%m%d-%H%M%S)"

json_out() {   # key=value ...; key:b bool (1/0), key:n number, key:l list ("|"-separated)
    python3 - "$@" <<'PY'
import json, sys
out = {}
for a in sys.argv[1:]:
    k, _, v = a.partition("=")
    if k.endswith(":b"):
        out[k[:-2]] = v == "1"
    elif k.endswith(":n"):
        out[k[:-2]] = int(v or 0)
    elif k.endswith(":l"):
        out[k[:-2]] = [x for x in v.split("|") if x]
    else:
        out[k] = v
print(json.dumps(out))
PY
}

status() {   # status <state> <message> [key=value ...]
    local state="$1" msg="$2"; shift 2
    json_out "state=$state" "message=$msg" "target=${TARGET_LABEL:-}" "started=${STARTED:-}" \
             "updated=$(date -Is)" "$@" > "$STATUS.tmp" && mv -f "$STATUS.tmp" "$STATUS"
    echo "[$(date +%T)] $state: $msg" | tee -a "$LOG"
}

status_field() {   # status_field <key>: a value of the last status ("" if none; lists "|"-joined)
    python3 - "$STATUS" "$1" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1])).get(sys.argv[2], "")
except Exception:
    v = ""
print("|".join(v) if isinstance(v, list) else v)
PY
}

# Backups an earlier move kept that still exist, minus any path given ("|"-joined).
# Every status carries them on: one written without them would hide them from
# "Delete backup" -- full copies of the data, left taking space unseen.
earlier_copies() {
    python3 - "$STATUS" "$@" <<'PY'
import json, os, sys
try:
    old = json.load(open(sys.argv[1])).get("old_copies") or []
except Exception:
    old = []
skip = set(sys.argv[2:])
print("|".join(p for p in old if os.path.exists(p) and p not in skip))
PY
}

# config.yaml data_path := $1, in place: the backend mounts config.yaml by inode,
# so truncate and write, never replace the file.
set_config_data_path() {
    python3 - "$INSTALL/config.yaml" "$1" <<'PY'
import re, sys
path, value = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().splitlines(True)
new = f'data_path: "{value}"\n'
for i, l in enumerate(lines):
    if re.match(r"^data_path\s*:", l):
        lines[i] = new
        break
else:
    at = next((i + 1 for i, l in enumerate(lines) if re.match(r"^domain\s*:", l)), len(lines))
    lines[at:at] = ["\n", "# Where Intact keeps its data (empty = the system disk). Settings -> General.\n", new]
with open(path, "r+", encoding="utf-8") as fh:
    fh.seek(0); fh.write("".join(lines)); fh.truncate()
PY
}

check_json() {
    local target="$1" why used free fstype root
    root="$(storage_docker_root)"
    used="$(storage_used_bytes "$INSTALL")"
    if [[ -z "$target" ]]; then
        # /var/lib/docker may not exist: a move away sets it aside.
        free="$(storage_free_bytes "$(dirname "$STORAGE_DOCKER_DEFAULT")")"; why=""
        fstype="$(findmnt -n -o FSTYPE --target / 2>/dev/null)"
        if [[ "$root" != "$STORAGE_DOCKER_DEFAULT" && -n "$(ls -A "$STORAGE_DOCKER_DEFAULT" 2>/dev/null)" ]]; then
            why="$STORAGE_DOCKER_DEFAULT already holds data (an old copy?) -- delete or rename it first"
        fi
    else
        why="$(storage_check_target "$target" "$INSTALL")"
        free="$(storage_free_bytes "$target" 2>/dev/null || echo 0)"
        fstype="$(findmnt -n -o FSTYPE --target "$target" 2>/dev/null)"
        if [[ -z "$why" && "$root" != "$target/docker" ]]; then
            for d in "$target/docker" "$target/intact-data"; do
                [[ -n "$(ls -A "$d" 2>/dev/null)" ]] && { why="$d already holds data (a backup?) -- delete the backup or choose an empty folder"; break; }
            done
        fi
    fi
    if [[ -z "$why" && "${free:-0}" -lt $(( used + used / 20 + 1073741824 )) ]]; then
        why="not enough free space: the move copies $(numfmt --to=iec "$used") and keeps the old copy"
    fi
    json_out "ok:b=$([[ -z "$why" ]] && echo 1 || echo 0)" "reason=$why" "used_bytes:n=$used" \
             "free_bytes:n=${free:-0}" "fstype=${fstype:-}" "docker_root=$root" \
             "data_src=$(storage_data_src "$INSTALL")"
}

# Rollback backups of the host config this run changes, and putting them back.
save_host_config() {
    cp -a "$STORAGE_DAEMON_JSON" "$STORAGE_DAEMON_JSON.before-move-$TS" 2>/dev/null || true
    cp -a "$STORAGE_FSTAB" "$STORAGE_FSTAB.before-move-$TS"
    DROPIN_BAK=""
    [[ -f "$STORAGE_DROPIN" ]] && { DROPIN_BAK="$STORAGE_DROPIN.before-move-$TS"; cp -a "$STORAGE_DROPIN" "$DROPIN_BAK"; }
}
restore_host_config() {
    [[ -f "$STORAGE_DAEMON_JSON.before-move-$TS" ]] && cp -a "$STORAGE_DAEMON_JSON.before-move-$TS" "$STORAGE_DAEMON_JSON"
    cp -a "$STORAGE_FSTAB.before-move-$TS" "$STORAGE_FSTAB"
    if [[ -n "$DROPIN_BAK" ]]; then cp -a "$DROPIN_BAK" "$STORAGE_DROPIN"; else rm -f "$STORAGE_DROPIN"; fi
}
drop_host_config_backups() {
    # For THIS run only: a .before-move file left in docker.service.d/ or /etc is
    # clutter an operator has to wonder about.
    rm -f "$STORAGE_DAEMON_JSON.before-move-$TS" "$STORAGE_FSTAB.before-move-$TS" ${DROPIN_BAK:+"$DROPIN_BAK"}
}

wait_for_docker_on() {   # wait_for_docker_on <root>: 0 when Docker runs on it
    for _ in $(seq 1 60); do
        [[ "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)" == "$1" ]] && return 0; sleep 2
    done
    return 1
}

wait_for_services() {    # wait_for_services <names, sorted>: echoes the ones still missing
    for _ in $(seq 1 90); do
        [[ "$(docker ps --format '{{.Names}}' | sort)" == "$1" ]] && break; sleep 5
    done
    comm -23 <(echo "$1") <(docker ps --format '{{.Names}}' | sort) | tr '\n' ' '
}

# ---------------------------------------------------------------------------
# --undo: back to the location the last move left as its backup, no copy.
undo() {
    exec 9>/run/intact-data-move.lock
    flock -n 9 || { echo "another data move is running"; exit 1; }
    STARTED="$(date -Is)"
    local state prev_path root_bak data_bak
    state="$(status_field state)"
    prev_path="$(status_field undo_path)"
    root_bak="$(status_field undo_root_backup)"
    data_bak="$(status_field undo_data_backup)"
    # Read now: every status written below replaces the file.
    local backups earlier
    backups="$(status_field old_copies)"
    earlier="$(earlier_copies "$root_bak" "$data_bak" "$STORAGE_DOCKER_DEFAULT" "$INSTALL/data")"
    TARGET_LABEL="${prev_path:-the system disk}"
    if [[ "$state" != "done" || -z "$root_bak" || -z "$data_bak" ]]; then
        echo "nothing to undo: the last move kept no backup to go back to"; exit 1
    fi
    if [[ ! -d "$root_bak" || ! -d "$data_bak" ]]; then
        status failed "Cannot undo: the backup ($root_bak, $data_bak) is gone." "old_copies:l=$(earlier_copies)"
        exit 1
    fi
    local cur_d cur_data prev_d moved_root moved_data
    cur_d="$(storage_docker_root)"
    cur_data="$(storage_data_src "$INSTALL")"
    if [[ -n "$prev_path" ]]; then prev_d="$prev_path/docker"; else prev_d="$STORAGE_DOCKER_DEFAULT"; fi
    : > "$LOG"
    save_host_config
    local running_before; running_before="$(docker ps --format '{{.Names}}' 2>/dev/null | sort)"

    undo_failed() {
        status failed "$1 -- putting the location back as it was"
        systemctl stop docker.socket docker 2>/dev/null
        restore_host_config
        mountpoint -q "$INSTALL/data" && umount "$INSTALL/data"
        # data/: a local backup that was put back goes back to being the backup
        if [[ -z "$prev_path" && ! -e "$data_bak" && -d "$INSTALL/data" ]]; then
            mv -T "$INSTALL/data" "$data_bak"
        fi
        if [[ "${moved_data:-}" == "$INSTALL/data.undone-$TS" && -d "$moved_data" ]]; then
            rmdir "$INSTALL/data" 2>/dev/null; mv -T "$moved_data" "$INSTALL/data"
        fi
        mkdir -p "$INSTALL/data"
        systemctl daemon-reload
        [[ -n "$cur_data" ]] && mount "$INSTALL/data" 2>/dev/null
        # Docker's data root
        if [[ "$prev_d" == "$STORAGE_DOCKER_DEFAULT" && -d "$STORAGE_DOCKER_DEFAULT" && ! -e "$root_bak" ]]; then
            mv -T "$STORAGE_DOCKER_DEFAULT" "$root_bak"
        fi
        if [[ "${moved_root:-}" == "$STORAGE_DOCKER_DEFAULT.undone-$TS" && -d "$moved_root" ]]; then
            rmdir "$STORAGE_DOCKER_DEFAULT" 2>/dev/null; mv -T "$moved_root" "$STORAGE_DOCKER_DEFAULT"
        fi
        systemctl start docker
        status failed "$1. Nothing was switched: Intact is running where it was before Undo." \
            "old_copies:l=$backups" "undo_path=$prev_path" \
            "undo_root_backup=$root_bak" "undo_data_backup=$data_bak"
        exit 1
    }

    status running "Stopping every service (Docker)"
    systemctl stop docker.socket docker || undo_failed "Docker did not stop"

    status running "Switching back to $TARGET_LABEL"
    # data/ -- the copy the move made is set aside as the new backup
    if [[ -n "$cur_data" ]]; then
        umount "$INSTALL/data" || undo_failed "Could not unmount $INSTALL/data"
        moved_data="$cur_data"
    else
        mv -T "$INSTALL/data" "$INSTALL/data.undone-$TS" || undo_failed "Could not set data/ aside"
        moved_data="$INSTALL/data.undone-$TS"
        mkdir "$INSTALL/data"; chown --reference="$moved_data" "$INSTALL/data"
    fi
    if [[ -z "$prev_path" ]]; then                    # back to a plain data/ folder
        storage_fstab_clear "$INSTALL/data"
        rmdir "$INSTALL/data" 2>/dev/null
        mv -T "$data_bak" "$INSTALL/data" || undo_failed "Could not put $data_bak back as data/"
    else                                              # back to data/ on the other disk
        storage_fstab_set "$data_bak" "$INSTALL/data"
        systemctl daemon-reload
        mount "$INSTALL/data" || undo_failed "Could not mount $data_bak on $INSTALL/data"
    fi
    # Docker's data root
    if [[ "$cur_d" == "$STORAGE_DOCKER_DEFAULT" ]]; then
        mv -T "$STORAGE_DOCKER_DEFAULT" "$STORAGE_DOCKER_DEFAULT.undone-$TS" || undo_failed "Could not set $cur_d aside"
        moved_root="$STORAGE_DOCKER_DEFAULT.undone-$TS"
    else
        moved_root="$cur_d"
    fi
    if [[ "$prev_d" == "$STORAGE_DOCKER_DEFAULT" ]]; then
        # Docker may have left an empty /var/lib/docker behind; anything more stops the undo.
        rmdir "$STORAGE_DOCKER_DEFAULT" 2>/dev/null
        mv -T "$root_bak" "$STORAGE_DOCKER_DEFAULT" || undo_failed "Could not put $root_bak back"
        storage_daemon_json_merge "data-root="
        rm -f "$STORAGE_DROPIN"
    else
        storage_daemon_json_merge "data-root=$prev_d"
        storage_write_dropin "$prev_path" "$INSTALL"
    fi

    status running "Starting Docker on $TARGET_LABEL"
    systemctl daemon-reload
    systemctl start docker || undo_failed "Docker did not start on $prev_d"
    wait_for_docker_on "$prev_d" || undo_failed "Docker is not using $prev_d"

    status running "Waiting for the services to come back"
    local missing; missing="$(wait_for_services "$running_before")"
    set_config_data_path "$prev_path" || echo "could not record data_path in config.yaml" | tee -a "$LOG"
    drop_host_config_backups
    local copies; copies="$moved_root|$moved_data"
    copies="$copies${earlier:+|$earlier}"
    status "done" "Undone: back on $TARGET_LABEL, as it was before the move.${missing:+ Not running yet: $missing.} The copy the move made is kept as a backup until you delete it." \
        "old_copies:l=$copies"
    exit 0
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    --check)  check_json "${2%/}"; exit 0 ;;
    --status) cat "$STATUS" 2>/dev/null || json_out "state=none" "message=no move has run"; exit 0 ;;
    --undo)
        [[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0 --undo"; exit 1; }
        undo ;;
    --cleanup)
        [[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
        state="$(status_field state)"
        [[ "$state" == "done" ]] || { echo "the last move is not 'done' (${state:-none}) -- not deleting anything"; exit 1; }
        old="$(status_field old_copies | tr '|' '\n')"
        [[ -n "$old" ]] || { echo "no old copy to delete"; exit 0; }
        while IFS= read -r p; do
            # Only what a move set aside, never a live location.
            [[ -n "$p" && -e "$p" ]] || continue
            [[ "$p" == "$(storage_docker_root)" || "$p" == "$(storage_data_src "$INSTALL")" \
               || "$p" == "$INSTALL/data" ]] && continue
            echo "deleting $p"; rm -rf --one-file-system "$p"
        done <<< "$old"
        # The backup is gone, and with it the undo.
        python3 - "$STATUS" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); s["old_copies"] = []; s["message"] += " The backup is deleted."
for k in ("undo_path", "undo_root_backup", "undo_data_backup"):
    s.pop(k, None)
json.dump(s, open(sys.argv[1], "w"))
PY
        exit 0 ;;
    --default) TARGET="" ;;
    ""|-h|--help) sed -n '2,10p' "$0"; exit 1 ;;
    *)         TARGET="${1%/}" ;;
esac
YES=0; [[ "${2:-}" == "--yes" ]] && YES=1
[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0 $*"; exit 1; }
exec 9>/run/intact-data-move.lock
flock -n 9 || { echo "another data move is running"; exit 1; }

TARGET_LABEL="${TARGET:-the system disk}"
STARTED="$(date -Is)"
CUR_D="$(storage_docker_root)"
CUR_DATA="$(storage_data_src "$INSTALL")"            # "" = data/ itself
# Where the data is now: what --undo goes back to after this move.
if [[ "$CUR_D" == "$STORAGE_DOCKER_DEFAULT" ]]; then PREV_PATH=""; else PREV_PATH="${CUR_D%/docker}"; fi
EARLIER="$(earlier_copies)"
if [[ -n "$TARGET" ]]; then DST_D="$TARGET/docker"; DST_DATA="$TARGET/intact-data"
else DST_D="$STORAGE_DOCKER_DEFAULT"; DST_DATA=""; fi
if [[ "$CUR_D" == "$DST_D" && "$CUR_DATA" == "$DST_DATA" ]]; then
    set_config_data_path "$TARGET"
    status "done" "The data is already on $TARGET_LABEL." "old_copies:l=$EARLIER"; exit 0
fi

chk="$(check_json "$TARGET")"
if ! python3 -c "import json,sys; sys.exit(0 if json.loads(sys.argv[1])['ok'] else 1)" "$chk"; then
    status failed "Cannot move to $TARGET_LABEL: $(python3 -c "import json,sys;print(json.loads(sys.argv[1])['reason'])" "$chk")" \
        "old_copies:l=$EARLIER"
    exit 1
fi
if [[ $YES -ne 1 ]]; then
    echo "This stops EVERY Intact service, copies $(numfmt --to=iec "$(storage_used_bytes "$INSTALL")") to $TARGET_LABEL,"
    echo "and restarts on it. The old location is kept as a backup until: sudo bash $0 --cleanup"
    read -r -p "Move now? [y/N] " a; [[ "$a" == [yY]* ]] || exit 1
fi

: > "$LOG"
save_host_config
VOLS_BEFORE="$(docker volume ls -q 2>/dev/null | sort)"
RUNNING_BEFORE="$(docker ps --format '{{.Names}}' 2>/dev/null | sort)"
OLD_COPIES=()

rollback() {
    status failed "$1 -- undoing the switch, restarting on the old location"
    systemctl stop docker.socket docker 2>/dev/null
    restore_host_config
    mountpoint -q "$INSTALL/data" && umount "$INSTALL/data"
    if [[ -d "$INSTALL/data.before-move-$TS" ]]; then
        rmdir "$INSTALL/data" 2>/dev/null; mv "$INSTALL/data.before-move-$TS" "$INSTALL/data"
    fi
    systemctl daemon-reload
    [[ -n "$CUR_DATA" ]] && mount "$INSTALL/data" 2>/dev/null
    if [[ -d "$STORAGE_DOCKER_DEFAULT.before-move-$TS" ]]; then
        rm -rf --one-file-system "$STORAGE_DOCKER_DEFAULT" 2>/dev/null
        mv "$STORAGE_DOCKER_DEFAULT.before-move-$TS" "$STORAGE_DOCKER_DEFAULT"
    fi
    systemctl start docker
    status failed "$1. Nothing was switched: Intact is running on its old location again. A partial copy may be left in $TARGET_LABEL." "old_copies:l=$EARLIER"
    exit 1
}

status running "Stopping every service (Docker)"
systemctl stop docker.socket docker || rollback "Docker did not stop"

status running "Copying Docker's data ($(du -sxh "$CUR_D" 2>/dev/null | cut -f1)) to $DST_D"
mkdir -p "$DST_D" && chmod 711 "$DST_D"
rsync -aHAXS --numeric-ids "$CUR_D/" "$DST_D/" >> "$LOG" 2>&1 || rollback "Copying Docker's data failed (see $LOG)"

SRC_DATA="${CUR_DATA:-$INSTALL/data}"
if [[ -n "$DST_DATA" ]]; then
    status running "Copying the install's data/ folder ($(du -sxh "$SRC_DATA" 2>/dev/null | cut -f1))"
    mkdir -p "$DST_DATA"
    rsync -aHAXS --numeric-ids "$SRC_DATA/" "$DST_DATA/" >> "$LOG" 2>&1 || rollback "Copying data/ failed (see $LOG)"
    chown --reference="$SRC_DATA" "$DST_DATA"; chmod --reference="$SRC_DATA" "$DST_DATA"
fi

status running "Switching to $TARGET_LABEL"
UNDO_DATA_BACKUP="$CUR_DATA"
if [[ -n "$CUR_DATA" ]]; then                       # data/ was a bind mount: unmount it
    umount "$INSTALL/data" || rollback "Could not unmount $INSTALL/data"
    OLD_COPIES+=("$CUR_DATA")
fi
if [[ -n "$DST_DATA" ]]; then
    if [[ -z "$CUR_DATA" ]]; then                   # data/ was a real folder: set it aside
        mv "$INSTALL/data" "$INSTALL/data.before-move-$TS" || rollback "Could not set data/ aside"
        OLD_COPIES+=("$INSTALL/data.before-move-$TS")
        UNDO_DATA_BACKUP="$INSTALL/data.before-move-$TS"
        mkdir "$INSTALL/data"
        chown --reference="$INSTALL/data.before-move-$TS" "$INSTALL/data"
    fi
    storage_fstab_set "$DST_DATA" "$INSTALL/data"
    systemctl daemon-reload
    mount "$INSTALL/data" || rollback "Could not mount $DST_DATA on $INSTALL/data"
else                                                # back to the system disk
    storage_fstab_clear "$INSTALL/data"
    rsync -aHAXS --numeric-ids "$SRC_DATA/" "$INSTALL/data/" >> "$LOG" 2>&1 || rollback "Copying data/ back failed"
fi
if [[ -n "$TARGET" ]]; then
    storage_daemon_json_merge "data-root=$DST_D"
    storage_write_dropin "$TARGET" "$INSTALL"
else
    storage_daemon_json_merge "data-root="
    rm -f "$STORAGE_DROPIN"
fi
if [[ "$CUR_D" == "$STORAGE_DOCKER_DEFAULT" ]]; then
    # Out of the way, so nothing starts on it by mistake. Kept until --cleanup.
    mv "$STORAGE_DOCKER_DEFAULT" "$STORAGE_DOCKER_DEFAULT.before-move-$TS" || rollback "Could not set $CUR_D aside"
    OLD_COPIES+=("$STORAGE_DOCKER_DEFAULT.before-move-$TS")
    UNDO_ROOT_BACKUP="$STORAGE_DOCKER_DEFAULT.before-move-$TS"
else
    OLD_COPIES+=("$CUR_D")
    UNDO_ROOT_BACKUP="$CUR_D"
fi

status running "Starting Docker on $TARGET_LABEL"
systemctl daemon-reload
systemctl start docker || rollback "Docker did not start on $DST_D"
wait_for_docker_on "$DST_D" || rollback "Docker is not using $DST_D"
[[ "$(docker volume ls -q | sort)" == "$VOLS_BEFORE" ]] || rollback "Docker on $DST_D does not list the same volumes"

status running "Waiting for the services to come back"
missing="$(wait_for_services "$RUNNING_BEFORE")"
set_config_data_path "$TARGET" || echo "could not record data_path in config.yaml" | tee -a "$LOG"
drop_host_config_backups
copies="$(IFS='|'; echo "${OLD_COPIES[*]}")${EARLIER:+|$EARLIER}"
undo_info=("undo_path=$PREV_PATH" "undo_root_backup=$UNDO_ROOT_BACKUP" "undo_data_backup=$UNDO_DATA_BACKUP")
if [[ -n "${missing// }" ]]; then
    status "done" "Moved to $TARGET_LABEL, but these containers are not running: $missing" "old_copies:l=$copies" "${undo_info[@]}"
else
    status "done" "Moved to $TARGET_LABEL. Every service is back. The old location is kept as a backup until you delete it." "old_copies:l=$copies" "${undo_info[@]}"
fi
