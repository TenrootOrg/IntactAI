#!/bin/bash
# Move Intact's data to another drive/folder, or back to the system disk.
#
#   sudo bash scripts/move-data.sh /mnt/intact-data    move there (asks first; --yes skips)
#   sudo bash scripts/move-data.sh --default           back to the system disk
#   sudo bash scripts/move-data.sh --check <path|"">   can it go there? (JSON; changes nothing)
#   sudo bash scripts/move-data.sh --status            the last move (JSON)
#   sudo bash scripts/move-data.sh --cleanup           delete the old copy a finished move kept
#
# What moves (lib/storage.sh): Docker's data root -- every module's volumes and
# the images -- and the install's data/ folder. Every service stops for the copy
# (minutes per 10 GB). The old copy is KEPT until --cleanup: a move never
# deletes evidence. Anything failing before Docker is back up on the new
# location undoes the switch and restarts on the old one. config.yaml's
# data_path is written only when the move succeeded.
#
# Settings → General → Data location runs this on the host as a transient
# systemd unit, so it survives Docker -- and the backend -- stopping.
set -uo pipefail

INSTALL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
                [[ -n "$(ls -A "$d" 2>/dev/null)" ]] && { why="$d already holds data -- choose an empty folder"; break; }
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

# ---------------------------------------------------------------------------
case "${1:-}" in
    --check)  check_json "${2%/}"; exit 0 ;;
    --status) cat "$STATUS" 2>/dev/null || json_out "state=none" "message=no move has run"; exit 0 ;;
    --cleanup)
        [[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
        state="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('state',''))" "$STATUS" 2>/dev/null)"
        [[ "$state" == "done" ]] || { echo "the last move is not 'done' (${state:-none}) -- not deleting anything"; exit 1; }
        old="$(python3 -c "import json,sys;print('\n'.join(json.load(open(sys.argv[1])).get('old_copies') or []))" "$STATUS")"
        [[ -n "$old" ]] || { echo "no old copy to delete"; exit 0; }
        while IFS= read -r p; do
            # Only what a move set aside, never a live location.
            [[ -n "$p" && -e "$p" ]] || continue
            [[ "$p" == "$(storage_docker_root)" || "$p" == "$(storage_data_src "$INSTALL")" ]] && continue
            echo "deleting $p"; rm -rf --one-file-system "$p"
        done <<< "$old"
        python3 - "$STATUS" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); s["old_copies"] = []; s["message"] += " The old copy is deleted."
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
if [[ -n "$TARGET" ]]; then DST_D="$TARGET/docker"; DST_DATA="$TARGET/intact-data"
else DST_D="$STORAGE_DOCKER_DEFAULT"; DST_DATA=""; fi
if [[ "$CUR_D" == "$DST_D" && "$CUR_DATA" == "$DST_DATA" ]]; then
    set_config_data_path "$TARGET"
    status "done" "The data is already on $TARGET_LABEL." "old_copies:l="; exit 0
fi

chk="$(check_json "$TARGET")"
if ! python3 -c "import json,sys; sys.exit(0 if json.loads(sys.argv[1])['ok'] else 1)" "$chk"; then
    status failed "Cannot move to $TARGET_LABEL: $(python3 -c "import json,sys;print(json.loads(sys.argv[1])['reason'])" "$chk")"
    exit 1
fi
if [[ $YES -ne 1 ]]; then
    echo "This stops EVERY Intact service, copies $(numfmt --to=iec "$(storage_used_bytes "$INSTALL")") to $TARGET_LABEL,"
    echo "and restarts on it. The old copy is kept until: sudo bash $0 --cleanup"
    read -r -p "Move now? [y/N] " a; [[ "$a" == [yY]* ]] || exit 1
fi

: > "$LOG"
cp -a "$STORAGE_DAEMON_JSON" "$STORAGE_DAEMON_JSON.before-move-$TS" 2>/dev/null || true
cp -a "$STORAGE_FSTAB" "$STORAGE_FSTAB.before-move-$TS"
DROPIN_BAK=""
[[ -f "$STORAGE_DROPIN" ]] && { DROPIN_BAK="$STORAGE_DROPIN.before-move-$TS"; cp -a "$STORAGE_DROPIN" "$DROPIN_BAK"; }
VOLS_BEFORE="$(docker volume ls -q 2>/dev/null | sort)"
RUNNING_BEFORE="$(docker ps --format '{{.Names}}' 2>/dev/null | sort)"
OLD_COPIES=()

rollback() {
    status failed "$1 -- undoing the switch, restarting on the old location"
    systemctl stop docker.socket docker 2>/dev/null
    [[ -f "$STORAGE_DAEMON_JSON.before-move-$TS" ]] && cp -a "$STORAGE_DAEMON_JSON.before-move-$TS" "$STORAGE_DAEMON_JSON"
    cp -a "$STORAGE_FSTAB.before-move-$TS" "$STORAGE_FSTAB"
    if [[ -n "$DROPIN_BAK" ]]; then cp -a "$DROPIN_BAK" "$STORAGE_DROPIN"; else rm -f "$STORAGE_DROPIN"; fi
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
    status failed "$1. Nothing was switched: Intact is running on its old location again. A partial copy may be left in $TARGET_LABEL." "old_copies:l="
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
if [[ -n "$CUR_DATA" ]]; then                       # data/ was a bind mount: unmount it
    umount "$INSTALL/data" || rollback "Could not unmount $INSTALL/data"
    OLD_COPIES+=("$CUR_DATA")
fi
if [[ -n "$DST_DATA" ]]; then
    if [[ -z "$CUR_DATA" ]]; then                   # data/ was a real folder: set it aside
        mv "$INSTALL/data" "$INSTALL/data.before-move-$TS" || rollback "Could not set data/ aside"
        OLD_COPIES+=("$INSTALL/data.before-move-$TS")
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
else
    OLD_COPIES+=("$CUR_D")
fi

status running "Starting Docker on $TARGET_LABEL"
systemctl daemon-reload
systemctl start docker || rollback "Docker did not start on $DST_D"
for _ in $(seq 1 60); do
    [[ "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)" == "$DST_D" ]] && break; sleep 2
done
[[ "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)" == "$DST_D" ]] || rollback "Docker is not using $DST_D"
[[ "$(docker volume ls -q | sort)" == "$VOLS_BEFORE" ]] || rollback "Docker on $DST_D does not list the same volumes"

status running "Waiting for the services to come back"
for _ in $(seq 1 90); do
    [[ "$(docker ps --format '{{.Names}}' | sort)" == "$RUNNING_BEFORE" ]] && break; sleep 5
done
set_config_data_path "$TARGET" || echo "could not record data_path in config.yaml" | tee -a "$LOG"
missing="$(comm -23 <(echo "$RUNNING_BEFORE") <(docker ps --format '{{.Names}}' | sort) | tr '\n' ' ')"
copies="$(IFS='|'; echo "${OLD_COPIES[*]}")"
if [[ -n "${missing// }" ]]; then
    status "done" "Moved to $TARGET_LABEL, but these containers are not running: $missing" "old_copies:l=$copies"
else
    status "done" "Moved to $TARGET_LABEL. Every service is back. The old copy is kept until you delete it." "old_copies:l=$copies"
fi
