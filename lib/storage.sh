#!/bin/bash
# Where Intact keeps its data: `data_path` in config.yaml. Empty (the default)
# is the system disk, as always: Docker's own /var/lib/docker and the install's
# data/ folder. Set to a folder (usually on another disk), it holds
#   <data_path>/docker       Docker's data root: every module's volumes -- the
#                            Velociraptor datastore of every org, Elasticsearch,
#                            Timesketch, memory dumps, reports -- and the images;
#   <data_path>/intact-data  the install's data/ folder (cases, the database,
#                            Velociraptor's CA), bind-mounted back onto data/ so
#                            no path inside Intact changes.
# scripts/move-data.sh moves a box; install.sh runs it when data_path differs.
#
# Sourced by lib/deps.sh (so by install.sh) and scripts/move-data.sh. Root, python3.

STORAGE_DOCKER_DEFAULT="/var/lib/docker"
STORAGE_DAEMON_JSON="${STORAGE_DAEMON_JSON:-/etc/docker/daemon.json}"
STORAGE_DROPIN="/etc/systemd/system/docker.service.d/intact-data-path.conf"
STORAGE_FSTAB_TAG="# intact data_path"
STORAGE_FSTAB="${STORAGE_FSTAB:-/etc/fstab}"   # tests point it elsewhere

# Merge settings into /etc/docker/daemon.json, keeping every other key.
#   storage_daemon_json_merge [data-root=<path>|data-root=]
# Always sets features.containerd-snapshotter=false (docker save needs it).
# Three installers in lib/deps.sh used to WRITE this file, and one rewrote it
# whenever the containerd key was missing: a "data-root" there -- this feature's,
# or one set by hand -- would be dropped by the next install, Docker would start
# on an empty /var/lib/docker, and every case would look gone.
storage_daemon_json_merge() {
    mkdir -p "$(dirname "$STORAGE_DAEMON_JSON")"
    python3 - "$STORAGE_DAEMON_JSON" "$@" <<'PY'
import json, os, sys
path, args = sys.argv[1], sys.argv[2:]
try:
    with open(path) as fh:
        cfg = json.load(fh) or {}
except FileNotFoundError:
    cfg = {}
except ValueError as e:
    sys.exit(f"{path} is not valid JSON ({e}) -- fix it by hand first")
cfg.setdefault("features", {})["containerd-snapshotter"] = False
for a in args:
    key, _, value = a.partition("=")
    if key == "data-root":
        if value:
            cfg["data-root"] = value
        else:
            cfg.pop("data-root", None)
tmp = path + ".intact-tmp"
with open(tmp, "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
os.replace(tmp, path)
PY
}

# Docker's data root as configured in daemon.json, else the default.
storage_docker_root() {
    python3 - "$STORAGE_DAEMON_JSON" "$STORAGE_DOCKER_DEFAULT" <<'PY'
import json, sys
try:
    print((json.load(open(sys.argv[1])).get("data-root") or sys.argv[2]).rstrip("/") or sys.argv[2])
except Exception:
    print(sys.argv[2])
PY
}

# "" when <path> can hold the data, else why not.
#   storage_check_target <path> <install dir>
storage_check_target() {
    local target="$1" install="$2" root
    [[ "$target" =~ ^/[A-Za-z0-9._/-]+$ && "$target" != *..* ]] \
        || { echo "use an absolute path of letters, digits and . _ - /"; return; }
    target="${target%/}"
    root="$(storage_docker_root)"
    case "$target/" in
        /|/proc/*|/sys/*|/dev/*|/run/*|/boot/*|/etc/*|/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/tmp/*|/var/tmp/*|/var/lib/docker*)
            echo "$target is a system folder"; return ;;
        "$root"/*)
            echo "$target is inside Docker's own data folder"; return ;;
        "$install"/*)
            echo "$target is inside the Intact install folder"; return ;;
    esac
    [[ -d "$target" ]] || { echo "$target does not exist -- create it (or mount the disk there) first"; return; }
    local fstype; fstype="$(findmnt -n -o FSTYPE --target "$target" 2>/dev/null)"
    case "$fstype" in
        ext4|xfs|btrfs) ;;
        *) echo "$target is on ${fstype:-an unknown} filesystem -- Docker needs ext4, xfs or btrfs"; return ;;
    esac
    local probe="$target/.intact-write-test.$$"
    if touch "$probe" 2>/dev/null; then rm -f "$probe"; else echo "$target is not writable"; return; fi
    echo ""
}

# Bytes a move copies: Docker's data root + the install's data/.
storage_used_bytes() {
    local install="$1"
    du -sxb "$(storage_docker_root)" "$install/data/" 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

storage_free_bytes() {
    df -B1 --output=avail "$1" 2>/dev/null | tail -1 | tr -d ' '
}

# Docker must not start until the data location is mounted: on an empty data
# root it would bring every module up with NEW, empty volumes -- and Velociraptor
# with a new CA, which every enrolled client then refuses.
storage_write_dropin() {
    local target="$1" install="$2"
    mkdir -p "$(dirname "$STORAGE_DROPIN")"
    cat > "$STORAGE_DROPIN" <<EOF
# Written by Intact (lib/storage.sh): data_path is $target.
[Unit]
RequiresMountsFor=$target $install/data
EOF
}

# data/ bind-mounted from <target>/intact-data, in /etc/fstab (tagged).
storage_fstab_set() {
    local src="$1" dst="$2"
    storage_fstab_clear "$dst"
    printf '%s %s none bind,x-systemd.requires-mounts-for=%s 0 0  %s\n' \
        "$src" "$dst" "$(dirname "$src")" "$STORAGE_FSTAB_TAG" >> "$STORAGE_FSTAB"
}

storage_fstab_clear() {
    local dst="$1"
    python3 - "$STORAGE_FSTAB" "$dst" "$STORAGE_FSTAB_TAG" <<'PY'
import sys
path, dst, tag = sys.argv[1:]
lines = open(path).read().splitlines(True)
keep = [l for l in lines if not (tag in l and len(l.split()) > 1 and l.split()[1] == dst)]
if keep != lines:
    open(path, "w").writelines(keep)
PY
}

# Where data/ really is: the tagged bind mount's source, else "" (data/ itself).
storage_data_src() {
    local install="$1"
    awk -v dst="$install/data" -v tag="$STORAGE_FSTAB_TAG" \
        'index($0, tag) && $2 == dst {print $1; exit}' "$STORAGE_FSTAB"
}

# Make the box match config.yaml's data_path (install.sh). Nothing to do when
# both Docker's data root and data/ are already where it says; else the move
# (scripts/move-data.sh), which on a fresh box copies next to nothing.
#   storage_apply_data_path <install dir> <data_path>   -> 0 ok, 1 the move failed
# STORAGE_MOVE_CMD overrides the move command (tests).
storage_apply_data_path() {
    local install="$1" path="${2%/}" want_root want_data
    if [[ -n "$path" ]]; then want_root="$path/docker"; want_data="$path/intact-data"
    else want_root="$STORAGE_DOCKER_DEFAULT"; want_data=""; fi
    if [[ "$(storage_docker_root)" == "$want_root" && "$(storage_data_src "$install")" == "$want_data" ]]; then
        return 0
    fi
    echo "data_path: putting Intact's data on ${path:-the system disk}..."
    ${STORAGE_MOVE_CMD:-bash "$install/scripts/move-data.sh"} "${path:---default}" --yes
}
