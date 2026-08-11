#!/usr/bin/env bash
# DEV-ONLY TOOL. Not shipped, not run by CI, not run by install.sh or upgrade.
#
# Reclaim what a local build-and-import test cycle leaves behind.
#
# WHY THIS EXISTS. One test cycle writes the same multi-GB payload to FIVE
# places, and nothing removed any of them: the build cache (~2.7 GB/tag), the
# release output (~1.8 GB/tag), the staged copy under data/tmp, the upload
# volume, and a new intact-backend image (1.26 GB). On 2026-08-11 that had
# reached 38 GB across eight tags and the appliance was at 89% full, which is
# not merely untidy -- plan_check_disk refuses an upgrade for want of space, so
# the leftovers of past tests stop the next one from running at all.
#
# Deliberately NOT age-based, unlike the two sweeps inside the product
# (routes/upgrade_routes.py's stale stages and uploads). This is a dev box
# running tests back to back; "older than 48h" would keep every tag built
# today, which is exactly the pile that caused the problem.
#
# Usage:
#   scripts/dev/cleanup_local_test_leftovers.sh [--keep N] [--dry-run]
#
#   --keep N    keep the N newest build/release tags (default 1). The images
#               are always kept to the newest two, matching the rollback
#               guarantee app.py's boot prune makes -- one to run, one to fall
#               back to.
#   --dry-run   print what would go, touch nothing.
set -uo pipefail

KEEP=1
DRY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)    KEEP="${2:-1}"; shift 2 ;;
        --keep=*)  KEEP="${1#*=}"; shift ;;
        --dry-run) DRY=1; shift ;;
        --help|-h) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_CACHE="${HOME}/.cache/intact-local-build"
RELEASES="${HOME}/intact-local-releases"

say()  { printf '  %s\n' "$*"; }
run()  { if (( DRY )); then say "would: $*"; else "$@" >/dev/null 2>&1; fi; }
free_gb() { df -BG --output=avail / | tail -1 | tr -dc '0-9'; }

BEFORE="$(free_gb)"
echo "Free before: ${BEFORE}G"
echo

# --- build cache + release output, oldest first -----------------------------
# Tags sort lexicographically because they are intact-YYYYMMDD.
for dir in "$BUILD_CACHE" "$RELEASES"; do
    [[ -d "$dir" ]] || continue
    echo "$(basename "$dir"):"
    mapfile -t tags < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
    n=${#tags[@]}
    drop=$(( n - KEEP ))
    (( drop < 0 )) && drop=0
    for ((i = 0; i < drop; i++)); do
        sz="$(du -sh "${dir}/${tags[$i]}" 2>/dev/null | cut -f1)"
        say "drop ${tags[$i]} (${sz})"
        run sudo rm -rf "${dir}/${tags[$i]}"
    done
    (( drop == 0 )) && say "nothing to drop (${n} tag(s), keeping ${KEEP})"
    echo
done

# --- staged packages + finished run logs ------------------------------------
# The stage under data/tmp is a hard link to the upload, so removing it frees
# nothing on its own -- it is the upload below that actually holds the bytes.
# Both go, or the next `du` is confusing.
echo "data/tmp:"
shopt -s nullglob
for p in "${ROOT}"/data/tmp/import-pkg-* "${ROOT}"/data/tmp/upgrade-pkg-*; do
    say "drop $(basename "$p")"
    run sudo rm -rf "$p"
done
# Keep the newest run's log and marker: that is the one someone is most likely
# to still want to read after a failure.
mapfile -t logs < <(find "${ROOT}/data/tmp" -maxdepth 1 -name 'upgrade-upgrade_*.log' -printf '%f\n' 2>/dev/null | sort)
for ((i = 0; i < ${#logs[@]} - 1; i++)); do
    id="${logs[$i]%.log}"; id="${id#upgrade-}"
    say "drop run ${id}"
    run sudo rm -f "${ROOT}/data/tmp/upgrade-${id}.log" \
                   "${ROOT}/data/tmp/upgrade-${id}.done.json" \
                   "${ROOT}/data/tmp/upgrade-launch-${id}.sh" \
                   "${ROOT}/data/tmp/recreate-${id}.log"
done
shopt -u nullglob
echo

# --- imported packages in the upload volume ---------------------------------
# Where the bytes actually are. The product sweeps these at 7 days
# (_sweep_stale_uploads); a test box cannot wait a week.
echo "uploads volume:"
if docker ps --format '{{.Names}}' | grep -q '^intact_backend$'; then
    mapfile -t ups < <(docker exec intact_backend sh -c 'ls -1 /data/uploads 2>/dev/null')
    if (( ${#ups[@]} )); then
        for u in "${ups[@]}"; do
            say "drop /data/uploads/${u}"
            run docker exec intact_backend rm -rf "/data/uploads/${u}"
        done
    else
        say "already empty"
    fi
else
    say "intact_backend not running — skipped"
fi
echo

# --- superseded backend images ----------------------------------------------
# Same rule as app.py's boot prune: newest two release tags, and never a tag a
# container references. Hand-built tags (:development, :latest) are left alone;
# they do not accumulate and deleting a dev box's working image to save 1.26 GB
# is a poor trade.
echo "intact-backend images:"
mapfile -t rel < <(docker images intact-backend --format '{{.Tag}}' 2>/dev/null \
                   | grep -E '^intact-[0-9]{8}' | sort -r)
inuse="$(docker ps -a --format '{{.Image}}' 2>/dev/null)"
for ((i = 2; i < ${#rel[@]}; i++)); do
    ref="intact-backend:${rel[$i]}"
    if grep -qF "$ref" <<< "$inuse"; then
        say "keep ${ref} (a container references it)"
        continue
    fi
    say "drop ${ref}"
    run docker rmi "$ref"
done
(( ${#rel[@]} <= 2 )) && say "nothing to drop (${#rel[@]} release tag(s), keeping 2)"
echo

# --- docker build cache + dangling layers -----------------------------------
# Cache only: costs rebuild time, never data. It reached 12.5 GB here, which
# was larger than every release package on the box put together.
echo "docker cache:"
if (( DRY )); then
    say "would: docker builder prune -af && docker image prune -f"
    docker system df 2>/dev/null | sed -n '2,5p' | sed 's/^/    /'
else
    say "build cache: $(docker builder prune -af 2>/dev/null | tail -1)"
    say "dangling:    $(docker image prune -f 2>/dev/null | tail -1)"
fi
echo

AFTER="$(free_gb)"
echo "Free after:  ${AFTER}G  (+$((AFTER - BEFORE))G)"
(( DRY )) && echo "(dry run — nothing was removed)"
exit 0
