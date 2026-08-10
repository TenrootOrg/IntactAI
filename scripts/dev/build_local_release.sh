#!/usr/bin/env bash
# DEV-ONLY TOOL. Not part of the shipped product, not run by CI, not run by
# install.sh/upgrade — this exists purely so changes to the backend/frontend
# can be exercised through the REAL package + apply pipeline (a genuine
# intact-upgrade-<tag>.tar, applied through the real offline-upgrade code
# path) without cutting an actual GitHub release for every iteration, and
# without re-downloading the ~5.5G of module assets that never change
# between backend-only edits.
#
# What it does:
#   1. The other 8 modules (elk/iris/timesketch/plaso/velociraptor/volweb/
#      aws_sigma/portainer) are downloaded ONCE per tag into a local cache
#      and reused on every later run for that tag — they don't change when
#      you're iterating on backend code, so there's no reason to re-fetch
#      them over a slow link every time.
#   2. The `intact` module (backend + frontend + tusd) is rebuilt from
#      CURRENT source EVERY run, using the same
#      scripts/ci/build_release_package.py CI itself uses — run inside the
#      already-running intact_backend container (it already has the docker
#      socket + every backend dependency installed) so no extra image needs
#      building. Docker's layer cache means this is fast unless
#      requirements*.txt actually changed.
#   3. The fresh `intact` asset + the cached 8 are combined into one real
#      intact-upgrade-<tag>.tar, ready for the normal offline-upgrade apply
#      path (or Import Upgrade Package in the dashboard).
#
# Usage: scripts/dev/build_local_release.sh <tag> [out_dir]
#
#   Delete the cache to force a re-download of the 8 cached modules:
#     rm -rf ~/.cache/intact-local-release/<tag>
set -euo pipefail

TAG="${1:?usage: build_local_release.sh <tag> [out_dir]}"
OUT_DIR="${2:-.}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="${INTACT_LOCAL_RELEASE_CACHE:-$HOME/.cache/intact-local-release}/$TAG"
BACKEND_CONTAINER="${INTACT_BACKEND_CONTAINER:-intact_backend}"
CACHED_MODULES="elk,iris,timesketch,plaso,velociraptor,volweb,aws_sigma,portainer"

log() { printf '[local-release] %s\n' "$1"; }
err() { printf '[local-release][ERROR] %s\n' "$1" >&2; }

mkdir -p "$OUT_DIR" "$CACHE_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

if ! docker inspect "$BACKEND_CONTAINER" >/dev/null 2>&1; then
    err "container '$BACKEND_CONTAINER' is not running -- this needs a live"
    err "backend container (docker socket + backend deps already installed)"
    exit 1
fi

# ── Step 1: the 8 non-backend module assets, downloaded once per tag ──────
CACHE_TAR="$CACHE_DIR/subset.tar"
if [ ! -f "$CACHE_TAR" ]; then
    log "no cache yet for $TAG -- downloading the 8 non-backend module assets once"
    log "(future runs for this tag reuse this; delete $CACHE_DIR to force a refresh)"
    tmp="$CACHE_DIR/.download"
    rm -rf "$tmp"; mkdir -p "$tmp"
    "$REPO_DIR/scripts/prepare_package.sh" "$TAG" "$tmp" "$CACHED_MODULES"
    found="$(find "$tmp" -maxdepth 1 -name "intact-upgrade-$TAG.tar*" | head -1)"
    if [ -z "$found" ]; then
        err "prepare_package.sh did not produce the expected output in $tmp"
        exit 1
    fi
    mv "$found" "$CACHE_TAR"
    rm -rf "$tmp"
    log "cached -> $CACHE_TAR"
else
    log "reusing cached 8-module assets: $CACHE_TAR"
fi

# ── Step 2: rebuild the intact module fresh, from current source ──────────
# /app/data inside the backend container is bind-mounted to the box's
# data/ dir on the host -- staging the current repo checkout under there
# (in a dotfile-prefixed subdir, kept out of the way of real data) makes it
# reachable from inside the container without touching /app/workdir, which
# is the box's own live install checkout, not this dev repo.
BOX_DATA_HOST="$(docker inspect "$BACKEND_CONTAINER" \
    --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}')"
if [ -z "$BOX_DATA_HOST" ]; then
    err "could not resolve $BACKEND_CONTAINER's /app/data mount on the host"
    exit 1
fi
SRC_STAGING_HOST="$BOX_DATA_HOST/.local_release_src"
SRC_STAGING_CT="/app/data/.local_release_src"
OUT_STAGING_HOST="$BOX_DATA_HOST/.local_release_out"
OUT_STAGING_CT="/app/data/.local_release_out"

log "syncing current source ($REPO_DIR) into the backend container's reach"
rm -rf "$SRC_STAGING_HOST" "$OUT_STAGING_HOST"
mkdir -p "$SRC_STAGING_HOST" "$OUT_STAGING_HOST"
rsync -a --exclude='.git' "$REPO_DIR/" "$SRC_STAGING_HOST/"

log "rebuilding the intact module asset from current source (this is the slow"
log "step only the FIRST time -- Docker's layer cache makes reruns fast unless"
log "requirements*.txt actually changed)"
# Deliberately no --commit: build_release_package.py resolves the TAG's own
# git commit and hard-fails if --commit disagrees ("the tag moved mid-build")
# -- exactly the check that would fire here, since the whole point of this
# tool is packaging CURRENT source (ahead of whatever commit the real
# intact-20260806 tag points to), not literally rebuilding that tagged
# commit. Leaving it unset makes it self-resolve with no mismatch check.
docker exec \
    -e INTACT_PATH="$SRC_STAGING_CT" \
    "$BACKEND_CONTAINER" \
    python3 "$SRC_STAGING_CT/scripts/ci/build_release_package.py" \
        --tag "$TAG" --module intact \
        --out "$OUT_STAGING_CT" \
        --work-dir "$OUT_STAGING_CT/intact-upgrade-$TAG"

INTACT_ASSET="$(find "$OUT_STAGING_HOST" -maxdepth 1 -name "$TAG-intact.tar*" | head -1)"
if [ -z "$INTACT_ASSET" ]; then
    err "expected $TAG-intact.tar[.gz] under $OUT_STAGING_HOST, found:"
    ls -la "$OUT_STAGING_HOST" >&2 || true
    exit 1
fi
log "built -> $(basename "$INTACT_ASSET") ($(du -h "$INTACT_ASSET" | cut -f1))"

# ── Step 3: combine the fresh intact asset with the cached 8 ──────────────
WORK="$(mktemp -d -p "$OUT_DIR" .local-release-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
log "unpacking the cached 8-module bundle"
tar -xf "$CACHE_TAR" -C "$WORK"
cp "$INTACT_ASSET" "$WORK/"

INDEX="$WORK/$TAG.index.json"
if [ ! -f "$INDEX" ]; then
    err "expected $INDEX from the cached bundle, not found"
    exit 1
fi
# build_release_package.py already wrote a <asset>.meta.json sidecar with
# the sha256/size it computed -- reuse that instead of hashing a multi-
# hundred-MB file a second time.
META="$INTACT_ASSET.meta.json"
if [ ! -f "$META" ]; then
    err "expected $META alongside the built asset, not found"
    exit 1
fi
python3 - "$INDEX" "$(basename "$INTACT_ASSET")" "$META" <<'PY'
import json, sys
idx_path, asset, meta_path = sys.argv[1:4]
idx = json.load(open(idx_path))
meta = json.load(open(meta_path))
idx.setdefault("assets", {})["intact"] = {
    "asset": asset, "version": "local",
    "size": meta["size"], "sha256": meta["sha256"], "parts": [],
}
json.dump(idx, open(idx_path, "w"), indent=2)
PY

# index.json FIRST, deliberately -- same reason prepare_package.sh does this:
# the Import UI peeks at only the first few MB of the upload to show what's
# in it, so the index needs to be in the opening KB, not wherever a bare `ls`
# would alphabetically sort it (it would NOT be first: "-elk..." sorts before
# ".index..." on the '-' vs '.' byte).
ASSETS=()
while IFS= read -r -d '' _a; do
    ASSETS+=("$_a")
done < <(find "$WORK" -maxdepth 1 \( -name "$TAG-*.tar.gz" -o -name "$TAG-*.tar" \) -printf '%P\0' | sort -z)

# The merged root manifest, when the cached bundle carried one. Without it the
# target dies in upkg_read_manifest with "per-module manifests but no merged
# manifest.json" -- prepare_package.sh started wrapping it, and this tool
# unpacks a prepare_package.sh bundle, so dropping it here would silently
# reintroduce the very failure that fix removed. Kept as `<tag>.manifest.json`,
# NOT `manifest.json`: upkg_expand_args's wrapper detector refuses a tar with a
# top-level member named exactly manifest.json, so renaming it would turn off
# unwrapping altogether.
WRAP_EXTRA=()
[ -f "$WORK/$TAG.manifest.json" ] && WRAP_EXTRA+=("$TAG.manifest.json")

FINAL="$OUT_DIR/intact-upgrade-$TAG-local.tar"
log "wrapping final package -> $FINAL"
tar -cf "$FINAL" -C "$WORK" "$TAG.index.json" "${WRAP_EXTRA[@]}" "${ASSETS[@]}"

log "verifying the wrapped package"
if ! tar -tf "$FINAL" >/dev/null 2>&1; then
    err "the wrapped package failed its integrity check (tar cannot read it back)"
    exit 1
fi

log "done: $FINAL ($(du -h "$FINAL" | cut -f1))"
log "upload this via Settings -> Apply Uploaded Package, or point the offline"
log "apply flow at it directly."
