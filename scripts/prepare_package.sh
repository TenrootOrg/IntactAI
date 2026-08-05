#!/usr/bin/env bash
# Download a release's per-module assets from GitHub and wrap them into ONE
# file for hand-carry into an air-gapped site.
#
#   scripts/prepare_package.sh <tag> [output_dir] [modules_csv]
#
#   <tag>          release tag, e.g. intact-20260805
#   [output_dir]   where to write the result (default: .)
#   [modules_csv]  comma-separated subset, e.g. elk,iris (default: every
#                  module the release's index lists). "intact" is always
#                  force-added -- a package without the platform itself
#                  cannot drive any other module's upgrade.
#
# Writes <output_dir>/intact-upgrade-<tag>.tar.gz and prints its path as the
# LAST line of stdout on success.
#
# Deliberately standalone: no import of this repo's Python backend. This is
# meant to run on any machine with curl + python3 + tar and internet access
# to github.com -- an operator's laptop preparing a package for a box that
# has none, just as much as this box calling it locally. The backend's
# Prepare Package feature (routes/upgrade_routes.py) runs this exact script
# as a subprocess and streams its stdout into the workflow log, rather than
# reimplementing any of this in Python -- one implementation, not two.
#
# NO MERGE. This does not extract or merge the module assets -- it wraps the
# N verified tar.gz files (+ the index) into one outer tar.gz, unchanged.
# The merge (union per-module manifests into one manifest.json) happens once,
# server-side, in services.upgrade.base.assemble_release_package() -- the
# same function that already merges N separately-uploaded assets. install.sh
# and the Import Upgrade Package endpoint both unwrap this file back into its
# N inner assets and hand them to that one, well-tested implementation.
set -euo pipefail

log()  { printf '[prepare] %s\n' "$*"; }
err()  { printf '[prepare][ERROR] %s\n' "$*" >&2; }

TAG="${1:-}"
OUT_DIR="${2:-.}"
MODULES_CSV="${3:-}"
REPO="TenrootOrg/IntactAI"
API="https://api.github.com"

if [ -z "$TAG" ]; then
    err "usage: prepare_package.sh <tag> [output_dir] [modules_csv]"
    exit 2
fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

log "release: $TAG"
log "repo: $REPO"
log "output: $OUT_DIR/intact-upgrade-$TAG.tar.gz"
[ -n "$MODULES_CSV" ] && log "modules requested: $MODULES_CSV"

AUTH=(-H "X-GitHub-Api-Version: 2022-11-28")
if [ -n "${GITHUB_TOKEN:-}" ]; then
    AUTH+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    log "GITHUB_TOKEN set -- 5000/hr API rate limit"
else
    log "no GITHUB_TOKEN set -- 60/hr anonymous API rate limit"
fi

log "fetching release metadata..."
if ! REL="$(curl -fsSL "${AUTH[@]}" "$API/repos/$REPO/releases/tags/$TAG")"; then
    err "cannot read release $TAG"
    err "  404 - no PUBLISHED release for that tag (a git tag alone is not"
    err "        enough; a DRAFT release needs a token to be visible)"
    err "  403 - rate limited (60/hr anonymous). Wait, or set GITHUB_TOKEN"
    err "  401 - the token you set is wrong or expired"
    exit 1
fi
log "release metadata OK"

IDX_URL="$(printf %s "$REL" | TAG="$TAG" python3 -c '
import json, os, sys
want = os.environ["TAG"] + ".index.json"
for a in json.load(sys.stdin).get("assets", []):
    if a["name"] == want:
        print(a["url"]); break
')"
if [ -z "$IDX_URL" ]; then
    err "release $TAG has no per-module index ($TAG.index.json)"
    err "its CI build may still be running, or it predates the per-module scheme"
    exit 1
fi

log "downloading index..."
curl -fsSL "${AUTH[@]}" -H "Accept: application/octet-stream" \
     -o "$TAG.index.json" "$IDX_URL"
log "index OK"

# name<TAB>module<TAB>url<TAB>sha256-of-the-whole-asset, one line per FILE to
# fetch (a split asset contributes one line per .part-NN, all sharing the
# same whole-asset sha256 -- that hash covers the reassembled file, since a
# split asset has no per-part digest published).
PLAN="$(printf %s "$REL" | IDX="$TAG.index.json" MODULES="$MODULES_CSV" python3 -c '
import json, os, sys
rel = json.load(sys.stdin)
urls = {a["name"]: a["url"] for a in rel.get("assets", [])}
idx = json.load(open(os.environ["IDX"]))
wanted = None
csv = os.environ.get("MODULES") or ""
if csv.strip():
    wanted = {m.strip() for m in csv.split(",") if m.strip()} | {"intact"}
available = idx.get("assets") or {}
if wanted is not None:
    missing = sorted(wanted - set(available))
    if missing:
        sys.exit("requested module(s) not in this release: " + ", ".join(missing))
for mod, e in sorted(available.items()):
    if wanted is not None and mod not in wanted:
        continue
    whole, sha = e["asset"], e.get("sha256", "")
    files = [whole] if whole in urls else [p for p in (e.get("parts") or []) if p in urls]
    if not files:
        sys.exit("index lists %s but the release does not publish it" % whole)
    for f in files:
        print("%s\t%s\t%s\t%s" % (f, mod, urls[f], sha))
')"
NFILES="$(printf '%s\n' "$PLAN" | grep -c . || true)"
log "$NFILES asset file(s) to fetch (up to 4 in parallel)"

> .expected_bytes
while IFS="$(printf '\t')" read -r name mod url sha; do
    [ -n "$name" ] || continue
    python3 -c "
import json,os,sys
idx=json.load(open(sys.argv[1]))
for e in (idx.get('assets') or {}).values():
    if e.get('asset')==sys.argv[2] or sys.argv[2] in (e.get('parts') or []):
        print(e.get('size') or 0); break
else:
    print(0)
" "$TAG.index.json" "$name" >> .expected_bytes
done <<< "$PLAN"
TOTAL_BYTES="$(awk '{s+=$1} END {print s+0}' .expected_bytes)"
rm -f .expected_bytes
log "total download: $(numfmt --to=iec "$TOTAL_BYTES" 2>/dev/null || echo "$TOTAL_BYTES bytes")"

# -sS, NOT curl's progress meter. Four parallel curls each redrawing a meter
# interleave into unreadable garbage, and this script's stdout is piped
# straight into the appliance's workflow log -- thousands of meter redraws
# would bury the lines that matter. Progress comes from the watcher below
# instead: one line per interval covering the whole download.
_dl_one() {
    name="$1"; mod="$2"; url="$3"
    printf '[prepare]   -> [%s] %s\n' "$mod" "$name"
    hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
    [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    if ! curl -fL -sS --retry 3 --retry-delay 5 "${hdrs[@]}" -o "$name" "$url"; then
        printf '[prepare][ERROR]   [%s] %s failed to download\n' "$mod" "$name" >&2
        return 1
    fi
    printf '[prepare]   <- [%s] %s done (%s)\n' "$mod" "$name" "$(du -h "$name" | cut -f1)"
}
export -f _dl_one
export GITHUB_TOKEN

# One aggregate progress line every 20s, so a multi-GB fetch is never silent
# for minutes at a time (which reads as a hang) without flooding the log.
#
# set -e is DISABLED inside this subshell, and the byte count comes from find
# rather than du, on purpose. With `set -o pipefail` in force, `du ./*.part-*`
# on a release with no split assets leaves the glob unmatched, du exits 1, the
# pipeline inherits that, and set -e kills the watcher on its FIRST iteration
# -- silently, because it is a background subshell. The result was a 5.5 GB
# download with no progress output at all, which is the exact failure this
# watcher exists to prevent. find matches nothing without erroring.
(
    set +e
    while :; do
        sleep 20
        got=$(find . -maxdepth 1 \( -name '*.tar.gz' -o -name '*.part-*' \) \
                   -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
        got="${got:-0}"
        if [ "${TOTAL_BYTES:-0}" -gt 0 ] 2>/dev/null; then
            printf '[prepare]   ... %s / %s (%d%%)\n' \
                "$(numfmt --to=iec "$got" 2>/dev/null || echo "$got")" \
                "$(numfmt --to=iec "$TOTAL_BYTES" 2>/dev/null || echo "$TOTAL_BYTES")" \
                "$(( got * 100 / TOTAL_BYTES ))"
        fi
    done
) &
WATCHER=$!
trap 'kill "$WATCHER" 2>/dev/null; rm -rf "$WORK"' EXIT

if ! printf '%s\n' "$PLAN" | cut -f1,2,3 | xargs -P 4 -L 1 bash -c '_dl_one "$1" "$2" "$3"' _; then
    kill "$WATCHER" 2>/dev/null || true
    err "one or more downloads failed"
    exit 1
fi
kill "$WATCHER" 2>/dev/null || true
trap 'rm -rf "$WORK"' EXIT
log "all downloads complete"

log "joining any split parts..."
for part0 in *.tar.gz.part-00; do
    [ -e "$part0" ] || continue
    whole="${part0%.part-00}"
    log "  joining $(basename "$whole")"
    cat "$whole".part-* > "$whole" && rm -f "$whole".part-*
done

log "verifying checksums..."
fail=0
while IFS="$(printf '\t')" read -r name mod url sha; do
    [ -n "$name" ] || continue
    whole="${name%.part-*}"
    [ -f "$whole" ] || continue
    [ -n "$sha" ] || { log "  [$mod] $(basename "$whole") -- no sha256 in index, unverified"; continue; }
    got="$(sha256sum "$whole" | awk '{print $1}')"
    if [ "$sha" != "$got" ]; then
        err "  [$mod] $(basename "$whole") CHECKSUM MISMATCH (want ${sha:0:16}..., got ${got:0:16}...)"
        fail=1
    else
        log "  [$mod] $(basename "$whole") OK"
    fi
done <<< "$PLAN"
[ "$fail" -eq 0 ] || { err "checksum verification failed -- refusing to package"; exit 1; }

NASSETS="$(ls -1 "$TAG"-*.tar.gz 2>/dev/null | wc -l)"
log "$NASSETS module asset(s) verified"

# Trim the index to the modules actually packed. The release's index names
# every module the RELEASE has; a subset package contains fewer. Shipping the
# untrimmed index would make the import screen list modules the file does not
# contain -- promising an upgrade it cannot perform, which is the same
# silent-staleness failure the whole per-module scheme exists to prevent.
log "trimming index to the $NASSETS packed module(s)..."
python3 - "$TAG.index.json" <<'PY'
import json, os, sys
path = sys.argv[1]
idx = json.load(open(path))
present = set(os.listdir('.'))
assets = idx.get('assets') or {}
kept = {m: e for m, e in assets.items() if e.get('asset') in present}
dropped = sorted(set(assets) - set(kept))
idx['assets'] = kept
json.dump(idx, open(path, 'w'), indent=2)
print("[prepare]   index lists %d module(s): %s" % (len(kept), ", ".join(sorted(kept))))
if dropped:
    print("[prepare]   not in this package: %s" % ", ".join(dropped))
PY

OUT="$OUT_DIR/intact-upgrade-$TAG.tar.gz"
log "wrapping into a single file..."
# index.json FIRST, deliberately. The Import UI peeks at only the first few MB
# of the uploaded file to show the operator what they are about to apply; with
# the index at the end of a multi-GB stream there is nothing to read without
# downloading all of it. Listing it first puts it in the opening KB.
tar -czf "$OUT" "$TAG.index.json" "$TAG"-*.tar.gz
log "wrote $(basename "$OUT") ($(du -h "$OUT" | cut -f1))"
log "done"
echo "$OUT"
