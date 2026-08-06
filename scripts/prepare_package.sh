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
# Writes <output_dir>/intact-upgrade-<tag>.tar and prints its path as the
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
# N verified module assets (+ the index) into one outer tar, unchanged.
#
# The outer wrap is a PLAIN tar, not tar.gz. Every byte inside it is already
# compressed (docker image layers are gzip at rest, and CI publishes each
# module asset compressed), so the outer deflate pass measured 0.55% -- 31 MB
# saved on a 5.44 GB package -- in exchange for a full single-threaded pass
# over all 5.4 GB on the operator's laptop. Readers were made format-agnostic
# first (tar -xf and tarfile.open(f,'r') both auto-detect), so every package
# already carried into a site as .tar.gz still opens exactly as before.
# The merge (union per-module manifests into one manifest.json) happens once,
# server-side, in services.upgrade.base.assemble_release_package() -- the
# same function that already merges N separately-uploaded assets. install.sh
# and the Import Upgrade Package endpoint both unwrap this file back into its
# N inner assets and hand them to that one, well-tested implementation.
set -euo pipefail

log()  { printf '[prepare] %s\n' "$*"; }
err()  { printf '[prepare][ERROR] %s\n' "$*" >&2; }

# Sizes and durations go through these everywhere, so "1.8G" and "2m14s" mean
# the same thing on every line of the log rather than varying with whichever
# tool happened to produce them (du -h, numfmt, raw seconds).
_h() { numfmt --to=iec "${1:-0}" 2>/dev/null || echo "${1:-0}B"; }
_elapsed() {
    s=${1:-0}
    if [ "$s" -ge 60 ]; then printf '%dm%02ds' $(( s / 60 )) $(( s % 60 ))
    else printf '%ds' "$s"; fi
}

RUN_STARTED=$(date +%s)
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

# Stage INSIDE the output directory, not /tmp.
#
# `mktemp -d` puts several GB of module assets on whatever filesystem backs
# /tmp -- which on plenty of hosts is a small partition or a tmpfs, i.e. RAM.
# The operator already told us where the result should go and that location
# must hold a full copy of it, so it is the one place we know is sized for
# this. It also means the free-space check below measures the filesystem the
# work will actually land on.
#
# Named (not mktemp's random suffix alone) so an orphan is self-explaining:
# a killed run used to leave "/tmp/tmp.f2LCsQ6rnE" holding 14 GB with nothing
# to say what it was or whether it mattered.
# Reap staging from a run that died where no trap could help -- SIGKILL, the
# OOM killer, a power cut. Those cannot be trapped by anything, so the only
# reliable cleanup is the NEXT run finding the debris and removing it. Matched
# by our own fixed prefix, so nothing else in the operator's directory is ever
# touched. Done before creating this run's dir so it can never remove itself.
for _stale in "$OUT_DIR"/.intact-prepare-*; do
    [ -d "$_stale" ] || continue
    printf '[prepare] %-9s %s (from an interrupted run)\n' "cleaning" "$(basename "$_stale")"
    rm -rf "$_stale"
done

WORK="$(mktemp -d -p "$OUT_DIR" .intact-prepare-XXXXXX 2>/dev/null)" \
    || WORK="$(mktemp -d)"

# ONE cleanup, on every path out of the script.
#
# EXIT alone does not fire when the run is signalled, and this script is
# routinely stopped by the operator (the UI's Stop button terminates it) --
# that is precisely how the 14 GB orphan happened. SIGKILL still cannot be
# trapped; nothing can fix that, which is why the staging directory is named
# and sits beside the output, where the next run reaps it.
#
# The half-written OUT is removed too unless the run got all the way through.
# A truncated tarball is worse than no file: it is the right name and a
# plausible size, so it looks like a package until it fails to extract on the
# air-gapped box it was carried to.
OUT_OK=0
_cleanup() {
    rm -rf "$WORK"
    if [ "$OUT_OK" -eq 0 ] && [ -n "${OUT:-}" ] && [ -f "$OUT" ]; then
        rm -f "$OUT"
        printf '[prepare] %-9s %s (incomplete)\n' "removed" "$(basename "$OUT")"
    fi
}
trap _cleanup EXIT INT TERM HUP
cd "$WORK"

# Settings block: one "key: value" per line, aligned, so the head of every run
# reads the same way and a wrong tag or output path is obvious at a glance.
printf '[prepare] %-9s %s\n' "release:" "$TAG"
printf '[prepare] %-9s %s\n' "repo:"    "$REPO"
printf '[prepare] %-9s %s\n' "output:"  "$OUT_DIR/intact-upgrade-$TAG.tar"
printf '[prepare] %-9s %s\n' "modules:" "${MODULES_CSV:-all in this release}"

AUTH=(-H "X-GitHub-Api-Version: 2022-11-28")
if [ -n "${GITHUB_TOKEN:-}" ]; then
    AUTH+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    printf '[prepare] %-9s %s\n' "auth:" "GITHUB_TOKEN set (5000/hr API rate limit)"
else
    printf '[prepare] %-9s %s\n' "auth:" "none (anonymous, 60/hr API rate limit)"
fi

log "fetching release metadata"
if ! REL="$(curl -fsSL "${AUTH[@]}" "$API/repos/$REPO/releases/tags/$TAG")"; then
    err "cannot read release $TAG"
    err "  404 - no PUBLISHED release for that tag (a git tag alone is not"
    err "        enough; a DRAFT release needs a token to be visible)"
    err "  403 - rate limited (60/hr anonymous). Wait, or set GITHUB_TOKEN"
    err "  401 - the token you set is wrong or expired"
    exit 1
fi

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

log "reading the release index"
curl -fsSL "${AUTH[@]}" -H "Accept: application/octet-stream" \
     -o "$TAG.index.json" "$IDX_URL"

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
        print("%s\t%s\t%s\t%s\t%d" % (f, mod, urls[f], sha, e.get("size") or 0))
')"
NFILES="$(printf '%s\n' "$PLAN" | grep -c . || true)"
TOTAL_BYTES="$(printf '%s\n' "$PLAN" | awk -F'\t' '{s+=$5} END {print s+0}')"

# Free-space check BEFORE the first byte. The assets are downloaded into WORK
# and then wrapped into a tarball beside them, so both copies exist at once:
# roughly 2x the download, plus a little slack. Discovering that after
# fetching 4 GB -- which is what happened before this check existed -- wastes
# the download and leaves the operator to work out what went wrong from a
# tar error.
# `|| true`, and no -P: `df -P --output=...` is rejected outright ("options -P
# and --output are mutually exclusive"), and under `set -e` + `pipefail` a
# non-zero df takes the whole script down at a command substitution -- silently,
# right after "reading the release index". Any df that cannot answer must leave
# _AVAIL empty and skip the check, never abort the run.
_AVAIL="$( { df --output=avail -B1 "$WORK" 2>/dev/null || true; } | tail -1 | tr -d ' ')"
_NEED=$(( TOTAL_BYTES * 21 / 10 ))
if [ -n "$_AVAIL" ] && [ "$_AVAIL" -lt "$_NEED" ] 2>/dev/null; then
    err "not enough free space in $OUT_DIR"
    err "  need  ~$(_h "$_NEED") (assets $(_h "$TOTAL_BYTES") + the wrapped copy)"
    err "  have   $(_h "$_AVAIL")"
    err "  Free space, or pass a different output directory, or package fewer"
    err "  modules with the 3rd argument (e.g. elk,iris)."
    exit 1
fi

log "downloading $NFILES asset(s), $(_h "$TOTAL_BYTES") total, 4 at a time"

# EVERY line in this phase is "<verb> <module> <size> [detail]", one fixed
# shape. Four downloads run at once, so start/finish lines interleave by
# nature -- with `->`/`<-` markers the operator had to decode arrows to work
# out what was happening. A left-aligned verb column reads down the page
# regardless of interleaving, and the module name is always in the same place.
#
# -sS, NOT curl's progress meter: four parallel meters redrawing interleave
# into unreadable garbage, and this stdout is piped straight into the
# appliance's workflow log. Aggregate progress comes from the watcher below.
_dl_one() {
    name="$1"; mod="$2"; url="$3"; want="$4"
    started=$(date +%s)
    printf '[prepare]   %-9s %-14s %8s\n' "start" "$mod" "$(_h "$want")"
    hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
    [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    # -C - resumes from whatever "$name" already has on disk instead of
    # restarting at byte 0. Without it, a drop near the end of a multi-GB
    # asset (observed: ELK's ~5.5G tar failing at 97% with "curl: (18)
    # Transferred a partial file") makes every one of the 3 retries below
    # re-download the whole file from scratch, so a link that reliably
    # cuts out around the same point/duration fails the same way 4 times
    # in a row instead of just finishing the remaining 3%.
    if ! curl -fL -sS -C - --retry 3 --retry-delay 5 "${hdrs[@]}" -o "$name" "$url"; then
        printf '[prepare][ERROR]   %-9s %-14s %s\n' "failed" "$mod" "$name" >&2
        return 1
    fi
    got=$(stat -c%s "$name" 2>/dev/null || echo 0)
    printf '[prepare]   %-9s %-14s %8s  in %s\n' \
        "done" "$mod" "$(_h "$got")" "$(_elapsed $(( $(date +%s) - started )))"
}
export -f _dl_one _h _elapsed
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
#
# Both '*.tar.gz' and '*.tar' are counted: CI publishes plain-tar assets now,
# but every release cut before that is still .tar.gz and must still show
# progress. A name ends in one or the other, never both, so nothing is
# double-counted.
(
    set +e
    while :; do
        sleep 20
        got=$(find . -maxdepth 1 \
                   \( -name '*.tar.gz' -o -name '*.tar' -o -name '*.part-*' \) \
                   -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
        got="${got:-0}"
        if [ "${TOTAL_BYTES:-0}" -gt 0 ] 2>/dev/null; then
            printf '[prepare]   %-9s %-14s %8s  of %s (%d%%)\n' \
                "progress" "" "$(_h "$got")" "$(_h "$TOTAL_BYTES")" \
                "$(( got * 100 / TOTAL_BYTES ))"
        fi
    done
) &
WATCHER=$!
trap 'kill "$WATCHER" 2>/dev/null; _cleanup' EXIT INT TERM HUP

DL_STARTED=$(date +%s)
if ! printf '%s\n' "$PLAN" | cut -f1,2,3,5 \
     | xargs -P 4 -L 1 bash -c '_dl_one "$1" "$2" "$3" "$4"' _; then
    kill "$WATCHER" 2>/dev/null || true
    err "one or more downloads failed"
    exit 1
fi
kill "$WATCHER" 2>/dev/null || true
# Re-arm without the watcher-kill, but keep every signal: resetting this to a
# bare EXIT left Ctrl-C during the wrap phase leaking the staging directory.
trap _cleanup EXIT INT TERM HUP
log "downloaded $NFILES asset(s), $(_h "$TOTAL_BYTES") in $(_elapsed $(( $(date +%s) - DL_STARTED )))"

# Both suffixes, because CI's split assets follow whatever the whole asset is:
# a plain-tar release splits into "<asset>.tar.part-NN", a release cut before
# that change into "<asset>.tar.gz.part-NN". Each glob is tested with -e rather
# than relying on it matching, since an unmatched glob is left literal by bash
# and would otherwise be joined as if it were a filename.
if find . -maxdepth 1 \( -name '*.tar.gz.part-00' -o -name '*.tar.part-00' \) \
        2>/dev/null | grep -q .; then
    log "joining split assets"
    for part0 in *.tar.gz.part-00 *.tar.part-00; do
        [ -e "$part0" ] || continue
        whole="${part0%.part-00}"
        printf '[prepare]   %-9s %-14s\n' "joining" "$(basename "$whole")"
        cat "$whole".part-* > "$whole" && rm -f "$whole".part-*
    done
fi

log "verifying checksums"
fail=0
while IFS="$(printf '\t')" read -r name mod url sha size; do
    [ -n "$name" ] || continue
    whole="${name%.part-*}"
    [ -f "$whole" ] || continue
    bytes=$(stat -c%s "$whole" 2>/dev/null || echo 0)
    if [ -z "$sha" ]; then
        printf '[prepare]   %-9s %-14s %8s  no sha256 in index\n' \
            "SKIPPED" "$mod" "$(_h "$bytes")"
        continue
    fi
    # || true: a read error here must report a mismatch, not kill the run at
    # a command substitution (set -e + pipefail).
    got="$( { sha256sum "$whole" 2>/dev/null || true; } | awk '{print $1}')"
    if [ "$sha" != "$got" ]; then
        printf '[prepare][ERROR]   %-9s %-14s want %s... got %s...\n' \
            "MISMATCH" "$mod" "${sha:0:16}" "${got:0:16}" >&2
        fail=1
    else
        printf '[prepare]   %-9s %-14s %8s\n' "ok" "$mod" "$(_h "$bytes")"
    fi
done <<< "$PLAN"
[ "$fail" -eq 0 ] || { err "checksum verification failed -- refusing to package"; exit 1; }

# The list of module assets to wrap, resolved ONCE and reused by the tar
# command below, so the count that gets logged and the set that gets packed can
# never disagree.
#
# find, not `ls glob | wc -l`: an unmatched glob makes ls exit non-zero, which
# under pipefail aborts the script silently at this assignment. Not a bare glob
# on the tar command line either, for the same reason in reverse -- bash leaves
# an unmatched glob literal and tar would be handed "intact-20260805-*.tar.gz"
# as a filename.
#
# Both suffixes are matched: CI publishes plain-tar assets, every release cut
# before that publishes .tar.gz, and prepare_package.sh has to be able to
# package either. Matching only one of them is the failure this guards against
# -- the globs would hit nothing, NASSETS would be 0, the checksum loop above
# would have had nothing to check, and the run would write a package containing
# only the index: correct name, plausible-looking log, no images.
# -printf '%P' so the members are stored as "intact-<tag>-elk.tar", not
# "./intact-<tag>-elk.tar" -- readers on the far side match member names by
# suffix and a "./" prefix is a needless difference from what the bare glob
# produced before.
ASSETS=()
while IFS= read -r -d '' _a; do
    ASSETS+=("$_a")
done < <(find . -maxdepth 1 \
              \( -name "$TAG-*.tar.gz" -o -name "$TAG-*.tar" \) \
              -printf '%P\0' 2>/dev/null | sort -z)
NASSETS=${#ASSETS[@]}
if [ "$NASSETS" -eq 0 ]; then
    err "no module assets to package"
    err "  $NFILES file(s) were downloaded for $TAG but none of them is named"
    err "  $TAG-<module>.tar[.gz] -- refusing to write an index-only package"
    exit 1
fi
log "verified $NASSETS module asset(s)"

# Trim the index to the modules actually packed. The release's index names
# every module the RELEASE has; a subset package contains fewer. Shipping the
# untrimmed index would make the import screen list modules the file does not
# contain -- promising an upgrade it cannot perform, which is the same
# silent-staleness failure the whole per-module scheme exists to prevent.
log "trimming index to the packed module(s)"
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
print("[prepare]   %-9s %s" % ("included", ", ".join(sorted(kept)) or "(none)"))
if dropped:
    print("[prepare]   %-9s %s" % ("excluded", ", ".join(dropped)))
PY

OUT="$OUT_DIR/intact-upgrade-$TAG.tar"
log "wrapping into a single file"
# index.json FIRST, deliberately. The Import UI peeks at only the first few MB
# of the uploaded file to show the operator what they are about to apply; with
# the index at the end of a multi-GB stream there is nothing to read without
# downloading all of it. Listing it first puts it in the opening KB.
WRAP_STARTED=$(date +%s)
tar -cf "$OUT" "$TAG.index.json" "${ASSETS[@]}"

# Prove the archive is readable before calling it a package. tar can exit 0
# having written something the far end cannot open (a disk that filled at the
# last block, a truncated write). Everything downstream -- install.sh, Import
# Upgrade Package -- starts by reading this file end to end, so it costs one
# pass here to find out now rather than after it has been carried to a site
# with no way to re-fetch it.
#
# `tar -tf`, not `gzip -t`: the wrap is a plain tar now and gzip -t on it is not
# a weaker check, it is no check at all -- it either errors on a file it was
# never going to be able to read or, worse, would have to be dropped and leave
# this step verifying nothing. Listing every member forces tar to walk the whole
# file and read every header, which is what catches the truncation this exists
# to catch. Output to /dev/null: the listing itself is noise, only the exit
# status matters.
log "verifying the wrapped package"
if ! tar -tf "$OUT" >/dev/null 2>&1; then
    err "the wrapped package failed its integrity check (tar cannot read it back)"
    err "  usually a full disk at the final write -- check space and re-run"
    exit 1
fi

# Only now is OUT a real package; before this line the trap deletes it.
OUT_OK=1
printf '[prepare]   %-9s %-14s %8s  in %s\n' "wrote" "$(basename "$OUT")" \
    "$(_h "$(stat -c%s "$OUT" 2>/dev/null || echo 0)")" \
    "$(_elapsed $(( $(date +%s) - WRAP_STARTED )))"
log "done in $(_elapsed $(( $(date +%s) - RUN_STARTED )))"
echo "$OUT"
