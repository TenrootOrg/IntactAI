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

# Handles a release published by build-release-package.yml instead of (or in
# addition to) the per-module scheme -- e.g. cut specifically for a box old
# enough that its manifest reader has never heard of index.json (see that
# workflow's own comment). That asset is already ONE file; this just fetches
# it (joining GitHub's <2GB split parts if present) and verifies it, then
# writes straight to $OUT_DIR/intact-upgrade-<tag>.tar[.gz] -- there is
# nothing to wrap, unlike the per-module path this whole script otherwise is.
#
# LEGACY, same bridge as refs.sh's upgrade_fetch_release and package.sh's
# manifest-precedence handling: every release before intact-20260811 is this
# shape, and build-release-package.yml stays dispatchable on demand for a box
# that still needs one. Remove once no box in the fleet is old enough to.
#
# Prints nothing on success except the final path (matching this script's
# contract of the last stdout line being the result); returns 1 if no such
# asset exists in $REL at all, which the caller treats as "genuinely not
# published either way" rather than an error in this function.
# Progress for one long download, polled off the output file's size.
#
# The legacy path used a bare `curl -sS` per part, so a 1.9 GB part produced
# ONE line and then nothing: an operator watching a real run saw 4m37s of
# silence between "downloading part-00" and "downloading part-01", with the
# workflow still reporting 0%. The per-module path has reported size, rate and
# elapsed per asset for a while; this brings the legacy path to the same
# standard rather than inventing a second vocabulary for it.
#
# Polled rather than parsing curl's own meter: curl writes that to the tty as
# carriage-return updates, which become one enormous line in a captured log.
# Watching the file size costs a stat every few seconds and prints whole lines.
_dl_watch() {
    local f="$1" total="$2" label="$3" pid="$4"
    local started prev=0 now delta rate pct
    started=$(date +%s)
    while kill -0 "$pid" 2>/dev/null; do
        sleep "${_DL_TICK:-15}"
        kill -0 "$pid" 2>/dev/null || break
        now=$(stat -c%s "$f" 2>/dev/null || echo 0)
        delta=$(( (now - prev) / ${_DL_TICK:-15} ))
        prev="$now"
        if [ "${total:-0}" -gt 0 ] 2>/dev/null; then
            pct=$(( now * 100 / total ))
            printf '[prepare]   %-9s %-30s %8s / %-8s %3s%%  %s/s\n' \
                "..." "$label" "$(_h "$now")" "$(_h "$total")" "$pct" "$(_h "$delta")"
        else
            printf '[prepare]   %-9s %-30s %8s  %s/s\n' \
                "..." "$label" "$(_h "$now")" "$(_h "$delta")"
        fi
    done
}

# One asset, with a start line, periodic progress and a done line carrying its
# size and elapsed -- the shape _dl_one already uses for per-module assets.
_dl_reported() {
    local dest="$1" url="$2" total="$3" label="$4"; shift 4
    local started rc
    started=$(date +%s)
    printf '[prepare]   %-9s %-30s %8s\n' "start" "$label" "$(_h "$total")"
    curl -fL -sS -C - --retry 20 --retry-delay 5 "$@" -o "$dest" "$url" &
    local cpid=$!
    _dl_watch "$dest" "$total" "$label" "$cpid"
    wait "$cpid"; rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[prepare]   %-9s %-30s rc=%s\n' "FAILED" "$label" "$rc"
        return "$rc"
    fi
    printf '[prepare]   %-9s %-30s %8s  %s\n' \
        "done" "$label" "$(_h "$(stat -c%s "$dest" 2>/dev/null || echo 0)")" \
        "$(_elapsed $(( $(date +%s) - started )))"
    return 0
}

_fetch_legacy_single_file() {
    local tag="$1" out_dir="$2" rel_json="$3"
    local plan
    plan="$(printf %s "$rel_json" | TAG="$tag" python3 -c '
import json, os, sys
tag = os.environ["TAG"]
assets = {a["name"]: a for a in json.load(sys.stdin).get("assets", [])}
whole = next((n for n in (f"intact-upgrade-{tag}.tar.gz", f"intact-upgrade-{tag}.tar") if n in assets), None)
if whole:
    print("WHOLE\t" + whole + "\t" + assets[whole]["url"] + "\t" + str(assets[whole].get("size") or 0))
else:
    parts = sorted(n for n in assets
                   if n.startswith(f"intact-upgrade-{tag}.tar.gz.part-")
                   or n.startswith(f"intact-upgrade-{tag}.tar.part-"))
    if not parts:
        sys.exit(1)
    base = parts[0].rsplit(".part-", 1)[0]
    print("BASE\t" + base)
    print("TOTAL\t" + str(sum(assets[p].get("size") or 0 for p in parts)) + "\t" + str(len(parts)))
    for p in parts:
        print("PART\t" + p + "\t" + assets[p]["url"] + "\t" + str(assets[p].get("size") or 0))
sha_name_gz = f"intact-upgrade-{tag}.tar.gz.sha256"
sha_name_plain = f"intact-upgrade-{tag}.tar.sha256"
sha = assets.get(sha_name_gz) or assets.get(sha_name_plain)
if sha:
    print("SHA\t" + sha["url"])
' 2>/dev/null)" || return 1
    [ -n "$plan" ] || return 1

    local hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
    [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    local base="" sha_url="" final="" tmp_dir
    tmp_dir="$(mktemp -d -p "$out_dir" .intact-prepare-legacy-XXXXXX)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp_dir'" RETURN

    local _legacy_started _nparts=0 _total=0 _idx=0
    _legacy_started=$(date +%s)
    while IFS="$(printf '\t')" read -r kind a b c; do
        case "$kind" in
            TOTAL) _total="$a"; _nparts="$b"
                   log "legacy single-file package: ${_nparts} part(s), $(_h "$_total") total"
                   ;;
            WHOLE)
                base="$a"
                log "legacy single-file package: 1 file, $(_h "${c:-0}")"
                _dl_reported "$tmp_dir/$a" "$b" "${c:-0}" "$a" "${hdrs[@]}" || return 1
                ;;
            BASE) base="$a" ;;
            PART)
                _idx=$(( _idx + 1 ))
                _dl_reported "$tmp_dir/$a" "$b" "${c:-0}" \
                             "part ${_idx}/${_nparts:-?} $(basename "$a")" "${hdrs[@]}" || return 1
                ;;
            SHA) sha_url="$a" ;;
        esac
    done <<< "$plan"
    [ -n "$base" ] || return 1

    if [ ! -f "$tmp_dir/$base" ]; then
        # Both of these are minutes of silence on a 5.5 GB package -- the join
        # is a full read+write of it, and sha256sum another full read. Saying
        # what is happening and what it produced is the difference between a
        # run that looks stuck and one that looks slow.
        local _join_started
        _join_started=$(date +%s)
        log "joining ${_nparts:-$(ls -1 "$tmp_dir/$base".part-* 2>/dev/null | wc -l)} part(s) into $(basename "$base")"
        cat "$tmp_dir/$base".part-* > "$tmp_dir/$base"
        rm -f "$tmp_dir/$base".part-*
        printf '[prepare]   %-9s %-30s %8s  %s\n' "joined" "$(basename "$base")" \
            "$(_h "$(stat -c%s "$tmp_dir/$base" 2>/dev/null || echo 0)")" \
            "$(_elapsed $(( $(date +%s) - _join_started )))"
    fi

    if [ -n "$sha_url" ]; then
        log "verifying checksum of $(_h "$(stat -c%s "$tmp_dir/$base" 2>/dev/null || echo 0)") (a full read; takes a moment)"
        curl -fsSL "${hdrs[@]}" -o "$tmp_dir/$base.sha256" "$sha_url"
        local want got
        want="$(awk '{print $1}' "$tmp_dir/$base.sha256")"
        got="$(sha256sum "$tmp_dir/$base" | awk '{print $1}')"
        if [ "$want" != "$got" ]; then
            err "MISMATCH on $base: want ${want:0:16}... got ${got:0:16}..."
            return 1
        fi
        log "checksum verified"
    else
        log "no .sha256 published alongside it -- skipping verification"
    fi

    # The host-level Docker/apt dependency bundle -- a release publishes it
    # as its own asset (build-release-package.yml's "system-bundle" step),
    # disjoint from this single-file package. Fetched as a SIBLING of $final
    # rather than merged into it: this branch's whole contract is "one file,
    # unwrapped, ready for --package" (see this function's own header), and
    # install.sh already looks beside a --package file argument for exactly
    # this name (the same lookup a bundle sitting next to a module asset on
    # a USB stick relies on) -- no install.sh change needed for this shape.
    local bundle_name="${tag}-system-bundle.tar"
    local bundle_info
    bundle_info="$(printf %s "$rel_json" | BNAME="$bundle_name" python3 -c '
import json, os, sys
name = os.environ["BNAME"]
assets = {a["name"]: a for a in json.load(sys.stdin).get("assets", [])}
a = assets.get(name)
if a:
    print(a["url"])
    sha = assets.get(name + ".sha256")
    print(sha["url"] if sha else "")
' 2>/dev/null)"
    if [ -n "$bundle_info" ]; then
        local bundle_url bundle_sha_url
        bundle_url="$(sed -n '1p' <<< "$bundle_info")"
        bundle_sha_url="$(sed -n '2p' <<< "$bundle_info")"
        log "fetching the Docker/dependency bundle"
        curl -fL -sS -C - --retry 20 --retry-delay 5 "${hdrs[@]}" \
             -o "$tmp_dir/$bundle_name" "$bundle_url"
        if [ -n "$bundle_sha_url" ]; then
            curl -fsSL "${hdrs[@]}" -o "$tmp_dir/$bundle_name.sha256" "$bundle_sha_url"
            local bwant bgot
            bwant="$(awk '{print $1}' "$tmp_dir/$bundle_name.sha256")"
            bgot="$(sha256sum "$tmp_dir/$bundle_name" | awk '{print $1}')"
            if [ "$bwant" != "$bgot" ]; then
                err "dependency bundle FAILED its checksum -- refusing to package"
                return 1
            fi
        fi
        mv "$tmp_dir/$bundle_name" "$out_dir/$bundle_name"
        log "included Docker/dependency bundle: $out_dir/$bundle_name ($(_h "$(stat -c%s "$out_dir/$bundle_name" 2>/dev/null || echo 0)"))"
    fi

    final="$out_dir/$base"
    mv "$tmp_dir/$base" "$final"
    log "done: $final ($(_h "$(stat -c%s "$final" 2>/dev/null || echo 0)")) in $(_elapsed $(( $(date +%s) - _legacy_started )))"
    echo "$final"
}

RUN_STARTED=$(date +%s)
TAG="${1:-}"
OUT_DIR="${2:-.}"
MODULES_CSV="${3:-}"
REPO="${INTACT_REPO:-TenrootOrg/IntactAI}"
# Overridable for the same reason as lib/upgrade/refs.sh's pair: the repo is
# private, so with no token there is no way to exercise this script at all.
# Defaults to real GitHub, so nothing changes for an operator.
API="${INTACT_GH_API_BASE:-https://api.github.com}"

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
    # No per-module index -- this release may have been published with ONLY
    # the legacy single-file format instead (build-release-package.yml),
    # which some releases use in place of the per-module scheme specifically
    # so a box old enough to predate the index (pre-2026-08-05) can still
    # take it. That release genuinely has no index.json at all -- it is not
    # an error, just a different (older) shape for this one tag. Fetch it
    # directly rather than failing outright.
    log "no per-module index for $TAG -- checking for a legacy single-file package"
    if _fetch_legacy_single_file "$TAG" "$OUT_DIR" "$REL"; then
        exit 0
    fi
    err "release $TAG has neither a per-module index ($TAG.index.json)"
    err "nor a legacy single-file package (intact-upgrade-$TAG.tar[.gz])"
    err "its CI build may still be running, or the release is incomplete"
    exit 1
fi

log "reading the release index"
curl -fsSL "${AUTH[@]}" -H "Accept: application/octet-stream" \
     -o "$TAG.index.json" "$IDX_URL"

# The MERGED root manifest, published by CI's `index` job alongside the
# per-module assets. Without it the wrapped package is unusable: every asset
# carries only its own manifests/<module>.json sidecar, and the apply side
# (lib/upgrade/package.sh:upkg_read_manifest) refuses a package that has those
# but no merged manifest.json -- "it predates the per-module release index, or
# only some of the release's assets were copied here". That is exactly the
# shape this script used to produce, so the flagship air-gap path (prepare
# here, hand-carry, `upgrade.sh --package` there) failed on arrival at the
# offline site, which is the worst possible place to discover it.
#
# Named "<tag>.manifest.json", NOT "manifest.json": the wrapper detector in
# upkg_expand_args refuses a tar whose top level contains a member named
# exactly `manifest.json` (that shape means "this IS a package", not "this
# wraps packages"), so the bare name would silently disable unwrapping.
MANIFEST_URL="$(printf %s "$REL" | TAG="$TAG" python3 -c '
import json, os, sys
want = os.environ["TAG"] + ".manifest.json"
for a in json.load(sys.stdin).get("assets", []):
    if a["name"] == want:
        print(a["url"]); break
')"
MANIFEST_NAME=""
if [ -n "$MANIFEST_URL" ]; then
    log "fetching the merged manifest"
    if curl -fsSL "${AUTH[@]}" -H "Accept: application/octet-stream" \
            -o "$TAG.manifest.json" "$MANIFEST_URL"; then
        MANIFEST_NAME="$TAG.manifest.json"
    else
        err "could not download $TAG.manifest.json"
        exit 1
    fi
else
    # A release cut before CI began publishing the merged manifest. Say so
    # loudly HERE, on the connected machine where it is cheap to react, rather
    # than letting the operator carry a package that cannot be applied.
    err "release $TAG publishes no $TAG.manifest.json"
    err "  The wrapped package will be REFUSED by 'upgrade.sh --package' on the"
    err "  target ('per-module manifests but no merged manifest.json')."
    err "  Use a release built by current CI, or apply the per-module assets"
    err "  directly on a machine that can reach GitHub."
    exit 1
fi

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

# The host-level Docker/apt dependency bundle -- deliberately NOT part of the
# per-module index above (build-release-assets.yml's "system-bundle" job
# publishes it as its own release asset, disjoint from any module, since
# Docker isn't owned by one module). A release built before this feature
# simply has none -- BUNDLE_PLAN is then empty and everything below is a
# no-op, same as any other release attribute this script doesn't recognise.
#
# Without this, the single file this script exists to produce silently
# lacks the one thing install.sh's air-gap path needs to install Docker
# without touching the internet -- the exact defect this fetch closes.
BUNDLE_NAME="${TAG}-system-bundle.tar"
BUNDLE_PLAN="$(printf %s "$REL" | TAG="$TAG" python3 -c '
import json, os, sys
tag = os.environ["TAG"]
assets = {a["name"]: a for a in json.load(sys.stdin).get("assets", [])}
name = f"{tag}-system-bundle.tar"
a = assets.get(name)
if a:
    print("BUNDLE\t" + name + "\t" + a["url"] + "\t" + str(a.get("size") or 0))
    sha = assets.get(name + ".sha256")
    if sha:
        print("SHA\t" + name + ".sha256\t" + sha["url"])
' 2>/dev/null)"
if [ -n "$BUNDLE_PLAN" ]; then
    BUNDLE_BYTES="$(printf '%s\n' "$BUNDLE_PLAN" | awk -F'\t' '$1=="BUNDLE"{print $4+0}')"
    TOTAL_BYTES=$(( TOTAL_BYTES + BUNDLE_BYTES ))
fi

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

# Deliberately NOT using aria2c/multi-connection splitting of a single
# asset here, after actually shipping and testing it. GitHub's release
# assets redirect (302) to a time-limited signed storage URL (Azure Blob
# SAS on this repo -- confirmed live: ~60 minute validity, `se=...Z` in
# the Location header). A tool that resolves that redirect ONCE and then
# splits the resulting (already time-boxed) URL into parallel segments --
# which is exactly what aria2c -x/-s does -- has no way to get a fresh
# URL if the transfer runs long or a segment stalls: every remaining
# segment starts failing auth at the same moment, which looks identical
# to a hang. Reproduced live: a real run against this release's ~1.8G ELK
# asset went from a fast start to completely frozen partway through.
# This is a documented, known incompatibility between aria2c and
# redirect-based signed-URL CDNs generally (aria2/aria2#2197), not
# something specific to this repo.
#
# Plain curl with `-L` does not have this problem: `--retry` re-runs the
# ENTIRE request on failure, including re-following the redirect from the
# original (non-expiring) api.github.com URL -- so every retry mints a
# fresh signed URL -- combined with `-C -` resuming from the correct byte
# offset already on disk. This is the same refresh-on-retry mechanism
# `gh release download` is built around; curl already does it natively.
# Verified live against the real ~1.8G ELK asset end-to-end.
#
# The actual bug in the previous plain-curl version wasn't the mechanism,
# it was too few retries (--retry 3) for a multi-GB transfer on a real
# link -- each retry is cheap (resumes, doesn't restart), so there's
# little downside to allowing many more of them.
#
# Real parallelism here comes from the OUTER fan-out below (several
# DIFFERENT files downloading at once, each independently resolving its
# own redirect/signed URL) -- that's safe because it never shares one
# resolved URL across connections, unlike per-file segmentation.
_OUTER_P=6
log "downloading $NFILES asset(s), $(_h "$TOTAL_BYTES") total, $_OUTER_P at a time"

# EVERY line in this phase is "<verb> <module> <size> [detail]", one fixed
# shape. Several downloads run at once, so start/finish lines interleave by
# nature -- with `->`/`<-` markers the operator had to decode arrows to work
# out what was happening. A left-aligned verb column reads down the page
# regardless of interleaving, and the module name is always in the same place.
#
# -sS, NOT curl's progress meter: parallel meters redrawing interleave into
# unreadable garbage, and this stdout is piped straight into the appliance's
# workflow log. Aggregate progress comes from the watcher below.
_CHUNK_MIN=$((64*1024*1024))   # not worth splitting under 64M
_CHUNKS=4

# Real multi-connection speedup for one large file WITHOUT aria2c's mistake:
# each chunk below hits the ORIGINAL api.github.com URL with its own Range
# header and its own -L, so each chunk independently resolves its OWN fresh
# signed redirect URL, scoped only to that chunk's own transfer time. No
# chunk shares a pre-resolved, time-boxed URL with another, so one chunk
# running long (or needing its own retries) can never invalidate the rest --
# the exact failure mode that made aria2c unusable here. Verified live: the
# CDN honors Range through the redirect (a 1MB range request returned
# exactly ~1MB of real content, not the whole file or an error).
_dl_chunked() {
    name="$1"; url="$2"; total="$3"; shift 3
    n="$_CHUNKS"
    size=$(( (total + n - 1) / n ))
    parts=(); pids=()
    start=0
    while [ "$start" -lt "$total" ]; do
        end=$(( start + size - 1 ))
        [ "$end" -ge "$total" ] && end=$((total - 1))
        part="$name.part-$start"
        parts+=("$part")
        curl -fL -sS -C - --retry 20 --retry-delay 5 \
             -H "Range: bytes=$start-$end" "$@" -o "$part" "$url" &
        pids+=($!)
        start=$((end + 1))
    done
    ok=1
    for pid in "${pids[@]}"; do
        wait "$pid" || ok=0
    done
    if [ "$ok" -ne 1 ]; then
        rm -f "${parts[@]}"
        return 1
    fi
    cat "${parts[@]}" > "$name" 2>/dev/null
    rm -f "${parts[@]}"
    # A server that silently ignored Range and returned 200-with-full-body
    # for every "chunk" would otherwise produce a corrupt, oversized
    # concatenation that only an exact size check catches.
    got=$(stat -c%s "$name" 2>/dev/null || echo 0)
    [ "$got" = "$total" ]
}
export -f _dl_chunked

_dl_one() {
    name="$1"; mod="$2"; url="$3"; want="$4"
    started=$(date +%s)
    printf '[prepare]   %-9s %-14s %8s\n' "start" "$mod" "$(_h "$want")"
    hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
    [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    ok=1
    if [ "${want:-0}" -ge "$_CHUNK_MIN" ] 2>/dev/null; then
        _dl_chunked "$name" "$url" "$want" "${hdrs[@]}" || ok=0
    else
        ok=0
    fi
    if [ "$ok" -ne 1 ]; then
        # Small file (not worth splitting), or the chunked path failed --
        # fall back to a single plain-curl stream. -C - resumes from
        # whatever "$name" already has on disk; --retry 20 (was 3) means
        # each retry re-follows -L from the original URL, minting a fresh
        # signed URL and resuming from disk, so a link that keeps dropping
        # mid-transfer eventually finishes via bounded retries instead of
        # giving up after 3.
        if ! curl -fL -sS -C - --retry 20 --retry-delay 5 "${hdrs[@]}" -o "$name" "$url"; then
            printf '[prepare][ERROR]   %-9s %-14s %s\n' "failed" "$mod" "$name" >&2
            return 1
        fi
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
     | xargs -P "$_OUTER_P" -L 1 bash -c '_dl_one "$1" "$2" "$3" "$4"' _; then
    kill "$WATCHER" 2>/dev/null || true
    err "one or more downloads failed"
    exit 1
fi
kill "$WATCHER" 2>/dev/null || true
# Re-arm without the watcher-kill, but keep every signal: resetting this to a
# bare EXIT left Ctrl-C during the wrap phase leaking the staging directory.
trap _cleanup EXIT INT TERM HUP
log "downloaded $NFILES asset(s), $(_h "$TOTAL_BYTES") in $(_elapsed $(( $(date +%s) - DL_STARTED )))"

# Fetch the dependency bundle, if this release has one. Its own step, own
# checksum check -- it isn't part of $PLAN (see where BUNDLE_PLAN is built
# above) so the module-asset verification loop below never sees it.
if [ -n "$BUNDLE_PLAN" ]; then
    log "fetching the Docker/dependency bundle"
    BUNDLE_SHA_URL=""
    while IFS="$(printf '\t')" read -r kind bname burl _rest; do
        case "$kind" in
            BUNDLE)
                hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
                [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
                curl -fL -sS -C - --retry 20 --retry-delay 5 "${hdrs[@]}" \
                     -o "$bname" "$burl"
                ;;
            SHA) BUNDLE_SHA_URL="$burl" ;;
        esac
    done <<< "$BUNDLE_PLAN"
    if [ -n "$BUNDLE_SHA_URL" ] && [ -f "$BUNDLE_NAME" ]; then
        # Accept: application/octet-stream is NOT optional on an API asset URL.
        # $BUNDLE_SHA_URL is https://api.github.com/repos/O/R/releases/assets/<id>
        # (the plan builder above stores a["url"], not browser_download_url), and
        # GitHub serves that endpoint content-negotiated: with this header you get
        # the asset's BYTES, without it you get the asset's JSON METADATA and a
        # 200 either way -- so `curl -f` is happy and the file on disk is a
        # pretty-printed object.
        #
        # It was missing here, and only here: the five sibling fetches (the
        # legacy path, index.json, manifest.json, the module fan-out, and the
        # bundle .tar in the loop immediately above) all send it. `awk '{print $1}'`
        # then returned the first field of EVERY line of that JSON, so `want`
        # became the multi-line string `{ / "url": / "id": / ...` and every real
        # release with a published sidecar failed to package:
        #
        #   dependency bundle FAILED its checksum (want {
        #   "url":
        #   "id":
        #   "..., got 1cee8a822b4cea98...) -- refusing to package
        #
        # Reported from a real intact-20260813 prepare run, 2026-08-13, after all
        # nine module assets had downloaded and verified cleanly.
        hdrs=(-H "X-GitHub-Api-Version: 2022-11-28" -H "Accept: application/octet-stream")
        [ -n "${GITHUB_TOKEN:-}" ] && hdrs+=(-H "Authorization: Bearer $GITHUB_TOKEN")
        curl -fsSL "${hdrs[@]}" -o "$BUNDLE_NAME.sha256" "$BUNDLE_SHA_URL"
        want="$(awk 'NR==1{print $1}' "$BUNDLE_NAME.sha256")"
        got="$(sha256sum "$BUNDLE_NAME" | awk '{print $1}')"
        rm -f "$BUNDLE_NAME.sha256"
        # Say WHICH failure this is. A sidecar that is not a hex digest at all is
        # a broken fetch, not a corrupt download, and the two want opposite
        # responses from whoever reads the log -- conflating them is what made
        # the bug above read as "the bundle is corrupt" for a whole release.
        if ! printf '%s' "$want" | grep -qE '^[0-9a-f]{64}$'; then
            err "dependency bundle sidecar is not a sha256 (got '${want:0:40}') -- the"
            err "  .sha256 fetch returned something other than the file's bytes;"
            err "  refusing to package rather than guess."
            exit 1
        fi
        if [ "$want" != "$got" ]; then
            err "dependency bundle FAILED its checksum (want ${want:0:16}..., got ${got:0:16}...) -- refusing to package"
            exit 1
        fi
    fi
    printf '[prepare]   %-9s %-14s %8s\n' "included" "system-bundle" \
        "$(_h "$(stat -c%s "$BUNDLE_NAME" 2>/dev/null || echo 0)")"
fi

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
# EXCLUDES *-system-bundle.tar even though it matches "$TAG-*.tar": that
# file is the host-level dependency bundle fetched above, not a module
# asset, and is added to the wrap explicitly below instead -- keeping it out
# of ASSETS/NASSETS here means this error check and the "module asset(s)"
# log line below stay accurate regardless of whether a bundle was fetched.
# install.sh's own directory-expansion glob excludes it by the same name for
# the same reason.
ASSETS=()
while IFS= read -r -d '' _a; do
    ASSETS+=("$_a")
done < <(find . -maxdepth 1 \
              \( -name "$TAG-*.tar.gz" -o -name "$TAG-*.tar" \) \
              ! -name '*-system-bundle.tar' \
              -printf '%P\0' 2>/dev/null | sort -z)
NASSETS=${#ASSETS[@]}
if [ "$NASSETS" -eq 0 ]; then
    err "no module assets to package"
    err "  $NFILES file(s) were downloaded for $TAG but none of them is named"
    err "  $TAG-<module>.tar[.gz] -- refusing to write an index-only package"
    exit 1
fi
log "verified $NASSETS module asset(s)"

# Add the bundle as its own wrap member, alongside (not instead of) the
# module assets found above -- see where BUNDLE_PLAN is built for why it's
# never part of ASSETS itself.
WRAP_MEMBERS=("$TAG.index.json")
# The merged manifest rides second, right behind the index -- both are tiny and
# both are read from the head of the stream (see the index-first note below).
[ -n "$MANIFEST_NAME" ] && [ -f "$MANIFEST_NAME" ] && WRAP_MEMBERS+=("$MANIFEST_NAME")

# ---------------------------------------------------------------------------
# The upgrade ENGINE, at the TOP LEVEL of the wrapper and near the head of the
# stream.
#
# It is already in this package -- buried inside the intact module asset at
# source/intact/. That is useless to the thing that needs it: an installed
# bootstrap must reach the target release's engine BEFORE it parses anything,
# and digging it out of a module asset means parsing the payload first. Which
# is the exact circularity that made a .tar -> .tar.gz change unupgradeable.
#
# So it rides here too, under its own frozen name, where
# scripts/bootstrap_upgrade.sh can pull it out by name with one tar call and no
# format detection. A few hundred KB against a multi-GB package.
# ---------------------------------------------------------------------------
_engine_dl() {
    local base="${INTACT_GH_DL_BASE:-https://github.com}/${REPO:-TenrootOrg/IntactAI}/releases/download/${TAG}"
    local n
    for n in "${TAG}-engine.tar.gz" "${TAG}-engine.tar.gz.sha256"; do
        [ -f "$n" ] && continue
        curl -fLsS --retry 3 --max-time 120 -o "$n" "${base}/${n}" 2>/dev/null || return 1
    done
    return 0
}
if _engine_dl; then
    WRAP_MEMBERS+=("${TAG}-engine.tar.gz" "${TAG}-engine.tar.gz.sha256")
    log "including the upgrade engine (${TAG}-engine.tar.gz)"
else
    # Not fatal. A release published before the engine asset existed simply
    # does not have one, and the bootstrap already treats its absence as
    # "fall back to the appliance's own engine" rather than as an error.
    # Saying so here means an operator carrying this package to an air-gapped
    # site knows which path it will take before they get there.
    rm -f "${TAG}-engine.tar.gz" "${TAG}-engine.tar.gz.sha256" 2>/dev/null
    log "no ${TAG}-engine.tar.gz published for this release — the target box will"
    log "  fall back to its own upgrade engine (this is the pre-split behaviour)"
fi

WRAP_MEMBERS+=("${ASSETS[@]}")
[ -n "$BUNDLE_PLAN" ] && [ -f "$BUNDLE_NAME" ] && WRAP_MEMBERS+=("$BUNDLE_NAME")

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
tar -cf "$OUT" "${WRAP_MEMBERS[@]}"

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
