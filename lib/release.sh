#!/bin/bash
# Intact.AI Platform Installer - Release Asset Downloads
#
# Fetching a release's assets from GitHub: the per-module image assets that
# lib/package.sh then loads, and the host system bundle (Docker + apt
# dependencies) that lib/deps.sh installs from.
#
# Split out of install.sh unchanged.

# Fetch the release package this checkout corresponds to, so an ONLINE install
# runs the same code as an air-gapped one.
#
# THE POINT IS NOT THE DOWNLOAD, IT IS THE SHARED PATH. Installing from a
# package means install and upgrade converge on one implementation: the same
# images, loaded the same way, deployed by the same compose files. Two
# implementations of "get this box running" are what let the installer and the
# upgrade engine drift -- secrets generated in both bash and Python, chmod
# policies that disagree, an ELK script one of them shipped and the other did
# not. One path is one thing to test.
#
# Falls back to per-image registry pulls if the asset cannot be had. That is the
# old behaviour, still correct, so a release without a published package (or a
# GitHub outage) degrades to a slower install rather than no install.
download_release_assets() {
    # Fetch every asset this release needs into $2 and leave their paths in
    # INTACT_PACKAGES.
    #
    # An INSTALL takes the COMPLETE module set. There is no baseline on a box
    # with nothing installed, so "only what changed" has no meaning here.
    #
    # Two shapes, both supported permanently:
    #   index present -> per-module assets (the current CI)
    #   no index      -> the single bundle (older releases, and the one-file
    #                    air-gap path)
    local tag="$1" dest_dir="$2"
    local repo="${INTACT_REPO:-TenrootOrg/IntactAI}"
    local api="https://api.github.com/repos/${repo}/releases/tags/${tag}"
    local hdr=(-H "Accept: application/vnd.github+json")
    [[ -n "${GITHUB_TOKEN:-}" ]] && hdr+=(-H "Authorization: token ${GITHUB_TOKEN}")

    log_info "Looking for release assets for ${tag}..."
    local json
    json="$(curl -sSL --max-time 60 "${hdr[@]}" "$api" 2>/dev/null)" || true
    [[ -n "$json" ]] || { log_error "  Could not reach the GitHub releases API"; return 1; }

    # The index, if this release has one. It is the ONLY place per-module
    # checksums live -- CI stopped publishing a `.sha256` file beside every
    # asset, because the release page then carried three files per module and
    # two of them were digests nothing read. Fetch it before anything else so
    # the payload can be verified against it below.
    #
    # Two spellings accepted: `<tag>.index.json`, and the older
    # `intact-release-<tag>.index.json` that doubled the prefix on a tag
    # already beginning with `intact-`.
    local index_json="" index_name=""
    local candidate
    for candidate in "${tag}.index.json" "intact-release-${tag}.index.json"; do
        if printf '%s' "$json" | grep -q "\"${candidate}\""; then
            index_name="$candidate"
            break
        fi
    done
    if [[ -n "$index_name" ]]; then
        log_info "  Reading the release index (${index_name})..."
        index_json="$(curl -fsSL --max-time 120 \
            "https://github.com/${repo}/releases/download/${tag}/${index_name}" \
            2>/dev/null)" || index_json=""
        [[ -n "$index_json" ]] || log_warn "  Could not read the release index — falling back to name matching"
    fi

    # What to fetch, and what it must hash to once whole. One
    # "<file-to-download><TAB><whole-asset><TAB><sha256-or-empty>" per line --
    # three columns because a split asset is downloaded as .part-NN pieces but
    # verified as the reassembled tarball.
    local names
    names="$(printf '%s' "$json" | INDEX_TAG="$tag" INDEX_JSON="$index_json" python3 -c '
import json, os, sys
tag = os.environ["INDEX_TAG"]
try:
    rel = json.load(sys.stdin)
except Exception:
    sys.exit(0)
names = [a.get("name", "") for a in (rel.get("assets") or [])]

# GitHub publishes a per-asset digest for every asset it hosts, including
# each individual split part -- captured here so every part can be verified
# right after its own download, before reassembly ever touches it. A -C -
# resumed download that continues past an earlier truncated or corrupted
# leftover ends up the right SIZE (curl only checks byte count) but the
# wrong CONTENT, which only a digest catches.
own_digest = {}
own_size = {}
for a in (rel.get("assets") or []):
    d = (a.get("digest") or "")
    own_digest[a.get("name") or ""] = d.split(":", 1)[1] if d.startswith("sha256:") else ""
    own_size[a.get("name") or ""] = a.get("size") or 0

# Per-module assets, straight from the index: it names the modules a release
# carries and the sha256 of each WHOLE tarball (taken pre-split, so it is also
# the only digest that covers a reassembled multi-part asset -- GitHub can only
# digest each .part-NN it received).
want = []
try:
    index = json.loads(os.environ.get("INDEX_JSON") or "")
except Exception:
    index = None
if index:
    attached, missing = set(names), []
    for entry in (index.get("assets") or {}).values():
        whole, sha = entry["asset"], entry.get("sha256") or ""
        parts = [p for p in (entry.get("parts") or []) if p in attached]
        if whole in attached:
            want.append((whole, whole, sha))
        elif parts:
            want.extend((p, whole, sha) for p in parts)
        else:
            missing.append(whole)
    if missing:
        # Marker on STDOUT -- stderr is discarded by the caller, so a bare
        # sys.exit(msg) here would read to the shell as "no assets found".
        print("__MISSING__" + ", ".join(sorted(missing)))
        sys.exit(0)

# No index: an older release, carrying the single bundle. GitHub publishes a
# per-asset digest of its own ("sha256:...") -- exact for an unsplit file, and
# all that shape ever is.
#
# TEMPORARY -- this branch exists only to bridge boxes on releases older than
# intact-20260807 (which predate the per-module index.json wrapper) through
# that one release. Remove it, and the CI trigger swap that made
# intact-20260807 publish in this single-bundle shape in the first place,
# once the fleet is past this transition -- planned for the patch after
# intact-20260807. See the legacy image-attribution handling in
# load_images_from_package() below for the other half of this bridge.
if not want:
    base = f"intact-upgrade-{tag}.tar.gz"
    for a in (rel.get("assets") or []):
        n = a.get("name") or ""
        if n == base:
            d = (a.get("digest") or "")
            want.append((n, n, d.split(":", 1)[1] if d.startswith("sha256:") else ""))
        elif n.startswith(base + ".part-"):
            # A reassembled bundle has no published digest of the whole on a
            # release this old; the parts are fetched and joined unverified
            # at the WHOLE-file level -- but each part is verified on its own
            # via own_digest above.
            want.append((n, base, ""))

for n, whole, sha in sorted(set(want)):
    own = own_digest.get(n) or ""
    size = own_size.get(n) or 0
    print(f"{n}|{whole}|{sha}|{own}|{size}")
' 2>/dev/null)" || true

    # An asset the index names but the release does not carry is fatal, not a
    # thing to install around: the install would come up missing a module while
    # reporting success.
    if [[ "$names" == __MISSING__* ]]; then
        log_error "  Release ${tag} indexes ${names#__MISSING__} but does not publish it"
        return 1
    fi
    if [[ -z "$names" ]]; then
        log_error "  Release ${tag} publishes no installable assets"
        return 1
    fi

    mkdir -p "$dest_dir"
    local n whole sha own size
    # sha_of[<whole asset>] = expected sha256 of the WHOLE reassembled file,
    # from the index -- verified after reassembly, further below.
    #
    # size_of[<name>] = expected byte size of THIS individual download (a
    # part, or the whole file if unsplit) -- GitHub publishes this in the
    # release API response, so no HEAD request is needed. Used only for the
    # heartbeat's live percentage below; download correctness never depends
    # on it.
    #
    # Field separator is "|", not a tab: "sha" is a middle column here and is
    # routinely empty for a legacy release, so a tab-joined line reads
    # "name<TAB><TAB>whole..." -- bash's `read` squeezes RUNS of tab into one
    # delimiter no matter what IFS is set to, which shifts every later column
    # left by one. "|" is never whitespace, so it does not.
    declare -A sha_of=()
    declare -A size_of=()
    local _dl_list; _dl_list="$(mktemp -p "${SCRIPT_DIR}/data/tmp" dl-list-XXXXXX)"
    local _count=0
    while IFS='|' read -r n whole sha own size; do
        [[ -n "$n" ]] || continue
        sha_of["$whole"]="$sha"
        size_of["$n"]="${size:-0}"
        # name|own-digest per line: _intact_fetch_asset runs in its own bash
        # process via xargs, so an associative array here would not survive
        # into it -- passing the digest alongside the name in the same line
        # does.
        printf '%s|%s\n' "$n" "$own" >> "$_dl_list"
        _count=$((_count + 1))
    done <<< "$names"

    # FOUR AT A TIME. This fetched one asset at a time while both other paths
    # that download the same assets already parallelise -- prepare_package.sh
    # with `xargs -P 4`, the backend's download.py with _ASSET_WORKERS = 4 --
    # so a first install was the slowest way to get the bytes. Measured on
    # intact-20260805: 5.85 GB serially in ~12 min, on a link that reached
    # 12 MB/s per stream.
    #
    # 4, matching the other two, because release assets come from one host and
    # more streams mostly steal bandwidth from each other.
    log_info "  Downloading ${_count} asset(s), 4 at a time..."

    # Multi-GB assets over a slow/throttled link can sit in this xargs fan-out
    # for 15+ minutes with ZERO output -- curl runs -fsSL (silent) and the only
    # progress signal that existed here was a printf that never reached
    # $LOG_FILE, so a healthy download and a hung one looked identical in the
    # log. A bare "N/M done" count turned out to be the same problem in a
    # smaller costume: on a real slow link the whole download can sit at
    # "0/3 done" for its entire multi-minute duration, which reads exactly
    # like stuck to someone who can't see WHY it's still 0. This heartbeat
    # reads each destination file's on-disk size every 30s (curl -C -
    # resumes into that same file, so its current size IS bytes-so-far) and
    # reports real byte counts and percentages against each asset's
    # published size from the release API -- no HEAD request needed, GitHub
    # already gives it to us in the metadata fetched above. Not
    # `run_with_heartbeat` (lib/common.sh): that helper takes one static
    # description string and wraps a single foreground command with a hard
    # timeout -- fine for "still extracting X", but it can't show a live,
    # per-worker byte count across N parallel downloads. This loop is
    # disposable scaffolding around the same xargs call below, not a
    # replacement for that helper.
    local _dl_status_dir
    _dl_status_dir="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" dl-status-XXXXXX)"
    local _dl_start=$SECONDS
    local _dl_heartbeat_pid=""
    local _dl_total_bytes=0 _dl_sz_name
    for _dl_sz_name in "${!size_of[@]}"; do
        _dl_total_bytes=$(( _dl_total_bytes + ${size_of[$_dl_sz_name]:-0} ))
    done
    (
        while sleep 30; do
            local _dl_done_n=0 _dl_got_bytes=0 _dl_detail="" \
                  _sz_name _sz_got _sz_want _sz_pct
            for _sz_name in $(printf '%s\n' "${!size_of[@]}" | sort); do
                _sz_want=${size_of[$_sz_name]:-0}
                if [[ -f "${_dl_status_dir}/${_sz_name//\//_}.done" ]]; then
                    # Known complete regardless of whether the release's
                    # metadata even carried a size -- reporting 0% for a
                    # finished asset (the size-unknown case, guard below)
                    # would be actively misleading, not just uninformative.
                    _sz_got=$_sz_want
                    _sz_pct=100
                    _dl_done_n=$((_dl_done_n + 1))
                else
                    _sz_got=$(stat -c%s "${dest_dir}/${_sz_name}" 2>/dev/null || echo 0)
                    _sz_pct=0
                    [[ "$_sz_want" -gt 0 ]] && _sz_pct=$(( _sz_got * 100 / _sz_want ))
                fi
                _dl_got_bytes=$((_dl_got_bytes + _sz_got))
                _dl_detail+="${_sz_name}: ${_sz_pct}%, "
            done
            _dl_detail="${_dl_detail%, }"
            local _dl_pct=0
            [[ "$_dl_total_bytes" -gt 0 ]] && _dl_pct=$(( _dl_got_bytes * 100 / _dl_total_bytes ))
            log_info "  ... downloading: $(( _dl_got_bytes / 1048576 ))/$(( _dl_total_bytes / 1048576 )) MB (${_dl_pct}%) — ${_dl_done_n}/${_count} done ($(( SECONDS - _dl_start ))s elapsed) — ${_dl_detail}"
        done
    ) &
    _dl_heartbeat_pid=$!
    # shellcheck disable=SC2064
    trap "kill ${_dl_heartbeat_pid} 2>/dev/null; rm -rf '${_dl_status_dir}'; trap - RETURN INT TERM" RETURN INT TERM

    _intact_fetch_asset() {
        # $1 is "name|own-digest" (own-digest may be empty) -- see the
        # _dl_list comment above for why it travels this way rather than
        # through an associative array.
        local line="$1" name digest dest got
        name="${line%%|*}"
        digest="${line#*|}"
        dest="${_DL_DEST}/${name}"
        # --retry-all-errors: plain --retry only retries a curated list of
        # conditions (timeouts, 5xx, a few others) -- an HTTP/2 stream error
        # (curl exit 92, "stream N was not closed cleanly: PROTOCOL_ERROR"),
        # seen for real against GitHub's release CDN under 4-way concurrency,
        # is NOT on that list, so it failed the whole install on one bad
        # stream instead of retrying. -C -: resume, so a retry on a
        # multi-hundred-MB asset continues instead of restarting at byte 0 --
        # the same fix prepare_package.sh's downloader already carries.
        #
        # Resume has its own failure mode though, also seen for real: a run
        # that dies mid-write (like the HTTP/2 error above) can leave a
        # partial file that is not cleanly truncated, and a LATER run's -C -
        # then builds on top of it -- ending up the right SIZE but the wrong
        # CONTENT, since curl's resume trusts the existing bytes rather than
        # re-checking them. The digest check right below is what actually
        # catches that; without it this would silently ship a corrupt
        # package that only fails much later, at tar extraction.
        if curl -fsSL -C - --retry 3 --retry-all-errors --retry-delay 5 --max-time 3600 \
                -o "$dest" \
                "https://github.com/${_DL_REPO}/releases/download/${_DL_TAG}/${name}" \
                2>>"${_DL_LOG}"; then
            if [[ -n "$digest" ]]; then
                got="$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')"
                if [[ "$got" != "$digest" ]]; then
                    rm -f "$dest"
                    printf '[install]   CORRUPT   %s (checksum mismatch, deleted -- a retry fetches it fresh)\n' "$name" >&2
                    return 1
                fi
            fi
            printf '[install]   done      %s\n' "$name"
            touch "${_DL_STATUS_DIR}/${name//\//_}.done" 2>/dev/null || true
        else
            printf '[install]   FAILED    %s\n' "$name" >&2
            return 1
        fi
    }
    export -f _intact_fetch_asset
    export _DL_DEST="$dest_dir" _DL_REPO="$repo" _DL_TAG="$tag" _DL_LOG="$LOG_FILE" \
           _DL_STATUS_DIR="$_dl_status_dir"

    # xargs exits 123 if ANY invocation failed, so one bad asset still fails
    # the install -- "a package that cannot be fetched is a FAILED INSTALL".
    # Piped through tee (matching every other long-running step in this
    # codebase, e.g. lib/docker.sh) so the per-asset done/FAILED/CORRUPT
    # lines land in $LOG_FILE too, not just the terminal; PIPESTATUS[0]
    # recovers xargs's own exit code since pipefail alone doesn't hand it
    # back cleanly through a `tee` consumer that always exits 0.
    xargs -P 4 -I{} -a "$_dl_list" bash -c '_intact_fetch_asset "$@"' _ {} 2>&1 | tee -a "$LOG_FILE"
    local _dl_rc=${PIPESTATUS[0]}
    kill "$_dl_heartbeat_pid" 2>/dev/null
    wait "$_dl_heartbeat_pid" 2>/dev/null
    rm -rf "$_dl_status_dir"
    trap - RETURN INT TERM
    if [[ $_dl_rc -ne 0 ]]; then
        log_error "  One or more asset downloads failed — see $LOG_FILE"
        rm -f "$_dl_list"
        unset -f _intact_fetch_asset
        return 1
    fi
    rm -f "$_dl_list"
    unset -f _intact_fetch_asset
    unset _DL_DEST _DL_REPO _DL_TAG _DL_LOG _DL_STATUS_DIR

    # Reassemble any split assets. CI splits anything over the 2 GiB asset cap;
    # the index's sha256 is of the WHOLE tarball, taken pre-split, so it is the
    # join that gets verified below, not the pieces.
    local part0
    while IFS= read -r part0; do
        [[ -n "$part0" ]] || continue
        local joined="${part0%.part-00}"
        log_info "  Reassembling $(basename "$joined")..."
        cat "${joined}".part-* > "$joined" && rm -f "${joined}".part-*
    done < <(find "$dest_dir" -maxdepth 1 \
                  \( -name '*.tar.gz.part-00' -o -name '*.tar.part-00' \) | sort)

    # Verify everything BEFORE anything is applied.
    INTACT_PACKAGES=()
    local f verified=0 unverified=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        local want="${sha_of[$(basename "$f")]:-}"
        if [[ -n "$want" ]]; then
            local got
            got="$(sha256sum "$f" | awk '{print $1}')"
            if [[ "$want" != "$got" ]]; then
                log_error "  $(basename "$f") FAILED its checksum (expected ${want:0:16}…, got ${got:0:16}…)"
                return 1
            fi
            verified=$((verified + 1))
        else
            unverified=$((unverified + 1))
        fi
        INTACT_PACKAGES+=("$f")
    done < <(find "$dest_dir" -maxdepth 1 \
                  \( -name '*.tar.gz' -o -name '*.tar' \) | sort)

    if (( ${#INTACT_PACKAGES[@]} == 0 )); then
        log_error "  Nothing downloaded"
        return 1
    fi
    log_success "  ${#INTACT_PACKAGES[@]} asset(s) ready (${verified} checksum-verified)"
    if (( unverified > 0 )); then
        log_warn "  ${unverified} asset(s) had no checksum in the release index — integrity unverified"
    fi
    return 0
}

# Fetches and stages this release's Docker/host-dependency bundle, if it has
# one, into its OWN destination dir -- deliberately separate from
# download_release_assets()'s dest_dir, so its *.tar doesn't get swept up by
# that function's broad *.tar/*.tar.gz module-asset globs.
#
# Return codes matter here and are NOT interchangeable:
#   0 = staged successfully, ready to install from
#   1 = this release genuinely has no bundle (predates the feature) -- NOT
#       an error, the caller falls through to the pre-bundle behaviour
#       exactly as before this feature existed
#   2 = the release DOES have a bundle but it could not be obtained/verified
#       -- this IS fatal. Per the "package is the only source" design there
#       is nowhere to fall through to once a release promises a bundle.
download_system_bundle() {
    local tag="$1" dest_dir="$2"
    local repo="${INTACT_REPO:-TenrootOrg/IntactAI}"
    local api="https://api.github.com/repos/${repo}/releases/tags/${tag}"
    local hdr=(-H "Accept: application/vnd.github+json")
    [[ -n "${GITHUB_TOKEN:-}" ]] && hdr+=(-H "Authorization: token ${GITHUB_TOKEN}")

    # A failed/empty/unparseable API call is NOT the same outcome as "this
    # release's metadata was read fine and it simply has no bundle asset" --
    # the first is an unknown state (transient GitHub hiccup, rate limit,
    # DNS blip) and must NOT be treated as "predates this feature" and fall
    # through to download.docker.com/live apt. Only a successfully parsed
    # release object that genuinely lacks the asset returns 1; everything
    # else that prevents a real answer returns 2 (fatal).
    local json curl_rc
    json="$(curl -sSL --max-time 60 "${hdr[@]}" "$api" 2>>"$LOG_FILE")"; curl_rc=$?
    if (( curl_rc != 0 )); then
        log_error "  Could not reach GitHub to check for a dependency bundle (curl exit ${curl_rc})"
        return 2
    fi
    if [[ -z "$json" ]]; then
        log_error "  GitHub returned an empty response checking for a dependency bundle"
        return 2
    fi
    # Confirms $json is actual release metadata (has an "assets" array) and
    # not, say, `{"message":"API rate limit exceeded"}` or a stray HTML error
    # page -- either of which contains no bundle name and would otherwise be
    # indistinguishable from a genuine "no bundle" release.
    if ! printf '%s' "$json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(d.get("assets"), list) else 1)
' 2>/dev/null; then
        log_error "  Could not parse GitHub's release metadata for ${tag} (rate-limited, or the tag doesn't exist)"
        return 2
    fi

    local bundle_name="${tag}-system-bundle.tar"
    printf '%s' "$json" | grep -q "\"${bundle_name}\"" || return 1

    log_info "Looking for the Docker/dependency bundle for ${tag}..."
    mkdir -p "$dest_dir"
    local bundle_file="${dest_dir}/${bundle_name}"
    if ! curl -fsSL -C - --retry 3 --retry-all-errors --retry-delay 5 --max-time 1800 \
            -o "$bundle_file" \
            "https://github.com/${repo}/releases/download/${tag}/${bundle_name}" \
            2>>"$LOG_FILE"; then
        log_error "  Could not download the dependency bundle (${bundle_name})"
        rm -f "$bundle_file"
        return 2
    fi

    local sha_name="${bundle_name}.sha256"
    if printf '%s' "$json" | grep -q "\"${sha_name}\""; then
        local sha_file="${dest_dir}/${sha_name}"
        if curl -fsSL --max-time 60 -o "$sha_file" \
                "https://github.com/${repo}/releases/download/${tag}/${sha_name}" 2>>"$LOG_FILE"; then
            local want got
            want="$(awk '{print $1}' "$sha_file" 2>/dev/null)"
            got="$(sha256sum "$bundle_file" | awk '{print $1}')"
            rm -f "$sha_file"
            if [[ -z "$want" || "$want" != "$got" ]]; then
                log_error "  Dependency bundle FAILED its checksum (expected ${want:-?:16}, got ${got:0:16}…)"
                rm -f "$bundle_file"
                return 2
            fi
        fi
    fi

    log_info "  Extracting dependency bundle..."
    local extract_dir="${dest_dir}/system-bundle"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    if ! tar -xf "$bundle_file" -C "$extract_dir" 2>>"$LOG_FILE"; then
        log_error "  Could not extract the dependency bundle"
        rm -f "$bundle_file"
        rm -rf "$extract_dir"
        return 2
    fi
    rm -f "$bundle_file"
    log_success "  Dependency bundle staged (${bundle_name})"
    return 0
}
