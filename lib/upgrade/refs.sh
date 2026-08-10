#!/bin/bash
# Intact.AI upgrade — release discovery.
#
# Replaces the parts of services/upgrade/resolver.py (891 lines) that a CLI
# actually needs. Dropped along with the UI: the 30-minute response cache (a
# CLI run makes at most three API calls and then exits), the rate-limit quota
# widget, compute_plan's forced/optional checkbox table, and
# resolve_upgrade_chain's multi-hop planning -- which was computed and
# DISPLAYED but never enforced anyway (upgrade_routes.py's _modules_from_track
# ignored plan['chain'] and dispatched straight to the final target).
#
# What survives is the part that was load-bearing: only list releases that
# actually ship an installable payload. A release with no assets cannot be
# upgraded to, and offering it is how an operator ends up staring at a 404.
# That is not hypothetical -- intact-20260615 is published with zero assets.

INTACT_REPO="${INTACT_REPO:-TenrootOrg/IntactAI}"

# Authorization header, only when a token is configured. Anonymous GitHub is
# 60 requests/hour per IP, which a couple of runs can exhaust.
_gh_curl() {
    local url="$1"
    local token="${GITHUB_TOKEN:-}"
    if [[ -z "$token" ]]; then
        token="$(read_config "['options']['github_token']" 2>/dev/null || echo "")"
        [[ "$token" == "None" ]] && token=""
    fi
    if [[ -n "$token" ]]; then
        curl -sfL --max-time 30 -H "Authorization: token ${token}" \
             -H "Accept: application/vnd.github+json" "$url"
    else
        curl -sfL --max-time 30 -H "Accept: application/vnd.github+json" "$url"
    fi
}

# ---------------------------------------------------------------------------
# upgrade_list_releases — what this box could upgrade to.
# ---------------------------------------------------------------------------
upgrade_list_releases() {
    local current
    current="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo "unknown")"

    log_info "Installed: ${current}"
    log_info "Querying ${INTACT_REPO} …"

    local json
    json="$(_gh_curl "https://api.github.com/repos/${INTACT_REPO}/releases?per_page=40")" || {
        log_error "Could not reach the GitHub releases API."
        log_error "  Without a token you get 60 requests/hour per IP. Set"
        log_error "  options.github_token in config.yaml, or export GITHUB_TOKEN."
        return 1
    }

    # The response goes via a temp FILE, not stdin. A heredoc and a herestring
    # both redirect stdin and the heredoc wins, so `python3 - <<'PY' <<<"$json"`
    # silently feeds the script an empty stdin and lists nothing. shellcheck
    # SC2261 catches it; it is invisible at runtime because the failure looks
    # like "no releases found".
    local tmp; tmp="$(mktemp)"
    printf '%s' "$json" > "$tmp"

    python3 - "$current" "$tmp" <<'PY'
import json, re, sys
current, path = sys.argv[1], sys.argv[2]
try:
    rels = json.load(open(path, encoding="utf-8"))
except Exception:
    print("Could not parse GitHub's response."); raise SystemExit(1)
if isinstance(rels, dict):
    print("GitHub says: %s" % rels.get("message", "?")); raise SystemExit(1)

def datekey(tag):
    m = re.match(r"^intact-(\d{8})$", tag or "")
    return int(m.group(1)) if m else -1

cur = datekey(current)
rows, skipped = [], []
for r in rels:
    tag = r.get("tag_name") or ""
    if r.get("draft"):
        continue
    assets = r.get("assets") or []
    payload = sum(a["size"] for a in assets
                  if a["name"].endswith((".tar", ".tar.gz")) or ".tar.gz.part-" in a["name"])
    if payload <= 0:
        skipped.append(tag)
        continue
    rows.append((datekey(tag), tag, payload))

rows.sort()
if not rows:
    print("\nNo release carries an installable payload.")
    raise SystemExit(0)

print("\n  %-24s %10s   %s" % ("RELEASE", "PAYLOAD", ""))
for key, tag, size in rows:
    if key == cur:
        note = "<- installed"
    elif key < cur:
        note = "older"
    else:
        note = "newer"
    print("  %-24s %9.2fG   %s" % (tag, size / 1e9, note))

newer = [t for k, t, _ in rows if k > cur]
if newer:
    print("\n  Next:  sudo bash scripts/upgrade.sh %s" % newer[0])
    if len(newer) > 1:
        # One hop at a time: only N->N+1 is ever QA'd, and the module
        # upgraders assume they are moving one release, not four.
        print("  (%d newer releases; upgrade one at a time)" % len(newer))
else:
    print("\n  Nothing newer than %s is published." % current)

if skipped:
    print("\n  Not listed (published with no installable assets): %s"
          % ", ".join(skipped))
PY
    rm -f "$tmp"
    return 0
}

# ---------------------------------------------------------------------------
# upgrade_fetch_release <tag> <dest_dir>
#
# Reuses download_release_assets (lib/release.sh:24) when the release carries
# a per-module index, and otherwise falls back to fetching the single-bundle
# assets directly -- which is what every release published so far actually is.
# ---------------------------------------------------------------------------
upgrade_fetch_release() {
    local tag="$1" dest="$2"
    mkdir -p "$dest" || return 1

    local json
    json="$(_gh_curl "https://api.github.com/repos/${INTACT_REPO}/releases/tags/${tag}")" || {
        log_error "No release '${tag}' (or GitHub is rate-limiting this IP)"
        return 1
    }

    local names
    names="$(python3 -c '
import json,sys
d=json.load(sys.stdin)
if isinstance(d,dict) and "assets" not in d:
    sys.exit(1)
for a in d.get("assets",[]):
    print(a["name"])' <<<"$json")" || {
        log_error "Could not read the asset list for ${tag}"; return 1; }

    if [[ -z "$names" ]]; then
        log_error "Release ${tag} has no assets — nothing to upgrade from."
        return 1
    fi

    # Per-module release (has an index) -> the existing parallel downloader
    # already handles part reassembly, per-part digests and resume.
    if grep -q 'index\.json$' <<< "$names"; then
        log_info "Release ${tag} publishes a per-module index; using the asset downloader"
        download_release_assets "$tag" "$dest"
        return $?
    fi

    log_info "Release ${tag} is a single-bundle release; fetching its parts"
    local base="https://github.com/${INTACT_REPO}/releases/download/${tag}"
    local n
    while IFS= read -r n; do
        case "$n" in
            *.tar|*.tar.gz|*.tar.gz.part-*) ;;
            *) continue ;;
        esac
        [[ "$n" == *-system-bundle.tar ]] && continue
        log_info "  fetching ${n}"
        if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "downloading ${n}" 3600 \
                curl -fL --retry 3 --retry-all-errors -C - -o "${dest}/${n}" "${base}/${n}"; then
            log_error "  could not download ${n}"
            return 1
        fi
    done <<< "$names"

    # Reassemble .part-NN into the whole archive, in numeric order, then verify
    # against the published .sha256 -- which covers the WHOLE, pre-split file.
    local part1
    part1="$(find "$dest" -maxdepth 1 -name '*.tar.gz.part-00' | head -1)"
    if [[ -n "$part1" ]]; then
        local whole="${part1%.part-00}"
        log_info "  reassembling $(basename "$whole") from parts"
        cat "${whole}".part-* > "$whole" || { log_error "  reassembly failed"; return 1; }
        rm -f "${whole}".part-*
        local shafile="${whole}.sha256"
        if [[ ! -f "$shafile" ]]; then
            curl -sfL -o "$shafile" "${base}/$(basename "$whole").sha256" 2>/dev/null || true
        fi
        if [[ -s "$shafile" ]]; then
            local want got
            want="$(awk '{print $1}' "$shafile" | head -1)"
            got="$(sha256_of "$whole")"
            if [[ "$want" != "$got" ]]; then
                log_error "  reassembled archive checksum mismatch"
                log_error "    expected ${want}"
                log_error "    got      ${got}"
                return 1
            fi
            log_success "  reassembled archive verified against the published sha256"
        else
            log_warn "  no published .sha256 for $(basename "$whole") — integrity unverified"
        fi
    fi
    return 0
}
