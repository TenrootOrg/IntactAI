#!/bin/bash
# Pre-install upgrade-check helper.
#
# When options.check_module_updates is true in config.yaml, this runs
# right at the top of install.sh — before any work is done. For each
# pinned version under `versions:` it queries the matching upstream
# GitHub repo for the latest non-prerelease tag. If the upstream is
# newer than the pin, the operator is asked whether to bump the pin;
# pressing y rewrites the value in config.yaml in place (preserves
# comments and key order — line-targeted Python edit, not a yaml.dump).
#
# Both pull-based modules (Timesketch, IRIS, Portainer, ELK) and
# build-based modules (Velociraptor — Dockerfile pulls the binary from
# the same releases page) are checked, because the upstream check
# semantics are identical: which release tag should we be on.
#
# Skipped: backend (internal version, no upstream repo to query).

# Map config.yaml versions.* keys to their upstream GitHub repos.
declare -A INTACT_UPSTREAM_REPOS=(
    [velociraptor]=Velocidex/velociraptor
    [timesketch]=google/timesketch
    [plaso]=log2timeline/plaso
    [iris]=dfir-iris/iris-web
    [portainer]=portainer/portainer
    [elk]=elastic/elasticsearch
)

# Per-module version-format spec.
#
# Each module's pin in config.yaml is already in *Docker image tag*
# format — docker-compose interpolation drops the value into
# `image: <repo>:${MODULE_VERSION}` verbatim. The upstream *Git tag*
# on GitHub may differ from the Docker tag for the same release:
#   - Elastic tags `v9.4.0` on GitHub but ships Docker images at
#     `docker.elastic.co/elasticsearch/elasticsearch:9.4.0` (bare).
#   - Velociraptor tags `v0.76` on GitHub, the binary it ships into
#     the locally-built image is named with the bare `0.76` form.
#   - IRIS uses `v2.4.27` in both formats.
#   - Timesketch and Plaso use bare date strings (`20260326`) in both.
#
# So the upgrade-check has TWO formats to deal with:
#   * config.yaml format (== Docker tag format) — what gets written
#     back into config.yaml when the operator accepts an upgrade
#   * upstream Git tag format — what `/releases/latest` returns and
#     what /releases/tag/<TAG> URLs use
#
# Two parallel maps tell us, per module, whether each format carries a
# leading `v`. Bare-vs-`v` is the only quirk in practice today; if a
# future module brings a richer format (e.g., `release-1.2.3`) the
# _config_to_upstream / _upstream_to_config helpers below are the only
# place that needs to learn about it.
declare -A INTACT_UPSTREAM_V_PREFIX=(
    [velociraptor]=yes
    [timesketch]=no
    [plaso]=no
    [iris]=yes
    [portainer]=no
    [elk]=yes
)
declare -A INTACT_CONFIG_V_PREFIX=(
    [velociraptor]=no
    [timesketch]=no
    [plaso]=no
    [iris]=yes
    [portainer]=no
    [elk]=no
)

# Convert a config.yaml pin (Docker-tag format) into the upstream Git
# tag format. Used to compare the operator's current pin against what
# `_upstream_latest_release` returned. Idempotent — passing a value
# already in upstream form yields the same value.
_config_to_upstream() {
    local module="$1" value="$2"
    local stripped="${value#v}"
    if [[ "${INTACT_UPSTREAM_V_PREFIX[$module]:-no}" == "yes" ]]; then
        echo "v${stripped}"
    else
        echo "$stripped"
    fi
}

# Convert an upstream Git tag into the config.yaml pin (Docker-tag)
# format. Used when writing an accepted upgrade back into config.yaml
# so the docker-compose interpolation gets a tag the registry actually
# serves.
_upstream_to_config() {
    local module="$1" tag="$2"
    local stripped="${tag#v}"
    if [[ "${INTACT_CONFIG_V_PREFIX[$module]:-no}" == "yes" ]]; then
        echo "v${stripped}"
    else
        echo "$stripped"
    fi
}

# Sentinel emitted when an upstream call is rejected by GitHub's
# anonymous rate-limit. Callers distinguish this from a generic
# empty-string failure (network down / 404) so they can stop the
# loop early instead of pointlessly retrying 5 more times.
INTACT_UPSTREAM_RATE_LIMITED="__INTACT_RATE_LIMITED__"

# Fetch the latest stable tag from a repo's /releases/latest endpoint.
# Returns:
#   - the tag_name on success (e.g., "v1.2.3" or "20260511")
#   - INTACT_UPSTREAM_RATE_LIMITED if GitHub rejected the call as
#     over-quota (HTTP 403 + body mentions "rate limit", or the
#     X-RateLimit-Remaining response header is 0)
#   - empty string on any other failure (network down, 404, parse error)
#
# Prereleases + drafts: GitHub's /releases/latest endpoint already
# excludes both by design — confirmed in practice across all six
# upstreams we track. No extra client-side guard needed.
_upstream_latest_release() {
    local repo="$1"
    # `-i` includes the response headers so we can read
    # X-RateLimit-Remaining to detect a 403/rate-limit response. We
    # pass the captured response to Python as argv (not stdin) because
    # `python3 -c` already consumes stdin for the script body — if we
    # piped curl's output to stdin, the script would see an empty
    # string. Argv is fine for /releases/latest responses (a few KB).
    local raw
    local -a _auth=(); [[ -n "${GITHUB_TOKEN:-}" ]] && _auth=(-H "Authorization: token $GITHUB_TOKEN")
    raw=$(curl -sLi --max-time 15 \
        -H "Accept: application/vnd.github+json" "${_auth[@]}" \
        "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null)
    [[ -z "$raw" ]] && return 0   # network failure → empty (handled by caller)

    python3 -c '
import sys, re, json
sentinel, raw = sys.argv[1], sys.argv[2]

# curl -L may produce multiple header blocks when following redirects;
# the actual body is everything after the LAST blank line.
parts = re.split(r"\r?\n\r?\n", raw)
body = parts[-1] if parts else ""
headers = "\n\n".join(parts[:-1]) if len(parts) > 1 else ""

status = 0
remaining = None
for line in headers.splitlines():
    if line.upper().startswith("HTTP/"):
        try:
            status = int(line.split()[1])
        except (IndexError, ValueError):
            pass
    elif line.lower().startswith("x-ratelimit-remaining:"):
        try:
            remaining = int(line.split(":", 1)[1].strip())
        except (IndexError, ValueError):
            pass

# Rate-limit detection: HTTP 403 with body mentioning rate-limit, OR
# the remaining-counter header at zero. Either is sufficient.
if (status == 403 and "rate limit" in body.lower()) or remaining == 0:
    print(sentinel)
    sys.exit(0)

try:
    d = json.loads(body)
    print(d.get("tag_name", "") or "")
except Exception:
    pass
' "$INTACT_UPSTREAM_RATE_LIMITED" "$raw" 2>/dev/null
}

# Quick zero-cost probe of the operator's current anonymous-API budget.
# Hits /rate_limit which by GitHub's documentation does NOT itself count
# against the quota. Returns the remaining-request count as an integer,
# or empty string if the call fails (in which case the caller proceeds
# optimistically — better to attempt the per-module check than skip
# preemptively on a transient network glitch).
_upstream_rate_limit_remaining() {
    local -a _auth=(); [[ -n "${GITHUB_TOKEN:-}" ]] && _auth=(-H "Authorization: token $GITHUB_TOKEN")
    curl -sL --max-time 10 \
        -H "Accept: application/vnd.github+json" "${_auth[@]}" \
        "https://api.github.com/rate_limit" 2>/dev/null \
        | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d['resources']['core']['remaining'])
except Exception:
    pass
" 2>/dev/null
}

# Format the rate_limit reset timestamp (unix seconds) into a
# human-readable local time. Falls back to the raw value if `date`
# can't parse it for some reason.
_upstream_rate_limit_reset_at() {
    local epoch
    local -a _auth=(); [[ -n "${GITHUB_TOKEN:-}" ]] && _auth=(-H "Authorization: token $GITHUB_TOKEN")
    epoch=$(curl -sL --max-time 10 \
        -H "Accept: application/vnd.github+json" "${_auth[@]}" \
        "https://api.github.com/rate_limit" 2>/dev/null \
        | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d['resources']['core']['reset'])
except Exception:
    pass
" 2>/dev/null)
    if [[ -n "$epoch" ]]; then
        date -d "@${epoch}" 2>/dev/null || echo "$epoch"
    fi
}

# Rewrite one module's pinned version in config.yaml in place. Operates
# line-by-line so comments + key order survive (yaml.safe_dump would
# blow both away). Atomic via tmp-rename. Restores file ownership in
# case install.sh is running under sudo and the YAML file was owned by
# the unprivileged user.
_pin_module_version() {
    local module="$1"
    local new_value="$2"
    local owner_user owner_group
    owner_user=$(stat -c '%U' "$CONFIG_FILE")
    owner_group=$(stat -c '%G' "$CONFIG_FILE")

    python3 - "$CONFIG_FILE" "$module" "$new_value" <<'PYEOF'
import re, sys, os
config_path, module, new_value = sys.argv[1], sys.argv[2], sys.argv[3]
with open(config_path) as f:
    lines = f.readlines()

in_versions = False
out = []
for line in lines:
    indent_str = re.match(r'^(\s*)', line).group(1)
    if line.startswith('versions:'):
        in_versions = True
        out.append(line)
        continue
    if in_versions:
        stripped = line.strip()
        # Exit the versions block when a new top-level key starts
        # (indent 0, non-comment, non-blank).
        if not indent_str and stripped and not stripped.startswith('#'):
            in_versions = False
        elif re.match(rf'^\s+{re.escape(module)}\s*:', line):
            # Always single-quote the value so YAML doesn't auto-cast
            # date-like strings (e.g. 20260511) to ints or omit
            # leading zeros.
            out.append(f"{indent_str}{module}: '{new_value}'\n")
            continue
    out.append(line)

tmp = config_path + '.tmp'
with open(tmp, 'w') as f:
    f.writelines(out)
os.replace(tmp, config_path)
PYEOF

    # Preserve original ownership in case we're root.
    chown "${owner_user}:${owner_group}" "$CONFIG_FILE" 2>/dev/null || true
}

# Public entry point. Iterates every key under `versions:` in
# config.yaml that has an upstream mapping; prompts the operator on
# each newer release; rewrites accepted pins. Designed to be called
# from main() in install.sh BEFORE any installation work.
check_module_updates() {
    log_info "Checking upstream module versions (this requires internet)..."

    # Note: no explicit TTY check needed. When stdin is /dev/null
    # (CI / `bash install.sh < /dev/null`) `read` returns EOF
    # immediately and `reply` stays empty, which our regex treats as N
    # — every module's pin is preserved. When stdin is a pipe with
    # `yes y` / `yes n` the answers flow through normally. When stdin
    # is a TTY the operator gets the interactive prompt. All three
    # modes work correctly without a guard.

    # Upfront budget probe: one free call to /rate_limit (doesn't
    # itself count against the quota). If GitHub's anonymous-API
    # budget for this IP is below what we need (6, one per module),
    # bail loudly instead of running a partial check. Operators
    # behind shared NAT or running back-to-back installs from CI hit
    # this without warning otherwise.
    local needed=${#INTACT_UPSTREAM_REPOS[@]}
    local remaining
    remaining=$(_upstream_rate_limit_remaining)
    if [[ -n "$remaining" && "$remaining" -lt "$needed" ]]; then
        local reset_at
        reset_at=$(_upstream_rate_limit_reset_at)
        log_warn "GitHub API anonymous-call budget too low for this run"
        log_warn "  remaining: ${remaining}/60   needed: ${needed}"
        log_warn "  resets at: ${reset_at:-unknown}"
        log_warn "  Skipping module update check; install will use existing pinned versions."
        log_warn "  Re-run after the reset, or set options.check_module_updates: false in config.yaml."
        return 0
    fi
    if [[ -z "$remaining" ]]; then
        log_info "  (could not pre-probe GitHub API budget — proceeding optimistically)"
    else
        log_info "  GitHub API budget: ${remaining}/60 remaining (need ${needed})"
    fi

    local any_change=false
    local rate_limit_hit=false
    for module in "${!INTACT_UPSTREAM_REPOS[@]}"; do
        local repo="${INTACT_UPSTREAM_REPOS[$module]}"
        local current
        current=$(read_config "['versions']['$module']")
        if [[ -z "$current" || "$current" == "None" ]]; then
            continue  # module not pinned in this config.yaml
        fi

        local upstream_tag
        upstream_tag=$(_upstream_latest_release "$repo")
        if [[ "$upstream_tag" == "$INTACT_UPSTREAM_RATE_LIMITED" ]]; then
            # GitHub rate-limit hit mid-loop (race with another call from
            # same IP, or the upfront probe was a slight underestimate).
            # The remaining 5 modules would all fail the same way —
            # break loudly instead of pretending to check them.
            log_warn "  ${module}: GitHub API rate limit hit"
            log_warn "  resets at: $(_upstream_rate_limit_reset_at || echo unknown)"
            log_warn "  Aborting update check; install will use existing pinned versions."
            log_warn "  Re-run after the reset, or set options.check_module_updates: false."
            rate_limit_hit=true
            break
        fi
        if [[ -z "$upstream_tag" ]]; then
            log_warn "  ${module}: could not reach ${repo} — skipping"
            continue
        fi

        # Bidirectional format conversion (see header comment for the
        # full rationale):
        #   * Project the operator's config.yaml pin into upstream-tag
        #     format so we're comparing apples-to-apples against what
        #     /releases/latest returned.
        #   * Project the upstream tag back into config.yaml (Docker-
        #     tag) format so the value we'd write actually matches
        #     what docker-compose interpolates.
        local current_as_upstream new_as_config
        current_as_upstream=$(_config_to_upstream "$module" "$current")
        new_as_config=$(_upstream_to_config "$module" "$upstream_tag")

        if [[ "$current_as_upstream" == "$upstream_tag" ]]; then
            log_info "  ${module}: ${current} (already latest)"
            continue
        fi

        log_info "  ${module}: ${current} → ${new_as_config}"
        echo "    https://github.com/${repo}/releases/tag/${upstream_tag}"
        local reply
        read -r -p "    Upgrade pinned version in config.yaml? [y/N] " reply
        if [[ "$reply" =~ ^[Yy] ]]; then
            _pin_module_version "$module" "$new_as_config"
            log_success "  ${module} pinned -> ${new_as_config}"
            any_change=true
        else
            log_info "  ${module} kept at ${current}"
        fi
    done

    if [[ "$any_change" == "true" ]]; then
        log_info "config.yaml updated. Continuing installation with the new pins..."
    fi
    if [[ "$rate_limit_hit" == "true" ]]; then
        # Already logged the loud warning where the limit fired; this
        # is just the trailing summary so the operator's eye catches
        # the truncation when scrolling back through install output.
        log_warn "Update check ended early due to GitHub rate limit — some modules were not checked."
    fi
}
