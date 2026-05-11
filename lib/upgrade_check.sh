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

# Fetch the latest non-prerelease tag from a repo's /releases/latest
# endpoint. Returns the tag_name (e.g., "v1.2.3" or "20260511"). Empty
# string on failure (network down, 404, rate-limited, etc.) — callers
# treat empty as "skip this module quietly".
_upstream_latest_release() {
    local repo="$1"
    curl -sL --max-time 15 \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('tag_name', '') or '')
except Exception:
    pass
" 2>/dev/null
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

    # Don't try to prompt if stdin isn't a terminal (CI / piped install).
    if [[ ! -t 0 ]]; then
        log_warn "  stdin is not a terminal — cannot prompt; skipping update check"
        log_warn "  (re-run interactively or edit versions: in config.yaml by hand)"
        return 0
    fi

    local any_change=false
    for module in "${!INTACT_UPSTREAM_REPOS[@]}"; do
        local repo="${INTACT_UPSTREAM_REPOS[$module]}"
        local current
        current=$(read_config "['versions']['$module']")
        if [[ -z "$current" || "$current" == "None" ]]; then
            continue  # module not pinned in this config.yaml
        fi

        local latest
        latest=$(_upstream_latest_release "$repo")
        if [[ -z "$latest" ]]; then
            log_warn "  ${module}: could not reach ${repo} — skipping"
            continue
        fi

        # Normalize for comparison (strip a leading 'v' on either side
        # since some projects tag with the prefix and pin without).
        local norm_cur="${current#v}"
        local norm_lat="${latest#v}"
        if [[ "$norm_cur" == "$norm_lat" ]]; then
            log_info "  ${module}: ${current} (already latest)"
            continue
        fi

        log_info "  ${module}: ${current} → ${latest}"
        echo "    https://github.com/${repo}/releases/tag/${latest}"
        local reply
        read -r -p "    Upgrade pinned version in config.yaml? [y/N] " reply
        if [[ "$reply" =~ ^[Yy] ]]; then
            _pin_module_version "$module" "$latest"
            log_success "  ${module} pinned -> ${latest}"
            any_change=true
        else
            log_info "  ${module} kept at ${current}"
        fi
    done

    if [[ "$any_change" == "true" ]]; then
        log_info "config.yaml updated. Continuing installation with the new pins..."
    fi
}
