#!/usr/bin/env bash
# Sanitize the STAGED copy of the repo's config files before they become a
# commit. Two files are covered, for the same reason:
#
#   config.yaml     — tracked so a clone or a downloaded release has a
#                     ready-to-edit file (there is no config.yaml.example any
#                     more). Also the OPERATOR's live file: at runtime it
#                     accumulates options.github_token — a real ghp_ PAT — plus
#                     the dashboard login and every module password.
#
#   qa/qa-config.yaml — tracked for the same reason, and holds the QA harness's
#                     sudo password for this appliance and the Administrator
#                     password for the Windows target. Nothing in it should
#                     ever reach GitHub.
#
# This rewrites the version going INTO the commit back to shipping defaults and
# leaves the operator's working copy untouched. So `git commit` never publishes
# a credential, and the operator does not lose their own settings by committing.
#
# HOW (this is the important part): it does NOT touch the working tree. It reads
# the staged blob, sanitizes it, writes a NEW blob with `git hash-object -w`, and
# repoints the index at it with `git update-index --cacheinfo`. Editing the file
# on disk instead would wipe the operator's live PAT every time they committed.
#
# Called from scripts/git-hooks/pre-commit. Bypassable with `git commit
# --no-verify`, which is why .github/workflows/secret-scan.yml re-checks the
# pushed result — this hook is the fast local guard, not the only one.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)

# ---------------------------------------------------------------------------
# sanitize <path-in-repo>
#
# No-op unless the path is staged. Rewrites the index entry in place if the
# sanitized content differs from what is staged.
# ---------------------------------------------------------------------------
sanitize() {
    local target="$1"

    if ! git diff --cached --name-only | grep -qx "$target"; then
        return 0
    fi

    local staged_sha
    staged_sha=$(git ls-files --stage -- "$target" | awk '{print $2}')
    [[ -n "$staged_sha" ]] || return 0     # staged as a deletion

    local tmp cleaned
    tmp=$(mktemp)
    cleaned=$(mktemp)

    git cat-file blob "$staged_sha" > "$tmp"
    python3 "${repo_root}/scripts/git-hooks/sanitize_config.py" \
            "$target" "$tmp" "$cleaned"

    if ! cmp -s "$tmp" "$cleaned"; then
        local new_sha
        new_sha=$(git hash-object -w "$cleaned")
        # Preserve the staged mode rather than hardcoding 100644 — forcing the
        # mode would silently drop an intentional +x.
        local mode
        mode=$(git ls-files --stage -- "$target" | awk '{print $1}')
        git update-index --cacheinfo "${mode},${new_sha},${target}"
        echo "  [${target}] staged copy sanitized to shipping defaults;" >&2
        echo "                your working file is unchanged." >&2
    fi

    rm -f "$tmp" "$cleaned"
}

sanitize "config.yaml"
sanitize "qa/qa-config.yaml"

exit 0
