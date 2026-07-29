#!/usr/bin/env bash
# Point this clone's git at scripts/git-hooks.
#
# The secret guard in scripts/git-hooks/pre-commit only runs if git is told to
# look there, and that setting lives in .git/config — which is per-clone and
# NOT tracked. So the guard shipped in the repo was off by default: a fresh
# clone, a new developer, or a rebuilt build box had no local protection at
# all until someone remembered to run the command by hand. The guard existing
# and the guard running are different things.
#
# Idempotent and safe to run repeatedly; install.sh calls it.
#
#     bash scripts/install-git-hooks.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Not a git repository — nothing to install." >&2
    exit 0
fi

current=$(git config --get core.hooksPath || true)

if [[ "$current" == "scripts/git-hooks" ]]; then
    echo "Git hooks already installed (core.hooksPath=scripts/git-hooks)"
else
    if [[ -n "$current" ]]; then
        # Don't silently steal a path someone set deliberately.
        echo "! core.hooksPath is currently '$current'." >&2
        echo "  Overwriting it with scripts/git-hooks. If that path had hooks" >&2
        echo "  you need, merge them into scripts/git-hooks/ instead." >&2
    fi
    git config core.hooksPath scripts/git-hooks
    echo "Git hooks installed (core.hooksPath=scripts/git-hooks)"
fi

# The hook's full rule set comes from gitleaks + .gitleaks.toml. Without the
# binary it falls back to a partial pattern list, which is worth saying at
# install time rather than leaving someone to discover it from a stderr line
# during a commit they are already halfway through.
if ! command -v gitleaks >/dev/null 2>&1; then
    echo ""
    echo "! gitleaks is not installed, so the pre-commit guard will run in"
    echo "  PARTIAL mode (it misses the Anthropic / OpenAI / OpenRouter /"
    echo "  Azure rules in .gitleaks.toml). CI still enforces the full set."
    echo "  Install: https://github.com/gitleaks/gitleaks/releases"
fi
