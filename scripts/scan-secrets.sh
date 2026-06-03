#!/usr/bin/env bash
# Scan the repo for secrets — full history + working tree + staged diff.
# Useful before a force-push, before tagging a release, or when adding
# a new template that might inadvertently contain a literal key.
#
# Exit code: 0 if clean, 1 if any leak detected, 2 if gitleaks missing.
#
# Usage:
#   bash scripts/scan-secrets.sh           # all three scans
#   bash scripts/scan-secrets.sh --staged  # just the pre-commit-style scan
#   bash scripts/scan-secrets.sh --history # just the historical commits
#   bash scripts/scan-secrets.sh --tree    # just the working tree

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

CONFIG=".gitleaks.toml"
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "${RED}gitleaks is not installed.${NC}"
    echo "  Install: https://github.com/gitleaks/gitleaks#installing"
    echo "  e.g. on Ubuntu: 'curl -fL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_$(uname -m).tar.gz | tar -xz -C /usr/local/bin gitleaks'"
    exit 2
fi

mode="${1:-all}"
fail=0

run_scan() {
    local label="$1"; shift
    echo
    echo "${YELLOW}== $label ==${NC}"
    if gitleaks "$@" --config "$CONFIG" --redact --no-banner; then
        echo "${GREEN}clean${NC}"
    else
        echo "${RED}LEAK DETECTED${NC}"
        fail=1
    fi
}

case "$mode" in
    --staged)  run_scan "staged diff"     protect --staged ;;
    --tree)    run_scan "working tree"    detect --no-git ;;
    --history) run_scan "history"         detect ;;
    all|"")
        run_scan "staged diff"  protect --staged
        run_scan "working tree" detect --no-git
        run_scan "history"      detect
        ;;
    *)
        echo "${RED}Unknown mode: $mode${NC}"
        echo "  Usage: $0 [--staged|--tree|--history]"
        exit 2
        ;;
esac

echo
if (( fail )); then
    echo "${RED}== one or more scans found secrets — fix before pushing ==${NC}"
    exit 1
fi
echo "${GREEN}== all scans clean ==${NC}"
