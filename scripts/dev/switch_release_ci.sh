#!/usr/bin/env bash
# Choose which workflow builds a release. Exactly one, always.
#
#   scripts/dev/switch_release_ci.sh legacy      single-asset bundle only
#   scripts/dev/switch_release_ci.sh per-module  per-module assets only
#   scripts/dev/switch_release_ci.sh             show the current state
#
# WHY A SCRIPT. The two workflows must not both fire on one publish -- they
# upload to the same release, and the per-module one re-drafts it at start and
# un-drafts at the end, so the legacy job can be attaching its 5.5 GB bundle
# while the release flips public underneath it. Keeping them mutually exclusive
# was a manual edit in two files, done four times in one day here, each time
# with a slightly different comment block. That is how one of them ends up
# half-commented.
#
# The `on:` trigger is the only thing that changes. Everything else in both
# workflows -- jobs, inputs, permissions -- is untouched, and workflow_dispatch
# stays on BOTH so either can always be run by hand against a tag regardless of
# which is armed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LEGACY="${ROOT}/.github/workflows/build-release-package.yml"
PERMOD="${ROOT}/.github/workflows/build-release-assets.yml"

_state() {
    python3 - "$1" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True) or d.get('on') or {}
print(f"{'ARMED  ' if 'release' in on else 'off    '}{d['name']}")
PY
}

show() {
    echo "  $(_state "$LEGACY")"
    echo "  $(_state "$PERMOD")"
}

# Comment or uncomment the `release:` trigger, leaving the rest of `on:` alone.
# Idempotent: running the same mode twice is a no-op rather than nesting `#`.
_arm() {   # $1 file
    python3 - "$1" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s2 = re.sub(r'^  # release:\n  #   types: \[published\]\n',
            '  release:\n    types: [published]\n', s, count=1, flags=re.M)
open(p, 'w').write(s2)
PY
}
_disarm() {
    python3 - "$1" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s2 = re.sub(r'^  release:\n    types: \[published\]\n',
            '  # release:\n  #   types: [published]\n', s, count=1, flags=re.M)
open(p, 'w').write(s2)
PY
}

_verify() {   # both files must still parse, and exactly one must be armed
    local armed=0 f
    for f in "$LEGACY" "$PERMOD"; do
        python3 -c "import sys,yaml; yaml.safe_load(open('$f'))" 2>/dev/null \
            || { echo "  ERROR: $f no longer parses as YAML" >&2; return 1; }
        python3 -c "
import yaml
d=yaml.safe_load(open('$f')); on=d.get(True) or d.get('on') or {}
raise SystemExit(0 if 'release' in on else 1)" 2>/dev/null && armed=$((armed + 1))
    done
    if (( armed != 1 )); then
        echo "  ERROR: ${armed} workflow(s) armed — must be exactly 1" >&2
        return 1
    fi
    return 0
}

case "${1:-}" in
    legacy)
        _arm "$LEGACY"; _disarm "$PERMOD" ;;
    per-module|permodule|new)
        _arm "$PERMOD"; _disarm "$LEGACY" ;;
    ""|show|status)
        show; exit 0 ;;
    *)
        echo "usage: $(basename "$0") [legacy|per-module]" >&2
        exit 2 ;;
esac

_verify || exit 1
show
echo
echo "  Commit and push to make it take effect:"
echo "    git add .github/workflows/build-release-*.yml && git commit && git push"
