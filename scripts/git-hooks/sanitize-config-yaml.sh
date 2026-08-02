#!/usr/bin/env bash
# Sanitize the STAGED copy of config.yaml before it becomes a commit.
#
# config.yaml is tracked so that a clone or a downloaded release has a
# ready-to-edit file (there is no config.yaml.example any more). But it is also
# the OPERATOR's live file: at runtime it accumulates options.github_token — a
# real ghp_ PAT — plus the dashboard login and every module password.
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
target="config.yaml"

# Nothing staged for config.yaml -> nothing to do.
if ! git diff --cached --name-only | grep -qx "$target"; then
    exit 0
fi

staged_sha=$(git ls-files --stage -- "$target" | awk '{print $2}')
[[ -n "$staged_sha" ]] || exit 0     # staged as a deletion

tmp=$(mktemp)
cleaned=$(mktemp)
trap 'rm -f "$tmp" "$cleaned"' EXIT

git cat-file blob "$staged_sha" > "$tmp"

python3 - "$tmp" "$cleaned" <<'PY'
import re, sys

src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    lines = f.read().splitlines(keepends=True)

# Textual edit, NOT a yaml round-trip: config.yaml is full of operator-facing
# comments that PyYAML would silently discard, and the whole point of tracking
# this file is that a human reads it before installing.
DEFAULT_PW = "123123"
out, current, changed = [], None, []

for ln in lines:
    m = re.match(r'^(\w+):', ln)
    if m:
        current = m.group(1)

    # options.github_token -> always empty. This is the one that matters: a
    # live PAT to a private org, written at runtime, never something to ship.
    t = re.match(r'^(\s*github_token:[ \t]*)(.*?)([ \t]*(?:#.*)?)$', ln)
    if t and t.group(2).strip().strip('"\''):
        out.append(f"{t.group(1)}''{t.group(3)}\n")
        changed.append("github_token")
        continue

    # Module passwords -> back to the shipped default. Operators are told to
    # change these at install time; whatever this box uses is not for git.
    p = re.match(r'^(    password:[ \t]*)(.*?)([ \t]*(?:#.*)?)$', ln)
    if p and p.group(2).strip().strip('"\'') != DEFAULT_PW:
        out.append(f"{p.group(1)}{DEFAULT_PW}{p.group(3)}\n")
        changed.append("password")
        continue

    # A fresh checkout must land in setup mode, or the first install has
    # first_login: false with no stored credential and fails closed = locked out.
    fl = re.match(r'^(first_login:[ \t]*)(.*?)([ \t]*(?:#.*)?)$', ln)
    if fl and fl.group(2).strip().lower() != "true":
        out.append(f"{fl.group(1)}true{fl.group(3)}\n")
        changed.append("first_login")
        continue

    out.append(ln)

with open(dst, "w") as f:
    f.writelines(out)

if changed:
    from collections import Counter
    c = Counter(changed)
    print(" ".join(f"{k}x{v}" if v > 1 else k for k, v in c.items()))
PY

summary=$(cat /dev/null)
if ! cmp -s "$tmp" "$cleaned"; then
    new_sha=$(git hash-object -w "$cleaned")
    git update-index --cacheinfo "100644,${new_sha},${target}"
    echo "  [config.yaml] staged copy sanitized to shipping defaults" >&2
    echo "                (github_token emptied, module passwords -> 123123," >&2
    echo "                 first_login -> true). Your working file is unchanged." >&2
fi

exit 0
