#!/usr/bin/env bash
# Every shell capture of the backend's python stdout must use a sentinel.
#
# THE BUG THIS EXISTS FOR. Importing services.storage prints three banner
# lines to STDOUT:
#
#   [STORAGE] Initializing SQLite storage...
#   [STORAGE] SQLite storage initialized: /app/data/intact.db
#   [WORKFLOW] Using SQLite + Elasticsearch storage for workflows
#
# So `x=$(docker exec intact_backend python3 -c '...')` never returns just the
# answer -- it returns the banners with the answer glued on, or, when the
# answer is empty, JUST the banners. bootstrap_iris_api_key's idempotency
# guard did exactly that and tested `[[ -n "$existing" ]]`, so it was true on
# every box and the IRIS api key was NEVER bootstrapped -- on installs or
# upgrades, since both call the same function. Measured on a clean
# 2026-08-24 install: zero iris rows in `secrets`, and "IRIS API key already
# in backend secrets DB — skipping bootstrap" in the same log. The read-back
# verification a few lines below it had the same flaw, which would have turned
# a successful write into a false "read-back didn't match" error the moment
# the guard was fixed.
#
# lib/modules/shared.sh had already hit this, documented it in a comment, and
# solved it with a sentinel; lib/modules/backend.sh solved it with
# contextlib.redirect_stdout. iris.sh had two instances that were missed. This
# test is the guard that stops a third from being written.
#
# scripts/migrate/ is out of scope: it is a one-shot migration tool for a
# retired platform, not part of install or upgrade.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run=0; failed=0

ok()   { printf '  \033[0;32mok\033[0m   - %s\n' "$1"; }
bad()  { printf '  \033[0;31mFAIL\033[0m - %s\n' "$1"; failed=$((failed+1)); }
check(){ run=$((run+1)); if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A capture is guarded when a sentinel grep or an in-python stdout redirect
# appears within the ~20 lines the `-c "..."` block spans. Line-window rather
# than paren-matching on purpose: the embedded python is full of ordinary
# parens, so brace counting misreads `get_secret('k')` as the end of the
# substitution and reports every file, guarded or not.
_scan() {
    python3 - "$1" <<'PY'
import os, re, sys
root = sys.argv[1]
for base in ("lib",):
    for dirpath, _dirs, files in os.walk(os.path.join(root, base)):
        for fn in sorted(files):
            if not fn.endswith(".sh"):
                continue
            p = os.path.join(dirpath, fn)
            lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
            for i, line in enumerate(lines):
                if line.lstrip().startswith("#"):
                    continue
                if not re.search(r'=\$\(\s*docker exec .*intact_backend python3', line):
                    continue
                window = "\n".join(lines[i:i + 20])
                if "grep -o" in window or "redirect_stdout" in window:
                    continue
                print(f"{os.path.relpath(p, root)}:{i + 1}")
PY
}

echo "== every backend python capture is sentinel-guarded or stdout-redirected =="
mapfile -t offenders < <(_scan "$ROOT")
run=$((run+1))
if [[ ${#offenders[@]} -eq 0 ]]; then
    ok "no unguarded backend-python captures under lib/"
else
    bad "unguarded backend-python capture(s) — the storage banner is read as the value:"
    for o in "${offenders[@]}"; do printf '         %s\n' "$o"; done
fi

# Non-vacuous: the scanner must catch the exact shape the bug had.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/lib"
cat > "$tmp/lib/regression.sh" <<'SH'
    existing=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
v = get_secret('iris.administrator.api_key')
sys.stdout.write(v or '')
" 2>/dev/null || true)
SH
mapfile -t caught < <(_scan "$tmp")
check "the scanner catches the original unguarded shape (non-vacuous)" \
  '[[ ${#caught[@]} -eq 1 ]]'

# A guarded capture must NOT be reported.
cat > "$tmp/lib/guarded.sh" <<'SH'
    existing=$(docker exec intact_backend python3 -c "
from services.storage.secret_store import get_secret
print('INTACT_IRISKEY:' + (get_secret('k') or ''))
" 2>/dev/null | grep -o 'INTACT_IRISKEY:.*' | tail -1 || true)
SH
mapfile -t caught2 < <(_scan "$tmp")
check "a sentinel-guarded capture is not reported (no false positive)" \
  '[[ ${#caught2[@]} -eq 1 ]]'

# iris.sh specifically, by name, since it is where the bug lived. Comment
# lines excluded -- the fix's own explanation quotes the broken form.
check "iris.sh's captures use the sentinel" \
  "[[ \$(grep -c 'INTACT_IRISKEY' '$ROOT/lib/modules/iris.sh') -ge 2 ]]"
check "iris.sh has no bare stdout.write of the key outside comments" \
  "! grep -vE '^\s*#' '$ROOT/lib/modules/iris.sh' | grep -qE 'sys\.stdout\.write\(v'"

echo
echo "$(basename "$0"): ${run} run, ${failed} failed"
[[ $failed -eq 0 ]]
