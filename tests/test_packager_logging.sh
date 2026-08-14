#!/usr/bin/env bash
# A guard that crashes when it fires is worse than no guard.
#
# scripts/ci/packager/*.py has no module-level `log`. Every function rebinds it
# from its own `logger` argument:
#
#     log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
#
# _reject_fabricated_mount_dirs did not. It took only `source_root` and called
# log() eight times, so the instant it found an offender it raised
#
#     Package preparation failed: name 'log' is not defined
#
# and the release build died with a NameError instead of the REFUSING TO BUILD
# diagnostic that names the offending paths and the one-line fix. It survived
# unnoticed because it only logs on a hit -- the happy path never touches those
# lines, so every green build was evidence of nothing.
#
# This asserts the property for the whole package rather than that one function:
# no top-level function may call log() without binding it. Nested functions are
# exempt, since they legitimately close over an enclosing binding.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

echo "== no top-level packager function may call log() unbound =="

OUT="$(python3 - "$ROOT" <<'PY'
import ast, os, sys
root = sys.argv[1]
pkg = os.path.join(root, "scripts", "ci", "packager")
bad = []
for fn in sorted(os.listdir(pkg)):
    if not fn.endswith(".py"):
        continue
    path = os.path.join(pkg, fn)
    tree = ast.parse(open(path).read())
    # Only TOP-LEVEL functions: a nested def may close over an enclosing `log`.
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
        calls, assigns, nested = [], set(), set()
        for sub in node.body:
            for n in ast.walk(sub):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not node:
                    nested.add(id(n))
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "log":
                calls.append(n.lineno)
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name) and t.id == "log":
                        assigns.add(t.lineno)
        if calls and not assigns and "log" not in params:
            bad.append(f"{fn}:{node.lineno} {node.name}() calls log() at line {min(calls)} but never binds it")
print("\n".join(bad))
PY
)"

if [[ -z "$OUT" ]]; then
    ok "every top-level function that logs also binds log"
else
    fail "every top-level function that logs also binds log" "$OUT"
fi

# And specifically the guard that was broken: it must take a logger and use it.
python3 - "$ROOT" <<'PY'
import ast, sys, os
p = os.path.join(sys.argv[1], "scripts", "ci", "packager", "package.py")
t = ast.parse(open(p).read())
for n in t.body:
    if isinstance(n, ast.FunctionDef) and n.name == "_reject_fabricated_mount_dirs":
        params = [a.arg for a in n.args.args]
        assigns = {x.id for m in ast.walk(n) if isinstance(m, ast.Assign)
                   for x in m.targets if isinstance(x, ast.Name)}
        sys.exit(0 if ("logger" in params and "log" in assigns) else 1)
sys.exit(2)
PY
case $? in
    0) ok "_reject_fabricated_mount_dirs takes a logger and binds log" ;;
    2) fail "_reject_fabricated_mount_dirs takes a logger and binds log" "function not found" ;;
    *) fail "_reject_fabricated_mount_dirs takes a logger and binds log" \
            "it crashes with NameError exactly when it detects an offender" ;;
esac

# The caller must actually pass one, or the default lambda silently swallows the
# diagnostic into stdout instead of the build log.
if grep -q '_reject_fabricated_mount_dirs(extracted_root, log)' "${ROOT}/scripts/ci/packager/package.py"; then
    ok "the call site passes the build logger through"
else
    fail "the call site passes the build logger through"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" -eq "$TOTAL" ]]
