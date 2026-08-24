#!/bin/bash
# `exec` with redirections and NO command applies them to the SHELL, for the
# rest of its life -- and every process it goes on to exec inherits them.
#
# scripts/upgrade.sh took the lock with
#
#     exec 9>"$LOCK" 2>/dev/null || true
#
# where the 2>/dev/null was only ever meant to hide noise from the fd-9 open.
# Instead it pointed fd 2 at /dev/null for the whole upgrade. The cost was not
# theoretical: applying an engine-less package via the documented CLI exited 2
# after printing a 505-byte, fully actionable explanation ("Give it the engine
# directly: --engine <path>") to a stderr nobody could see, while the byte-
# identical failure run through bootstrap_upgrade.sh printed it in full. Every
# raw-stderr diagnostic after that line went the same way -- docker errors,
# stray tracebacks, anything not routed through log_error.
#
# Two guards here: the shape (no bare `exec` may carry a stderr redirect), and
# the behaviour (the group-wrapped form must still leave fd 2 usable).

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "== no bare exec redirection may touch stderr =="
# A bare `exec` is one with no command word after the redirections. Only those
# mutate the shell; `exec somecmd 2>/dev/null` is an ordinary, safe replace.
offenders="$(grep -rn --include='*.sh' -E '^[[:space:]]*exec[[:space:]]+[0-9]*[<>][^|]*2>' "$ROOT" \
             | grep -v '/tests/' | grep -v '/\.git/' || true)"
if [[ -z "$offenders" ]]; then
    ok "no bare 'exec <fd>' redirects stderr anywhere in the tree"
else
    fail "a bare 'exec' redirects stderr -- it will silence the whole run" "$offenders"
fi

echo "== the lock line still opens fd 9 =="
if grep -qE '^[[:space:]]*\{ exec 9>' "$ROOT/scripts/upgrade.sh"; then
    ok "upgrade.sh takes the lock through a group-wrapped exec"
else
    fail "upgrade.sh no longer opens fd 9 the expected way" \
         "$(grep -n 'exec 9' "$ROOT/scripts/upgrade.sh" || echo '(no exec 9 at all)')"
fi

echo "== behaviour: the buggy form silences, the fixed form does not =="
cat > "$TMP/bad.sh" <<'EOF'
exec 9>"$1" 2>/dev/null || true
echo "diagnostic" >&2
EOF
cat > "$TMP/good.sh" <<'EOF'
{ exec 9>"$1"; } 2>/dev/null || true
echo "diagnostic" >&2
EOF
bad="$(bash "$TMP/bad.sh"  "$TMP/a.lock" 2>&1 >/dev/null)"
good="$(bash "$TMP/good.sh" "$TMP/b.lock" 2>&1 >/dev/null)"
[[ -z "$bad" ]]              && ok "the old form does swallow stderr (bug reproduces)" \
                             || fail "the old form no longer swallows stderr" "got '$bad'"
[[ "$good" == "diagnostic" ]] && ok "the group-wrapped form leaves stderr reaching the terminal" \
                             || fail "the fixed form still swallows stderr" "got '$good'"

echo "== behaviour: the fix still leaves fd 9 lockable =="
cat > "$TMP/lock.sh" <<'EOF'
{ exec 9>"$1"; } 2>/dev/null || true
flock -n 9 && echo LOCKED || echo NOTLOCKED
EOF
[[ "$(bash "$TMP/lock.sh" "$TMP/c.lock")" == "LOCKED" ]] \
    && ok "fd 9 survives the group and flock still takes it" \
    || fail "fd 9 did not survive the group wrapper" "flock could not lock it"

echo
echo "  $PASS/$TOTAL passed"
[[ "$PASS" == "$TOTAL" ]]
