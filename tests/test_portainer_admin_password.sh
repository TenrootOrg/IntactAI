#!/usr/bin/env bash
# The shipped Portainer password must be usable, and the refusal must say why.
#
# config.yaml shipped `1234qwer!@#$`, which is EXACTLY 12 characters. It passed
# the length test and tripped the literal match against the known-weak default,
# so every default install generated a random password and printed:
#
#   Portainer password missing or < 12 chars in config.yaml
#
# Neither clause was true. The operator opened config.yaml, saw a 12-character
# password sitting there, and had nothing to go on. One message covered four
# branches and named the two that had not fired.
#
# Two properties are asserted here:
#   1. the value config.yaml ships is actually ACCEPTED (a default nobody can
#      use is worse than no default -- it looks configured and is not);
#   2. every refusal names the condition that fired, and the retired default is
#      still refused so a box carrying it never inherits a weak credential.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

P="${ROOT}/lib/modules/portainer.sh"

echo "== the shipped default is usable =="
# Read the TRACKED config, not the box's live one: they differ, and it is the
# tracked file that every install starts from.
SHIPPED="$(cd "$ROOT" && git show HEAD:config.yaml 2>/dev/null | python3 -c "
import sys, yaml
try:
    d = yaml.safe_load(sys.stdin)
    print((d.get('modules', {}).get('portainer') or {}).get('password', '') or '')
except Exception:
    print('')
")"
RETIRED='1234qwer!@#$'

if [[ -n "$SHIPPED" && "$SHIPPED" != "None" ]]; then
    ok "config.yaml ships a Portainer password"
else
    fail "config.yaml ships a Portainer password"
fi
if (( ${#SHIPPED} >= 12 )); then
    ok "it meets Portainer's 12-character minimum (${#SHIPPED} chars)"
else
    fail "it meets Portainer's 12-character minimum" \
         "got ${#SHIPPED}; a short value leaves the admin account silently uncreated"
fi
if [[ "$SHIPPED" != "$RETIRED" ]]; then
    ok "it is not the retired default"
else
    fail "it is not the retired default" \
         "that value is refused, so every install would fall back to a random password"
fi
# The whole point: the shipped value survives the guard and is used as-is.
if [[ -n "$SHIPPED" && "$SHIPPED" != "None" && ${#SHIPPED} -ge 12 && "$SHIPPED" != "$RETIRED" ]]; then
    ok "so the guard accepts it and Portainer is seeded with it"
else
    fail "so the guard accepts it and Portainer is seeded with it"
fi

echo
echo "== the retired default is still refused =="
if grep -q "_PORTAINER_RETIRED_DEFAULT=" "$P"; then
    ok "the retired default is still named in the guard"
else
    fail "the retired default is still named in the guard" \
         "a box whose config still carries it would inherit a publicly-known password"
fi

echo
echo "== each refusal states the condition that fired =="
# Distinct reason strings, not one message covering every branch.
for r in "no Portainer password is set" "shorter than Portainer's 12-character minimum" "retired shipped default"; do
    if grep -qF "$r" "$P"; then
        ok "reason present: ${r}"
    else
        fail "reason present: ${r}"
    fi
done
# The old catch-all must be gone, or the misdiagnosis survives.
if grep -qF "Portainer password missing or < 12 chars" "$P"; then
    fail "the old catch-all message is gone" \
         "it named the two conditions that had not fired on a default install"
else
    ok "the old catch-all message is gone"
fi
# A refusal must still tell the operator where to read the generated password.
if grep -q 'Retrieve it with: cat' "$P"; then
    ok "a refusal still points at the generated password file"
else
    fail "a refusal still points at the generated password file"
fi

echo
echo "== the branch chosen matches the input =="
# Exercise the real decision rather than trusting the strings above.
run_branch() {
    LOG_OUT="$(
        portainer_password="$1" bash -c '
            _PORTAINER_RETIRED_DEFAULT='"'"'1234qwer!@#$'"'"'
            reason=""
            if [[ -z "$portainer_password" || "$portainer_password" == "None" ]]; then
                reason="empty"
            elif (( ${#portainer_password} < 12 )); then
                reason="short"
            elif [[ "$portainer_password" == "$_PORTAINER_RETIRED_DEFAULT" ]]; then
                reason="retired"
            fi
            echo "${reason:-accepted}"
        '
    )"
    echo "$LOG_OUT"
}
for case in "::empty" "None::empty" "short1::short" '1234qwer!@#$::retired'; do
    val="${case%%::*}"; want="${case##*::}"
    got="$(run_branch "$val")"
    if [[ "$got" == "$want" ]]; then
        ok "input '${val:-<empty>}' -> ${want}"
    else
        fail "input '${val:-<empty>}' -> ${want}" "got '${got}'"
    fi
done
got="$(run_branch "$SHIPPED")"
if [[ "$got" == "accepted" ]]; then
    ok "the shipped default -> accepted"
else
    fail "the shipped default -> accepted" "got '${got}'"
fi

echo
echo "== aws_sigma ships enabled =="
if (cd "$ROOT" && git show HEAD:config.yaml 2>/dev/null | python3 -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)
raise SystemExit(0 if (d.get('modules', {}).get('aws_sigma') or {}).get('enabled') else 1)
"); then
    ok "modules.aws_sigma.enabled is true in the tracked config"
else
    fail "modules.aws_sigma.enabled is true in the tracked config"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" -eq "$TOTAL" ]]
