#!/bin/bash
# The release CI switch: .github/release-ci.conf decides which of the two
# release workflows builds a tag.
#
# WHY THIS EXISTS. Both workflows are `release: published` triggered, so both
# always start; a `gate` job in each reads the conf and the loser skips its
# build. That gate had no `ref:` on its checkout, and on a release event
# checkout's default ref is THE TAG. So each gate read release-ci.conf out of
# the tag's tree -- and every tag cut before the file existed carries no conf at
# all, so both gates fell through to the default no matter what main said.
# Editing the switch, committing and pushing changed nothing, which is exactly
# what the file instructs you to do. Reported from the field as "the ci switch
# is broken its always trigger both".
#
# The asserts are the properties that failure violated, and the polarity that
# makes the two workflows mutually exclusive.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

ASSETS="${ROOT}/.github/workflows/build-release-assets.yml"
LEGACY="${ROOT}/.github/workflows/build-release-package.yml"
CONF="${ROOT}/.github/release-ci.conf"

echo "== the conf exists and carries the key =="
if [[ -f "$CONF" ]]; then ok "release-ci.conf is present"
else fail "release-ci.conf is present" "no conf means both gates take the default"; fi
if grep -qE '^[[:space:]]*is_new_CI[[:space:]]*=' "$CONF"; then
    ok "is_new_CI is set ($(grep -E '^[[:space:]]*is_new_CI' "$CONF" | tr -d ' '))"
else
    fail "is_new_CI is set"
fi

echo
echo "== the gate reads the DEFAULT BRANCH, not the release tag =="
# This is the bug. Without an explicit ref the conf is read from the tag, and
# the switch on main becomes decorative.
for pair in "assets:$ASSETS" "legacy:$LEGACY"; do
    w="${pair%%:*}"; f="${pair#*:}"
    ref="$(python3 -c "
import yaml,sys
d=yaml.safe_load(open('$f'))
s=d['jobs']['gate']['steps'][0]
print((s.get('with') or {}).get('ref',''))" 2>/dev/null)"
    if [[ "$ref" == *default_branch* ]]; then
        ok "${w} gate checks out the default branch"
    else
        fail "${w} gate checks out the default branch" \
             "ref='${ref}' -- on a release event an empty ref means THE TAG, and a tag without the conf ignores the switch entirely"
    fi
done

echo
echo "== polarity: the two gates are exact opposites =="
# Extracted from the workflows rather than restated, so a future edit to one
# side alone fails here instead of at release time.
_polarity() {   # <file> -> the value of NEW under which it sets run=yes
    grep -oE '\[ "\$NEW" = "(true|false)" \][[:space:]]*&&[[:space:]]*echo "run=yes"' "$1" \
        | grep -oE '"(true|false)"' | head -1 | tr -d '"'
}
pa="$(_polarity "$ASSETS")"; pl="$(_polarity "$LEGACY")"
[[ "$pa" == "true"  ]] && ok "per-module builds when is_new_CI is TRUE" \
    || fail "per-module builds when is_new_CI is TRUE" "got '${pa}'"
[[ "$pl" == "false" ]] && ok "legacy builds when is_new_CI is FALSE" \
    || fail "legacy builds when is_new_CI is FALSE" "got '${pl}'"
if [[ -n "$pa" && -n "$pl" && "$pa" != "$pl" ]]; then
    ok "the two are mutually exclusive"
else
    fail "the two are mutually exclusive" "both build on NEW='${pa}' -- two jobs uploading to one release"
fi

echo
echo "== the gate's parser, exercised for real =="
# The same grep the workflows run, against the same shapes a human might type.
_decide() {     # <conf body> -> the NEW value the gate would compute
    local d; d="$(mktemp -d)"; printf '%s\n' "$1" > "$d/conf"
    local NEW=true
    grep -qiE '^[[:space:]]*is_new_CI[[:space:]]*=[[:space:]]*(false|no|0)[[:space:]]*$' "$d/conf" && NEW=false
    rm -rf "$d"; printf '%s' "$NEW"
}
_case() {       # <label> <conf body> <expected NEW>
    local got; got="$(_decide "$2")"
    [[ "$got" == "$3" ]] && ok "$1" || fail "$1" "expected NEW=$3, got NEW=$got"
}
_case "is_new_CI = TRUE  -> per-module"          "is_new_CI = TRUE"  true
_case "is_new_CI = FALSE -> legacy"              "is_new_CI = FALSE" false
_case "lowercase false is honoured"              "is_new_CI = false" false
_case "no/0 are honoured"                        "is_new_CI=0"       false
_case "sloppy spacing is honoured"              "  is_new_CI   =   FALSE   " false
_case "an unset key defaults to per-module"      "# nothing here"    true
_case "a commented-out switch does NOT count"    "# is_new_CI = FALSE" true
_case "FALSE with a trailing comment does NOT match" "is_new_CI = FALSE # legacy" true

echo
echo "== both build jobs are gated, and by-hand runs bypass the switch =="
for pair in "assets:$ASSETS" "legacy:$LEGACY"; do
    w="${pair%%:*}"; f="${pair#*:}"
    n="$(grep -c "needs.gate.outputs.run == 'yes'" "$f")"
    if (( n >= 1 )); then ok "${w}: its build job honours the gate"
    else fail "${w}: its build job honours the gate" "an ungated job builds on every release"; fi
    if grep -q "github.event_name == 'workflow_dispatch' || needs.gate.outputs.run" "$f"; then
        ok "${w}: a manual run ignores the switch"
    else
        fail "${w}: a manual run ignores the switch" \
             "you could not produce the other shape for one tag without flipping the file"
    fi
done

echo
echo "== the stood-down run announces itself =="
# Both runs appear in the Actions list on every release -- GitHub cannot read a
# file before starting one. The loser must say so, or it reads as a run that
# needs cancelling, and a cancelled run is indistinguishable from a failed
# release in the history.
for pair in "assets:$ASSETS" "legacy:$LEGACY"; do
    w="${pair%%:*}"; f="${pair#*:}"
    if grep -q 'STOOD DOWN' "$f"; then ok "${w}: says STOOD DOWN when it is not the builder"
    else fail "${w}: says STOOD DOWN when it is not the builder"; fi
done
if grep -q 'nothing to cancel' "$CONF"; then
    ok "the conf tells you not to cancel the other run"
else
    fail "the conf tells you not to cancel the other run" \
         "it previously claimed 'exactly one runs, always', which is false and is what prompted the manual cancelling"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
