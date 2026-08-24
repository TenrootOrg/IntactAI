#!/bin/bash
# Reported for real (ClickUp, 2026-08-19): an operator downloaded a release,
# `cd`ed into it (the natural thing to do with a folder you just extracted),
# and typed the online-upgrade command from there. Two things went wrong in
# sequence, neither of them a mistake a careful reading of the README would
# have prevented:
#
#   1. `--root ./intact` -- the real appliance is a SIBLING of the release
#      folder, not something inside it, so from in there it is `../intact`.
#   2. Once corrected to `--root ../intact`, the command still had no release
#      tag on it -- "Nothing to upgrade to: give a release tag or --package."
#
# Both are now handled: (1) the appliance-detection error suggests the
# sibling directory by name when one exists and looks real; (2) a missing tag
# defaults to the release this checkout IS (its own VERSION file), since
# there is no legitimate scenario where those differ.
#
# This runs the REAL scripts/upgrade.sh, not a stub -- a fake reproduction of
# the appliance-detection and argument-validation logic would only prove the
# fake agrees with itself.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

RELEASE="${SCRATCH}/intact-20260899"
APPLIANCE="${SCRATCH}/intact"

# The release checkout: just what upgrade.sh needs to get through the
# checkout-completeness and appliance-detection checks -- scripts/ + lib/ +
# its own VERSION, not the whole repo (modules/, tests/, .git/ add nothing
# here and cost real time to copy).
mkdir -p "$RELEASE"
cp -r "${ROOT}/scripts" "${ROOT}/lib" "$RELEASE/"
echo "intact-20260899" > "${RELEASE}/VERSION"

# The real appliance, as a SIBLING of the release -- exactly the layout the
# README's own download step produces.
mkdir -p "${APPLIANCE}/modules"
: > "${APPLIANCE}/install.sh"
: > "${APPLIANCE}/config.yaml"

echo "== wrong relative path (the operator's actual first command) =="
out="$(cd "$RELEASE" && bash scripts/upgrade.sh --root ./intact 2>&1 || true)"
if grep -q "Found a real appliance one level up instead:" <<< "$out"; then
    ok "the error suggests looking one level up"
else
    fail "the error suggests looking one level up" "$out"
fi
if grep -qF "Try:  --root ${APPLIANCE}" <<< "$out"; then
    ok "the suggested --root is the exact, correct, absolute path"
else
    fail "the suggested --root is the exact, correct, absolute path" "$out"
fi

echo
echo "== corrected path, but the tag was still never typed =="
out="$(cd "$RELEASE" && timeout 15 bash scripts/upgrade.sh --root ../intact 2>&1 || true)"
if grep -qF "using intact-20260899, the release this checkout is" <<< "$out"; then
    ok "the missing tag defaults to this checkout's own VERSION"
else
    fail "the missing tag defaults to this checkout's own VERSION" "$out"
fi
if grep -q "Nothing to upgrade to" <<< "$out"; then
    fail "does NOT still hit the old hard error" "$out"
else
    ok "does NOT still hit the old hard error"
fi
if grep -q "needs root" <<< "$out"; then
    ok "gets past argument validation into the real run (stops on 'needs root', the correct next wall)"
else
    fail "gets past argument validation into the real run" "$out"
fi

echo
echo "== a release with no VERSION file still gets the original, honest error =="
rm -f "${RELEASE}/VERSION"
out="$(cd "$RELEASE" && bash scripts/upgrade.sh --root ../intact 2>&1 || true)"
if grep -q "Nothing to upgrade to: give a release tag or --package." <<< "$out"; then
    ok "no VERSION to infer from -> the original error, not a blank/wrong tag"
else
    fail "no VERSION to infer from -> the original error, not a blank/wrong tag" "$out"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
