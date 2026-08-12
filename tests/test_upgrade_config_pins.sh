#!/bin/bash
# Every module's pin key must exist in the config.yaml this release ships.
#
# _intact_validate_config_pins maps each module to the `versions:` key that
# holds its pin, and REFUSES THE UPGRADE when the key is absent. So a wrong
# entry in that map is not a cosmetic error -- it stops the platform module
# dead, before anything is swapped.
#
# That is what happened on 2026-08-12. The map said:
#
#     [aws_sigma]=cloudtrail   [o365rc]=dfir_o365rc
#
# which are the PRE-RENAME names. _intact_config_migrations renames
# versions.cloudtrail -> versions.aws_sigma and runs at intact.sh:59 --
# immediately BEFORE this validation at :60. So the check demanded the very
# keys the step before it had just removed, and any box with aws_sigma or
# o365rc enabled could not upgrade:
#
#     config.yaml is missing pin(s) this release needs:
#       - aws_sigma: no versions.cloudtrail in config.yaml
#
# It took intact's rollback down with it, leaving "needs manual repair".
#
# Nothing caught it because both halves were self-consistent: the map matched
# the code that read it, and the migration matched the config. Only comparing
# the map against the shipped config.yaml -- what this test does -- crosses
# that gap.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${ROOT}/config.yaml"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

[[ -f "$CFG" ]] || { echo "  no config.yaml at $CFG"; exit 1; }

# The map, read out of the real source rather than restated here -- a copy
# would drift and the test would keep passing while the product broke.
mapfile -t PAIRS < <(
    sed -n '/declare -A _primary_key=(/,/^    )/p' "${ROOT}/lib/upgrade/intact/config.sh" \
    | grep -oE '\[[a-z_0-9]+\]=[a-z_0-9]+' | tr -d '[]' | tr '=' ' '
)

echo "== every _primary_key resolves against the shipped config.yaml =="
(( ${#PAIRS[@]} )) || fail "the _primary_key map could be parsed" "sed/grep found nothing"

for pair in "${PAIRS[@]}"; do
    mod="${pair%% *}"; key="${pair##* }"
    if python3 -c "
import sys, yaml
v = (yaml.safe_load(open('$CFG')) or {}).get('versions') or {}
sys.exit(0 if '$key' in v and v['$key'] not in (None, '') else 1)
" 2>/dev/null; then
        ok "${mod} -> versions.${key}"
    else
        fail "${mod} -> versions.${key}" \
             "that key is not in config.yaml; the upgrade refuses with 'no versions.${key}'"
    fi
done

echo
echo "== the pre-rename names are a FALLBACK, never the primary =="
# Keeping them readable is right -- an un-migrated box may still have them --
# but a primary entry pointing at one is the bug this file exists for.
for legacy in cloudtrail dfir_o365rc; do
    if sed -n '/declare -A _primary_key=(/,/^    )/p' \
         "${ROOT}/lib/upgrade/intact/config.sh" | grep -q "=${legacy}\b"; then
        fail "_primary_key does not point at '${legacy}'" \
             "that is the pre-rename key; migrations remove it one step earlier"
    else
        ok "_primary_key does not point at '${legacy}'"
    fi
done
if grep -q '_legacy_key\[\$m\]' "${ROOT}/lib/upgrade/intact/config.sh"; then
    ok "an un-migrated box can still fall back to the old name"
else
    fail "an un-migrated box can still fall back to the old name"
fi

echo
echo "== validation still runs AFTER the migration that renames these =="
# If these ever swap order, the fallback above becomes the only thing working
# and the primary lookup silently stops being exercised.
mig=$(grep -n "apply config.yaml schema migrations" "${ROOT}/lib/upgrade/intact/intact.sh" | cut -d: -f1)
val=$(grep -n "validate config.yaml pins" "${ROOT}/lib/upgrade/intact/intact.sh" | cut -d: -f1)
if [[ -n "$mig" && -n "$val" && "$mig" -lt "$val" ]]; then
    ok "migrations (line ${mig}) run before validation (line ${val})"
else
    fail "migrations run before validation" "got migrate=${mig:-?} validate=${val:-?}"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
