#!/bin/bash
# A failed INSTALL must undo itself, not try to restore a version that never
# existed.
#
# Every module registers `u_undo "_u_compose_up_old <m>"` first, so it unwinds
# last. For an upgrade that is right: put the old stack back. For an INSTALL
# there is no old stack -- so the undo tried to `compose up` from a .env that
# had just been restored away and images that were never pulled, failed, and a
# failed undo is reported as "ROLLBACK FAILED -- this module needs manual
# repair".
#
# Observed 2026-08-11: a fresh iris install failed on a missing rabbitmq image
# and told the operator to hand-repair a box on which iris had never existed
# and on which nothing was broken. The install itself failing was correct; the
# instruction was not.
#
# Reproduced live by removing iris, clearing its pin, deleting the rabbitmq
# image and re-running the install: the report now reads "install undone, iris
# is still not installed", exit is still 1, and no containers or networks are
# left behind. Volumes are deliberately kept.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

echo "== the undo branches on the planned action =="

# _u_compose_up_old's decision, in isolation. The real one shells out to
# docker compose; what is under test is which of the two operations it picks.
declare -A PLAN_ACTION=()
_decide() {
    local m="$1"
    if [[ "${PLAN_ACTION[$m]:-}" == install ]]; then echo "down"; else echo "up"; fi
}
PLAN_ACTION[iris]="install"
check "a failed INSTALL tears down"          "$(_decide iris)"       "down"
PLAN_ACTION[iris]="upgrade"
check "a failed UPGRADE restores the old stack" "$(_decide iris)"    "up"
PLAN_ACTION[elk]=""
check "unknown action falls back to restoring"  "$(_decide elk)"     "up"

echo
echo "== the real shared.sh carries that branch =="
S="${ROOT}/lib/upgrade/modules/shared.sh"
if grep -q 'PLAN_ACTION\[\$m\]:-}" == install' "$S"; then
    ok "_u_compose_up_old checks for an install"
else
    fail "_u_compose_up_old checks for an install" "a failed install will demand manual repair again"
fi
if grep -q 'down --remove-orphans' "$S"; then
    ok "it tears down on the install path"
else
    fail "it tears down on the install path"
fi
# No -v. The volumes are empty after a failed first install, but "empty" is a
# guess -- an undo path must never be the thing that deletes a volume.
if grep -qE '_u_compose "\$dir" down --remove-orphans( |$)' "$S" && \
   ! grep -qE 'down .*(-v|--volumes)' "$S"; then
    ok "the teardown keeps volumes (no -v)"
else
    fail "the teardown keeps volumes" "an undo must never delete a volume"
fi

echo
echo "== the report says what actually happened =="
C="${ROOT}/lib/upgrade/core.sh"
if grep -q 'install undone' "$C"; then
    ok "a failed install reports 'install undone'"
else
    fail "a failed install reports 'install undone'"
fi
if grep -q 'is still not installed' "$C"; then
    ok "it says the module is still not installed"
else
    fail "it says the module is still not installed"
fi
# The heading used to assert "these are back on their previous version", which
# is false for an install and contradicted the line printed under it.
if grep -q 'undone, the box is as it was' "${ROOT}/lib/upgrade/report.sh"; then
    ok "the rolled-back heading is neutral"
else
    fail "the rolled-back heading is neutral" "it contradicts the install line beneath it"
fi
# The distinction that matters: undone is NOT the same bucket as needs-repair.
if grep -q 'UPGRADE_FAILED+=("${module} — ${U_LABEL} (rc=${U_RC}) AND ROLLBACK FAILED' "$C"; then
    ok "a genuinely failed unwind still demands manual repair"
else
    fail "a genuinely failed unwind still demands manual repair" \
         "the real needs-repair case must not have been softened away"
fi

echo "== a rollback must never leave Elasticsearch unable to start =="
# ES migrates its data directory on first start at a new version and then
# refuses to open it on an older one. So restoring elk's .env is destructive
# exactly when the upgrade got far enough to start ES. Observed 2026-08-12 on a
# real 0726 -> 0811 upgrade: ES came up healthy at 9.4.4, the elk_setup
# container failed for an unrelated reason, the pins rolled back to 9.4.2, and
# Elasticsearch could not start at all afterwards -- the rollback left the box
# worse than the failure.
E="${ROOT}/lib/upgrade/modules/elk.sh"
if grep -q '_u_elk_restore_env' "$E"; then
    ok "elk's undo goes through the downgrade guard"
else
    fail "elk's undo goes through the downgrade guard" \
         "a plain restore_file_from_backup bricks Elasticsearch"
fi
if grep -q 'cannot downgrade a node from version' "$E"; then
    ok "the guard records ES's own error text"
else
    fail "the guard records ES's own error text"
fi
# Only the version pins are held forward; every other key still reverts.
if grep -q 'restore_file_from_backup "\$envf" "\$bak"' "$E"; then
    ok "the rest of the .env is still restored"
else
    fail "the rest of the .env is still restored" "holding the whole file would strand other edits"
fi

# Functional: the decision, both ways.
_decide() {
    local img_tag="$1" target="$2"
    [[ "docker.elastic.co/elasticsearch/elasticsearch:${img_tag}" == *":${target}" ]] \
        && echo hold || echo rollback
}
check "ES already at the target -> hold the pins forward" "$(_decide 9.4.4 9.4.4)" "hold"
check "ES never reached the target -> normal rollback"    "$(_decide 9.4.2 9.4.4)" "rollback"

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
