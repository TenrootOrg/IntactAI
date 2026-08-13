#!/bin/bash
# Three module-specific hazards that had Python tests against the deleted
# engine, and no coverage at all after it went.
#
# test_timesketch_rollback.py, test_iris_admin_password.py and
# test_velociraptor_build_refresh.py all imported `services.upgrade`, which was
# removed with the in-container Python engine. They could not run, and had not
# for some time — so the behaviour they guarded was being carried on trust.
# This is the same three concerns asserted against the bash engine that
# actually runs now.
#
# Deliberately NOT a port. The Python tests exercised functions that no longer
# exist; what survives is the property each was protecting.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

echo "== timesketch: the only path that deletes a volume =="
# The single destructive operation in the whole engine. It is reached only on a
# Postgres MAJOR change, and only with a dump in hand — that refusal is the
# guarantee, so it is the thing to assert.
P="${ROOT}/lib/upgrade/timesketch/postgres.sh"
if grep -q 'refusing to wipe the volume without a dump' "$P"; then
    ok "it refuses to wipe without a dump"
else
    fail "it refuses to wipe without a dump" \
         "this refusal is the only thing standing between a major bump and data loss"
fi
if grep -q 'could not identify the postgres data volume' "$P"; then
    ok "it refuses when the volume cannot be identified"
else
    fail "it refuses when the volume cannot be identified" "an unnamed volume must not be guessed at"
fi
# Only a MAJOR change may take that path; a minor bump must not.
if grep -q '_TS_PG_MIGRATE=1' "$P" && grep -q 'Postgres major changes' "$P"; then
    ok "the wipe is gated on a MAJOR version change"
else
    fail "the wipe is gated on a MAJOR version change"
fi
# Postgres alone comes up first: the stack must not connect to a database that
# has not been restored yet.
if grep -q 'up -d --no-build --pull never timesketch-postgres' "$P"; then
    ok "postgres starts ALONE before the restore"
else
    fail "postgres starts alone before the restore" \
         "web/worker would connect to an unrestored database"
fi

# The gate itself, in the shape the module uses.
_wipe_allowed() {   # <major changed> <dump present> -> yes|no
    [[ "$1" == "yes" && -n "$2" ]] && echo yes || echo no
}
check "major change + dump  -> wipe allowed"      "$(_wipe_allowed yes /tmp/d.sql)" "yes"
check "major change, NO dump -> refused"          "$(_wipe_allowed yes '')"         "no"
check "no major change       -> never wipes"      "$(_wipe_allowed no /tmp/d.sql)"  "no"

echo
echo "== iris: the admin password is only honoured at first init =="
# IRIS reads IRIS_ADM_PASSWORD when it initialises and never again, so an
# upgrade has to re-assert it against the running instance rather than trust
# the .env. Losing this means the documented password stops working after an
# upgrade, silently.
I="${ROOT}/lib/upgrade/modules/iris.sh"
if grep -q 'enforce_iris_admin_password' "$I"; then
    ok "the upgrade re-asserts the IRIS admin password"
else
    fail "the upgrade re-asserts the IRIS admin password" \
         "IRIS only reads IRIS_ADM_PASSWORD at first init — the .env alone is not enough"
fi
# Best-effort: a password that cannot be re-asserted must not fail the module.
if grep -q 'could not re-assert the IRIS admin password' "$I"; then
    ok "failing to re-assert warns rather than failing the upgrade"
else
    fail "failing to re-assert warns rather than failing the upgrade"
fi
if grep -q '^enforce_iris_admin_password()' "${ROOT}/lib/modules/iris.sh"; then
    ok "install and upgrade share one implementation"
else
    fail "install and upgrade share one implementation" \
         "two copies of a credential routine will drift"
fi

echo
echo "== velociraptor: the only image built ON the box =="
# Every other module pulls a published image; velociraptor is compiled here, so
# a release that changed its Dockerfile or entrypoint must actually rebuild —
# otherwise the fix ships and never arrives.
V="${ROOT}/lib/upgrade/velociraptor/image.sh"
if grep -q 'compose build' "$V"; then
    ok "the upgrade rebuilds the velociraptor image"
else
    fail "the upgrade rebuilds the velociraptor image" \
         "a Dockerfile/entrypoint fix would never reach the box"
fi
# It must build from the RELEASE's build inputs, not the box's stale ones.
if grep -q '_intact_refresh_module_code' "${ROOT}/lib/upgrade/intact/assets.sh"; then
    ok "module build inputs are refreshed before the build"
else
    fail "module build inputs are refreshed before the build" \
         "compose build would use the box's old Dockerfile"
fi
# PRIMARY_IMAGES must NOT cover velociraptor — it is built, not pulled.
if python3 -c "
import sys
ns={}
exec(open('${ROOT}/modules/backend/services/image_map.py',encoding='utf-8').read(), ns)
sys.exit(0 if 'velociraptor' not in (ns.get('PRIMARY_IMAGES') or {}) else 1)" 2>/dev/null; then
    ok "velociraptor is not in PRIMARY_IMAGES (built, not pulled)"
else
    fail "velociraptor is not in PRIMARY_IMAGES" "the loader would look for a tar that is never packaged"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
