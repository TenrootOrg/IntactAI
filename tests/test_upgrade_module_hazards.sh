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
# ...and a tag that already exists must NOT short-circuit the release's image.
#
# The tag is velociraptor-server:<UPSTREAM version>, but the image also bakes in
# our bundled_artifacts, entrypoint.sh and client binaries. Change an artifact
# without bumping upstream and the tag is identical while the contents are not.
# _velo_resolve_image returned early on _u_image_present, so the packaged image
# was never loaded: an appliance upgraded 0726 -> 0811 -> 0813 still logged
# "invalid token '#'" for IRIS.Sync.Asset and tenRoot.IRIS.Timeline.Add on every
# boot, months after 8bfdbc0 fixed them, because velociraptor stayed 0.77.1 and
# `resolve` matched the tag and skipped in 1s.
#
# Assert the ORDER: the package tar is consulted before image presence.
_tar_ln="$(grep -n 'local tar=' "$V" | head -1 | cut -d: -f1)"
_present_ln="$(grep -n '_u_image_present "\$ref" && {\|if _u_image_present "\$ref"; then' "$V" | head -1 | cut -d: -f1)"
if [[ -n "$_tar_ln" && -n "$_present_ln" ]] && (( _tar_ln < _present_ln )); then
    ok "the packaged image is preferred over an existing tag"
else
    fail "the packaged image is preferred over an existing tag" \
         "a matching tag skips the load, so artifact fixes never reach the box"
fi
# And it must say so, rather than silently swapping the image underneath.
if grep -q 'does not change when our artifacts do' "$V"; then
    ok "and the log explains why a present image is reloaded"
else
    fail "and the log explains why a present image is reloaded"
fi
# A stale image with no usable tar is still usable, but must be flagged.
if grep -q 'bundled artifacts may be older than this release' "$V"; then
    ok "keeping a stale image warns about its baked content"
else
    fail "keeping a stale image warns about its baked content" \
         "silently reusing it is what hid this for months"
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

echo "== a module upgrade must pin config.yaml, not just its .env =="
# `--only elk` is supported and skips the intact module that would merge the
# package's pins into config.yaml. The module .env then moves while config.yaml
# does not -- and update_env_files (install.sh, change_ip.sh) re-derives every
# .env FROM config.yaml, so the next repair silently REGRESSES the pin.
#
# For Elasticsearch that is fatal: it refuses to open a data directory a newer
# version wrote. Observed on a live box 2026-08-13 — ES running 9.4.6 with both
# pins reading 9.4.5, one recreate away from being unstartable.
for pair in "elk:modules/elk.sh" "iris:modules/iris.sh" "volweb:modules/volweb.sh" \
            "portainer:modules/portainer.sh" "timesketch:timesketch/timesketch.sh" \
            "velociraptor:velociraptor/velociraptor.sh" "plaso:modules/plaso.sh" \
            "aws_sigma:modules/aws_sigma.sh"; do
    mod="${pair%%:*}"; rel="${pair#*:}"
    if grep -q "_pin_module_version" "${ROOT}/lib/upgrade/${rel}"; then
        ok "${mod} pins config.yaml"
    else
        fail "${mod} pins config.yaml" \
             "its .env would move while config.yaml stays stale; change_ip.sh then regresses it"
    fi
done

echo
echo "== elk's host preflight must not fail merely because it runs in a container =="
# The dashboard runs the engine inside a helper container
# (upgrade_launcher.py: docker run -d --name intact-upgrade-runner-<run_id>).
# A container has no systemd, so `systemctl is-system-running` answers "offline"
# there however healthy the host is -- and elk is the ONLY module that calls
# preflight_host_check. Left fatal, that rolled elk back on EVERY dashboard
# upgrade while the same package applied from a shell succeeded. Observed
# 2026-08-13 on a real box: "systemd state = offline (cgroup-unit creation will
# fail)" -> "elk - host preflight (rc=1); restored to 9.4.2", with the host
# itself reporting `running` at that moment.
P="${ROOT}/lib/modules/shared.sh"
if grep -q '/.dockerenv' "$P"; then
    ok "the systemd probe is skipped when running in a container"
else
    fail "the systemd probe is skipped when running in a container" \
         "elk cannot be upgraded from the dashboard without this"
fi
if grep -q "skipping the systemd probe" "$P"; then
    ok "and it says so rather than passing silently"
else
    fail "and it says so rather than passing silently" \
         "a check that was not performed must not read as a check that passed"
fi
# The probe must still exist for the host path -- deleting it would be the
# other wrong fix.
if grep -q 'systemctl is-system-running' "$P"; then
    ok "the probe still runs on a real host"
else
    fail "the probe still runs on a real host" "it exists for the 2026-06-15 cgroup failure"
fi

echo
echo "== timesketch: an empty alembic table blocks UPGRADES, not INSTALLS =="
# The refusal exists because on an EXISTING database an empty alembic_version
# means the bootstrap did not take, and stamping head would mark an unmigrated
# schema as migrated. But on a FRESH install empty is the correct state -- the
# database was created minutes ago and alembic must walk base -> head to build
# the schema.
#
# Applied to both, it made timesketch impossible to install through the engine:
# `bootstrap alembic if untracked` runs before the stack is up, so on an install
# it no-ops ("no timesketch-web container yet"), the only re-stamp afterwards is
# gated on a Postgres MAJOR migration, and the run rolled itself back with
#   ↩ timesketch — apply database migrations (rc=1); install undone
# Observed 2026-08-14 enabling timesketch and applying a full release.
S="${ROOT}/lib/upgrade/timesketch/schema.sh"
if grep -q 'U_FROM:-.*== "not installed"' "$S"; then
    ok "a fresh install is allowed to migrate from base"
else
    fail "a fresh install is allowed to migrate from base" \
         "without this timesketch cannot be installed by the engine at all"
fi
if grep -q 'refusing to upgrade the schema' "$S"; then
    ok "an UPGRADE with an empty alembic table is still refused"
else
    fail "an UPGRADE with an empty alembic table is still refused" \
         "that refusal is what stops a stamp-then-upgrade masking an unmigrated schema"
fi
# The distinction must be on the install/upgrade flag, not on something
# incidental like whether migrations were staged.
#
# Assert the STRUCTURE, not the proximity: this was a `grep -B4` around the
# refusal until the fresh-install branch grew a populated-schema case between
# the two and pushed them ~30 lines apart. The behaviour had not changed; the
# assertion was just measuring distance. Scope to the empty-alembic block and
# ask whether it branches on U_FROM at all.
if sed -n '/if \[\[ -z "\$before" \]\]; then/,/^    fi$/p' "$S" | grep -q 'U_FROM:-.*== "not installed"'; then
    ok "the two cases are told apart by U_FROM"
else
    fail "the two cases are told apart by U_FROM"
fi

echo
echo "== an UNDONE INSTALL must not leave the stack running =="
# _ts_bring_back_up brought the stack up unconditionally. Right for a failed
# UPGRADE (the box had timesketch before and must still have it after); wrong
# for a failed INSTALL, where `up -d` starts a stack the operator never had --
# while the report says "install undone, timesketch is still not installed".
# Observed 2026-08-14: 8 containers running, 4 volumes, TIMESKETCH_VERSION
# stamped in .env AND config.yaml, over a database whose migration had just
# failed. The shared unwind (_u_compose_up_old) has branched on
# PLAN_ACTION == install for a while; this module's own undo had not.
P="${ROOT}/lib/upgrade/timesketch/postgres.sh"
if grep -q 'PLAN_ACTION\[timesketch\]:-.*== install' "$P"; then
    ok "the timesketch undo branches on install"
else
    fail "the timesketch undo branches on install" \
         "a failed install would leave a live stack the report calls uninstalled"
fi
# It must STOP after the down on that branch -- not fall through to `up -d`.
if sed -n '/PLAN_ACTION\[timesketch\]:-.*== install/,/^    fi/p' "$P" | grep -q 'return 0'; then
    ok "and stops after the teardown instead of bringing it up"
else
    fail "and stops after the teardown instead of bringing it up"
fi
# The upgrade path must still restore the stack.
if grep -q 'up -d --no-build --pull never' "$P"; then
    ok "a failed UPGRADE still brings the old stack back"
else
    fail "a failed UPGRADE still brings the old stack back" \
         "that is the whole point of the undo on an upgrade"
fi

echo
echo "== a fresh install must STAMP an already-built schema, not replay it =="
# timesketch-web builds the schema itself on first start (create_all), which is
# why alembic_version is empty. Replaying base -> head over it dies on the first
# ALTER: (psycopg2.errors.DuplicateColumn) column "group_id" of relation
# "searchindex_accesscontrolentry" already exists -- observed 2026-08-14 with
# 117 tables present. Empty alembic_version does NOT imply a bare database.
S="${ROOT}/lib/upgrade/timesketch/schema.sh"
if grep -q '_ts_schema_is_populated()' "$S"; then
    ok "there is a probe distinguishing a bare database from a built one"
else
    fail "there is a probe distinguishing a bare database from a built one"
fi
if sed -n '/U_FROM:-.*== "not installed"/,/^        else/p' "$S" | grep -q 'if _ts_schema_is_populated; then'; then
    ok "the fresh-install branch consults it before choosing a remedy"
else
    fail "the fresh-install branch consults it before choosing a remedy" \
         "a populated schema would be migrated from base and die on DuplicateColumn"
fi
if sed -n '/if _ts_schema_is_populated; then/,/^            fi/p' "$S" | grep -q 'tsctl db stamp -d /migrations head'; then
    ok "a populated schema is stamped at head"
else
    fail "a populated schema is stamped at head"
fi
# A genuinely bare database must still be migrated, or a real install builds nothing.
if grep -q 'is bare — running the migrations from base' "$S"; then
    ok "a bare database is still migrated from base"
else
    fail "a bare database is still migrated from base"
fi
# The refusal on a pre-existing database must survive all of this.
if grep -q 'refusing to upgrade the schema' "$S"; then
    ok "an existing install with empty alembic_version is still refused"
else
    fail "an existing install with empty alembic_version is still refused" \
         "that guard is what stops a silent stamp over an unmigrated schema"
fi

echo
echo "== the bare-vs-built decision must survive the create_all race =="
# timesketch-web builds the schema at startup, concurrently with the probe, so a
# pre-check alone cannot be right. One run: 12:07:27 "the database is bare",
# 12:07:36 DuplicateColumn on group_id. Decide from the FAILURE too, when the
# database has stopped moving.
S="${ROOT}/lib/upgrade/timesketch/schema.sh"
BLK="$(sed -n '/tsctl db upgrade -d \/migrations/,/^    fi$/p' "$S")"
if printf '%s' "$BLK" | grep -q 'tsctl db stamp -d /migrations head'; then
    ok "a failed upgrade can still recover by stamping"
else
    fail "a failed upgrade can still recover by stamping" \
         "the pre-check alone loses the race and the install dies on DuplicateColumn"
fi
# Recovery is gated on all three: fresh install, nothing applied, schema present.
for g in 'U_FROM:-.*== "not installed"' '\-z "\$(_ts_alembic_revision)"' '_ts_schema_is_populated'; do
    if printf '%s' "$BLK" | grep -q "$g"; then
        ok "recovery is gated on: $g"
    else
        fail "recovery is gated on: $g"
    fi
done
# A partial migration must NOT be stamped over.
if printf '%s' "$BLK" | grep -q 'log_error "  tsctl db upgrade failed"'; then
    ok "a non-empty alembic_version still fails the run"
else
    fail "a non-empty alembic_version still fails the run" \
         "stamping a half-migrated schema buries the mismatch"
fi

echo
echo "== a probe answering 200 must not certify a crash-looping stack =="
# timesketch installed, reported "health: timesketch is UP (timesketch-web HTTP
# 200)" and "0 error(s)" -- while intact_timesketch_nginx, the module's own
# front door, was in Restarting(1) on an unreadable certificate. u_containers_of
# lists four timesketch containers and nginx is not one of them, so the gate
# could not have seen it. Observed 2026-08-14.
H="${ROOT}/lib/upgrade/health/core.sh"
C="${ROOT}/lib/upgrade/core.sh"
if grep -q 'u_crashlooping_of()' "$H"; then
    ok "there is a crash-loop probe"
else
    fail "there is a crash-loop probe"
fi
# It must enumerate from Docker's labels, not the hand-maintained list that
# omitted nginx in the first place.
if grep -A4 'u_crashlooping_of()' "$H" | grep -q 'com.docker.compose.project'; then
    ok "it enumerates by compose project label, not u_containers_of"
else
    fail "it enumerates by compose project label, not u_containers_of" \
         "the hand-maintained list is exactly what missed intact_timesketch_nginx"
fi
if grep -A4 'u_crashlooping_of()' "$H" | grep -q 'status=restarting'; then
    ok "it filters on restarting"
else
    fail "it filters on restarting"
fi
# The 'up' arm must consult it and downgrade rather than log success blindly.
UPARM="$(sed -n '/^            up)/,/^                ;;/p' "$C")"
if printf '%s' "$UPARM" | grep -q 'u_crashlooping_of'; then
    ok "the up verdict consults the crash-loop probe"
else
    fail "the up verdict consults the crash-loop probe" \
         "otherwise a 200 from the primary service certifies the whole stack"
fi
if printf '%s' "$UPARM" | grep -q 'verdict="degraded"'; then
    ok "a crash-looping stack downgrades to degraded"
else
    fail "a crash-looping stack downgrades to degraded"
fi
# Degraded, NOT down: the service is answering, so rolling back is
# disproportionate -- but it must still reach the report.
if printf '%s' "$UPARM" | grep -q 'UPGRADE_DEGRADED+='; then
    ok "and is recorded in the report rather than silently logged"
else
    fail "and is recorded in the report rather than silently logged" \
         "the whole failure was that the report said 0 errors"
fi
if printf '%s' "$UPARM" | grep -q 'U_FAILED=1'; then
    fail "a crash-loop does not trigger a rollback" \
         "the primary service answers; unwinding a working upgrade is worse"
else
    ok "a crash-loop does not trigger a rollback"
fi

echo
echo "== the Kibana data view must actually be reachable =="
# Kibana serves TLS itself (SERVER_SSL_ENABLED=true), so the probe's
# http://127.0.0.1:5601 could never return 200 and the data view was never
# re-asserted on any box. It read as a timeout, not a wrong scheme:
#   17:57:46 "Kibana is now available" / 17:58:59 "did not answer in 120s".
E="${ROOT}/lib/upgrade/modules/elk.sh"
KB="$(sed -n 's/^\s*local kb="\(.*\)"$/\1/p' "$E" | head -1)"
if [[ "$KB" == https://* ]]; then
    ok "the Kibana probe speaks https (${KB})"
else
    fail "the Kibana probe speaks https" "got '${KB}' — a TLS port never answers plain HTTP"
fi
# Self-signed cert: without -k every request fails the handshake.
if sed -n '/_u_kibana_data_view()/,/^}/p' "$E" | grep -q 'curl -sk'; then
    ok "and passes -k for the self-signed cert"
else
    fail "and passes -k for the self-signed cert"
fi
# The two implementations must assert the SAME data view, or fixing the scheme
# just creates a second near-duplicate in Discover.
SH_TITLE="$(sed -n 's/^\s*local view_title="\(.*\)"$/\1/p' "$E" | head -1)"
PY_TITLE="$(sed -n 's/^DATA_VIEW_TITLE = "\(.*\)"$/\1/p' "${ROOT}/modules/backend/services/kibana_init.py" | head -1)"
if [[ -n "$SH_TITLE" && "$SH_TITLE" == "$PY_TITLE" ]]; then
    ok "elk.sh and kibana_init.py agree on the title ('${SH_TITLE}')"
else
    fail "elk.sh and kibana_init.py agree on the title" \
         "elk.sh='${SH_TITLE}' kibana_init.py='${PY_TITLE}' — divergence duplicates the view"
fi
# 409 means the backend's initialiser won the race; that is success, not failure.
if sed -n '/_u_kibana_data_view()/,/^}/p' "$E" | grep -q '"409"'; then
    ok "a 409 from a concurrent creator counts as success"
else
    fail "a 409 from a concurrent creator counts as success"
fi
# The wait only mattered once the request could succeed at all.
DL="$(sed -n 's/^\s*local deadline=\([0-9]*\)$/\1/p' "$E" | head -1)"
if [[ -n "$DL" ]] && (( DL >= 300 )); then
    ok "the readiness wait allows for a slow/swapping box (${DL}s)"
else
    fail "the readiness wait allows for a slow/swapping box" \
         "got '${DL}'; Kibana took ~10min from container start on a swapping box"
fi
# It must stay best-effort: a missing data view may never fail an upgrade.
if grep -q '_u_kibana_data_view || log_warn' "$E"; then
    ok "a missing data view still only warns"
else
    fail "a missing data view still only warns"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
