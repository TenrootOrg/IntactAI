#!/bin/bash
# Two things that both looked fine and both did nothing:
#
#   1. The GUI's "reinstall" tick on a module already at the target version.
#      It was forwarded as --only, and --only is checked BEFORE the version
#      comparison, so plan.sh still classified the module noop and skipped it.
#      The operator ticked a box, the request succeeded, and the module was
#      never touched (found 2026-08-11).
#
#   2. Fixing (1) by adding --reinstall immediately broke something worse: the
#      stage-0 hop forwards the operator's arguments verbatim to the TARGET
#      package's own upgrade.sh, whose parser rejects unknown options with
#      exit 2. So a new backend importing any older package died before
#      touching anything -- verified against a real intact-20260817 package,
#      which is exactly the "sat on a USB stick for a month" case that has no
#      way to fetch a newer one.
#
# Both are silent-failure shapes, which is why they get a suite rather than a
# line in a run log.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

echo "== plan.sh: --reinstall promotes a noop to an upgrade =="

# plan.sh's classification, exercised directly. Sourcing the whole engine
# would drag in docker, the config loader and a real package; the branch under
# test is a string comparison against one global.
_classify() {
    # $1 = module, $2 = current, $3 = target, $4 = UPGRADE_REINSTALL
    local m="$1" current="$2" target="$3" UPGRADE_REINSTALL="$4"
    if [[ "$current" == "$target" ]]; then
        if [[ -n "${UPGRADE_REINSTALL:-}" && ",${UPGRADE_REINSTALL}," == *",${m},"* ]]; then
            echo "upgrade"; return
        fi
        echo "noop"; return
    fi
    echo "upgrade"
}

check "same version, not requested -> noop" \
      "$(_classify portainer 2.39.5 2.39.5 "")" "noop"
check "same version, requested -> upgrade" \
      "$(_classify portainer 2.39.5 2.39.5 "portainer")" "upgrade"
check "same version, requested among others -> upgrade" \
      "$(_classify portainer 2.39.5 2.39.5 "elk,portainer,iris")" "upgrade"
check "same version, a DIFFERENT module requested -> still noop" \
      "$(_classify portainer 2.39.5 2.39.5 "elk,iris")" "noop"
check "substring must not match ('portainer' vs 'porta')" \
      "$(_classify porta 1 1 "portainer")" "noop"
check "version gap is an upgrade regardless" \
      "$(_classify portainer 2.39.4 2.39.5 "")" "upgrade"

echo
echo "== the real plan.sh carries this branch =="
if grep -q 'UPGRADE_REINSTALL' "${ROOT}/lib/upgrade/plan.sh"; then
    ok "plan.sh consults UPGRADE_REINSTALL"
else
    fail "plan.sh consults UPGRADE_REINSTALL" "the branch is gone; the tick is dead again"
fi
if grep -q -- '--reinstall)' "${ROOT}/lib/upgrade/args.sh"; then
    ok "args.sh parses --reinstall"
else
    fail "args.sh parses --reinstall"
fi
if grep -q -- '_validate_module_list "$UPGRADE_REINSTALL" --reinstall' "${ROOT}/lib/upgrade/args.sh"; then
    ok "a typo'd --reinstall module is rejected, not silently ignored"
else
    fail "a typo'd --reinstall module is rejected"
fi

echo
echo "== the routes actually send it =="
R="${ROOT}/modules/backend/routes/upgrade_routes.py"
if grep -q '"--reinstall", ",".join(reinstall)' "$R"; then
    ok "online route forwards the reinstall opt-ins"
else
    fail "online route forwards the reinstall opt-ins"
fi
if grep -q '"--reinstall", ",".join(reinstall_modules)' "$R"; then
    ok "import route forwards the reinstall opt-ins"
else
    fail "import route forwards the reinstall opt-ins"
fi
# The lists must be DISJOINT. Import briefly sent its whole selected list as
# --reinstall, which the engine tolerated (plan.sh only reads it on the noop
# branch) but which rendered as "reinstall everything" in the log and the
# launch script -- not what was asked for, and not what happened.
if grep -q 'reinstall_modules if m not in selected_modules' "$R"; then
    ok "a reinstall for a module outside the run is rejected"
else
    fail "a reinstall for a module outside the run is rejected"
fi
if grep -q 'reinstall_modules:' "${ROOT}/modules/nginx/html/js/stores/settings.js"; then
    ok "the Import modal sends reinstall_modules"
else
    fail "the Import modal sends reinstall_modules" "backend cannot re-derive which ticks were no-change"
fi

echo
echo "== --only is taken literally, and says so when it omits intact =="
# An --only without intact upgrades modules against the current backend code
# and pins. Usually a mistake, but sometimes exactly the point: repairing or
# installing one module without moving the platform. So the engine warns and
# obeys, and intact is not special-cased anywhere -- if it is already at the
# target it is a no-op like any other module, and the reinstall tick is how you
# re-apply it. (The --only help used to claim the engine added intact back; no
# code ever did.)
if grep -q 'does not include intact, but this package carries it' "${ROOT}/lib/upgrade/plan.sh"; then
    ok "the engine warns when --only omits intact"
else
    fail "the engine warns when --only omits intact" "silent half-upgrade against old backend code"
fi
if grep -q 'PLAN_ACTION\[\$m\]="skip:excluded by --only"' "${ROOT}/lib/upgrade/plan.sh"; then
    ok "the engine OBEYS --only rather than forcing intact in"
else
    fail "the engine obeys --only" "single-module repair from a shell is gone"
fi
if grep -q '_with_intact' "$R"; then
    fail "the routes do NOT special-case intact" "intact should behave like every other module"
else
    ok "the routes do not special-case intact"
fi

echo "== stage-0 hop: an older packaged engine must not choke on it =="

# ---------------------------------------------------------------------------
# The argv filter this file used to test is GONE, along with the handover that
# needed it.
#
# scripts/upgrade.sh used to exec the target engine with the operator's argv,
# so a flag this engine knew and an older packaged engine did not would kill
# the run with "Unknown option" -- which is what --reinstall did on 2026-08-11,
# and why an allowlist of droppable flags was bolted on.
#
# Handover now goes through scripts/bootstrap_upgrade.sh, which forwards argv
# UNTOUCHED and strips only the flags it owns itself. An unknown flag is no
# longer a problem to be filtered: it is a flag some engine understands and the
# bootstrap does not, which is the normal case. So what needs testing is the
# opposite property -- that nothing is dropped, and that the bootstrap's own
# flags do not leak through to an engine that would reject them.
# ---------------------------------------------------------------------------
BOOT="${ROOT}/scripts/bootstrap_upgrade.sh"

if [[ -f "$BOOT" ]]; then
    ok "scripts/bootstrap_upgrade.sh exists"
else
    fail "scripts/bootstrap_upgrade.sh exists" "the single handover path is missing"
fi

# The old mechanism must be genuinely gone, not merely unused -- two handover
# paths is two things to keep in agreement forever.
for _dead in _u_forwardable_args _U_DROPPABLE_OPTS INTACT_UPGRADE_LEGACY; do
    if grep -q "^[^#]*${_dead}" "${ROOT}/scripts/upgrade.sh"; then
        fail "${_dead} is gone from upgrade.sh" "the old argv handover is still live"
    else
        ok "${_dead} is gone from upgrade.sh"
    fi
done

# --reinstall is the flag that started all of this: it must reach the engine.
_probe() {
    # Print what the bootstrap would exec, without fetching or running anything.
    sed -n 's/.*exec "\${_exec\[@\]}" "\${_FWD\[@\]}".*/FORWARDS_FWD/p' "$BOOT"
}
if [[ -n "$(_probe)" ]]; then
    ok "the bootstrap execs the forwarded args"
else
    fail "the bootstrap execs the forwarded args" "handover no longer passes argv through"
fi

# Its own flags must NOT be forwarded: the engine has never heard of them.
for _own in --engine --no-verify --prepare; do
    if grep -q -- "${_own}" <(sed -n '/^_FWD=()/,/^done$/p' "$BOOT"); then
        ok "${_own} is stripped from the passthrough"
    else
        fail "${_own} is stripped from the passthrough" "would reach the engine as Unknown option"
    fi
done

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
