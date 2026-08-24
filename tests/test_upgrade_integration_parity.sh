#!/usr/bin/env bash
# Integrations the INSTALLER performs must also happen on the UPGRADE path.
#
# A module can be turned on in config.yaml and then reached by an upgrade
# rather than by re-running install.sh — the operator "adopts" a feature they
# never had. The module then comes up, passes every container and health probe,
# and is quietly half-configured, because the step that wires it to the rest of
# the platform only ever ran from lib/modules/orchestrator.sh.
#
# All three below were found that way, by an e2e scenario that installed a
# backend-only box and adopted nine modules through the dashboard:
#
#   bootstrap_iris_api_key   IRIS up, backend cannot call its API
#   seed_volweb_admin        VolWeb up, nobody can log in
#   seed_yara_rulesets       VolWeb up, nothing to scan with
#
# and one worse than all of them, because it fails silently in the field:
#
#   VELOX_SERVER_URL         modules/velociraptor/.env ships with a developer's
#                            address baked in. install.sh rewrites it from
#                            config.yaml's domain; the upgrade did not. Clients
#                            handed out by an upgrade-installed server spend
#                            forever on "Waiting for a reachable server".
#
# The point is not these four. It is that the class is easy to re-create every
# time a module gains a post-deploy step, and the failure never looks like a
# failure.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${ROOT}/tests/helpers.sh"

fail=0

# Every executable line under lib/upgrade/, comments stripped, collected ONCE.
#
# A variable rather than a function piped into `grep -q`: under `set -o
# pipefail`, grep -q exits the moment it matches, the upstream grep takes
# SIGPIPE, and the pipeline reports failure even though the search SUCCEEDED —
# so every check reported the opposite of the truth.
_UPGRADE_CODE="$(find "${ROOT}/lib/upgrade" -name '*.sh' -print0 \
    | xargs -0 grep -h -v '^[[:space:]]*#' 2>/dev/null || true)"

# function name -> what breaks when the upgrade path omits it
check_parity() {
    local fn="$1" consequence="$2"
    if ! grep -rq "\b${fn}\b" "${ROOT}/lib/modules/" 2>/dev/null; then
        echo "  SKIP ${fn} — no longer an installer-side function"
        return 0
    fi
    # CODE only. The first version of this grepped the tree raw and was
    # satisfied by the explanatory comment sitting next to the call — removing
    # the call itself still passed. A guard a comment can satisfy is not a
    # guard.
    if grep -q "\b${fn}\b" <<<"$_UPGRADE_CODE"; then
        echo "  ok   ${fn}"
    else
        echo "  FAIL ${fn} — called by the installer, never by the upgrade."
        echo "       ${consequence}"
        fail=1
    fi
}

echo "installer integrations that the upgrade path must also perform:"
check_parity bootstrap_iris_api_key \
    "IRIS installed by an upgrade comes up healthy; the backend holds no api key."
check_parity seed_volweb_admin \
    "VolWeb installed by an upgrade comes up with no admin account to log in as."
check_parity seed_yara_rulesets \
    "VolWeb installed by an upgrade has no YARA rules to scan with."

# Not a function — a value. Same class, worse symptom.
echo "the client-facing server address:"
if grep -q "VELOX_SERVER_URL" <<<"$_UPGRADE_CODE"; then
    echo "  ok   VELOX_SERVER_URL is re-derived on the upgrade path"
else
    echo "  FAIL VELOX_SERVER_URL is only ever written by install.sh."
    echo "       modules/velociraptor/.env ships with a hard-coded address, so a"
    echo "       server installed by an upgrade hands out clients that can never"
    echo "       reach it."
    fail=1
fi

# The guard must not pass by finding its own subject in a comment.
if ! grep -v '^[[:space:]]*#' "${ROOT}/lib/upgrade/modules/iris.sh" 2>/dev/null | grep -q "bootstrap_iris_api_key"; then
    echo "  FAIL the iris upgrade module does not mention the api key bootstrap at all"
    fail=1
fi

exit $fail
