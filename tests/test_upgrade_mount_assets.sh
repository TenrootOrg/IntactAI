#!/bin/bash
# The bind-mount asset rule, and the diagnosis of it.
#
# Docker fabricates an empty DIRECTORY for a bind-mount source that does not
# exist. A compose file that arrives ahead of the file it mounts therefore
# produces a container that dies with `exit 126` and an error naming a path
# rather than a cause.
#
# This is not hypothetical. On 2026-08-12 a customer upgrade 0726 -> 0811
# failed exactly this way: the box received 0811's elk compose (byte-identical
# to the release) which bind-mounts ./config/setup-kibana-user.sh, the script
# itself never arrived, and intact_elk_setup exited 126. The real message --
#
#   setup-kibana-user.sh: setup-kibana-user.sh: Is a directory
#
# -- existed only in that container's log. The upgrade log showed compose
# progress output and the exit code. Finding it took a support bundle.
#
# The same run failed portainer for a sibling reason: secrets/agent.env is
# excluded from every package by CI's secret scan, so no package can ship it
# and it has to be generated on the box.
#
# Both are fixed in the bash engine; 0726's Python engine, which ran Phase 2,
# has neither. What this suite guards is that the fixes stay, and that the
# failure is now DIAGNOSABLE from the upgrade log alone.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

echo "== the engine recovers a fabricated directory =="
A="${ROOT}/lib/upgrade/intact/assets.sh"
if grep -q 'removed the empty directory Docker created' "$A"; then
    ok "it removes Docker's fabricated empty directory"
else
    fail "it removes Docker's fabricated empty directory" \
         "without this the exit-126 crash loop cannot be recovered by an upgrade"
fi
if grep -q 'delivered \${rel}' "$A"; then
    ok "it delivers the file the compose mounts"
else
    fail "it delivers the file the compose mounts"
fi
# A NON-empty directory is a legitimate mount (elk's config/pipeline). Only the
# empty one is Docker's fabrication, and mistaking the two would delete config.
if grep -q 'non-empty directory but the package ships a file; leaving it' "$A"; then
    ok "a non-empty directory is left alone"
else
    fail "a non-empty directory is left alone" "this is how a config dir gets destroyed"
fi
if grep -q 'neither the package nor this box has it' "$A"; then
    ok "it warns when nobody has the file, before compose runs"
else
    fail "it warns when nobody has the file"
fi

echo
echo "== the mount list comes from the compose file itself =="
# Hardcoding the known mounts would silently miss the next one a release adds,
# which is the very way this failed.
if grep -q "grep -oE '\^" "$A" && grep -q '\\./\[\^:\]' "$A"; then
    ok "mounts are parsed out of the compose file"
else
    fail "mounts are parsed out of the compose file"
fi
# The exact extraction, against the real elk compose.
COMPOSE="${ROOT}/modules/elk/docker-compose.yaml"
if [[ -f "$COMPOSE" ]]; then
    mounts="$(grep -oE '^\s*-\s*\./[^:]+:' "$COMPOSE" 2>/dev/null \
              | sed 's/^[[:space:]]*-[[:space:]]*\.\///; s/:$//' | sort -u)"
    if grep -qx 'config/setup-kibana-user.sh' <<< "$mounts"; then
        ok "elk's setup script is seen as a mount asset"
    else
        fail "elk's setup script is seen as a mount asset" \
             "this is the exact file the customer upgrade lost"
    fi
else
    fail "modules/elk/docker-compose.yaml exists"
fi

echo
echo "== portainer's secret is generated, never shipped =="
P="${ROOT}/lib/upgrade/modules/portainer.sh"
if grep -q 'agent.env' "$P" && grep -q 'openssl rand' "$P"; then
    ok "the upgrade generates secrets/agent.env"
else
    fail "the upgrade generates secrets/agent.env" \
         "no package can carry it — CI's secret scan rejects secrets/"
fi

echo
echo "== a failed container's own log reaches the upgrade log =="
C="${ROOT}/lib/upgrade/core.sh"
if grep -q '_u_log_container_failures' "$C"; then
    ok "u_do reports failed containers"
else
    fail "u_do reports failed containers" \
         "compose says 'exit 126' and stops; the reason is in the container log"
fi
# Only containers that actually exited non-zero, or every unrelated unhealthy
# container becomes noise in a report someone has to read under pressure.
if grep -q 'exited.*dead' "$C" || grep -q '"exited" || .*"dead"' "$C"; then
    ok "only exited/dead containers are reported"
else
    fail "only exited/dead containers are reported"
fi

# The extraction, against the customer's real compose output.
_names() {
    grep -oE '\b(intact|iris|timesketch|volweb)_[a-z0-9_-]+' <<< "$1" | sort -u | tr '\n' ' '
}
check "container names are found in compose's failure text" \
      "$(_names 'Container intact_elk_setup  service "setup" didnt complete successfully: exit 126
 Container intact_elasticsearch  Healthy')" \
      "intact_elasticsearch intact_elk_setup "

echo
echo "== the support bundle can name this failure on its own =="
S="${ROOT}/modules/backend/services/support_bundle.py"
for want in _copy_upgrade_engine_logs _version_manifest _bind_mount_audit; do
    if grep -q "def ${want}" "$S"; then
        ok "bundle collects: ${want}"
    else
        fail "bundle collects: ${want}"
    fi
done
if grep -q 'EMPTY DIR' "$S"; then
    ok "the audit flags a fabricated empty directory by name"
else
    fail "the audit flags a fabricated empty directory"
fi
# The bundle refuses to ship .env files at all; an allowlist of KEY NAMES is
# what makes reading version pins out of them safe.
if grep -q "_VERSION_KEY = re.compile" "$S"; then
    ok "only *VERSION keys are read from .env"
else
    fail "only *VERSION keys are read from .env" "a redaction regex that misses one key leaks a credential"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
