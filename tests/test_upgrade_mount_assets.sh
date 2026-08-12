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
echo "== the pre-flight refuses to walk into the trap, for EVERY module =="
# The two failures above were found one module at a time. This class has now
# appeared in three (elk's mount, portainer's env_file, timesketch's
# postgres.env), so the check lives in _u_compose -- the single function every
# module starts through -- rather than in each module's own file.
S="${ROOT}/lib/upgrade/modules/shared.sh"
if grep -q '_u_precheck_compose_sources "$dir"' "$S"; then
    ok "_u_compose pre-checks before starting a module"
else
    fail "_u_compose pre-checks before starting a module"
fi
# Only on the way up: refusing to STOP a module because a secret is missing is
# how a half-upgraded box becomes unrecoverable.
if grep -q '\*" up "\*)' "$S"; then
    ok "the pre-check gates 'up' only, never 'down'"
else
    fail "the pre-check gates 'up' only" "blocking 'down' would strand a half-upgraded box"
fi
if grep -q 'env_file' "$S"; then
    ok "env_file entries are parsed, not just ./ mounts"
else
    fail "env_file entries are parsed" "this is exactly what was missed for portainer"
fi

# Functional: the three shapes, against real compose files.
_load() {
    log_warn(){ :; }; log_error(){ :; }
    . /dev/stdin <<< "$(sed -n '/^_u_compose_sources()/,/^}/p' "$S")"
    . /dev/stdin <<< "$(sed -n '/^_u_precheck_compose_sources()/,/^}/p' "$S")"
}
TD="$(mktemp -d)"; trap 'rm -rf "$TD"' EXIT

# (a) a missing env_file must REFUSE
mkdir -p "$TD/a/secrets"; cp "${ROOT}/modules/portainer/docker-compose.yaml" "$TD/a/" 2>/dev/null
( _load; _u_precheck_compose_sources "$TD/a" ) >/dev/null 2>&1     && fail "a missing env_file refuses the start" "compose would fail obscurely instead"     || ok "a missing env_file refuses the start"

# (b) once generated, it proceeds
printf 'AGENT_SECRET=x\n' > "$TD/a/secrets/agent.env"
printf 'pw\n' > "$TD/a/secrets/admin_password"
( _load; _u_precheck_compose_sources "$TD/a" ) >/dev/null 2>&1     && ok "once the secret exists, the start proceeds"     || fail "once the secret exists, the start proceeds"

# (c) Docker's fabricated empty directory is removed; a real directory mount
#     (elk's config/pipeline) is not.
mkdir -p "$TD/b/config"; cp "${ROOT}/modules/elk/docker-compose.yaml" "$TD/b/" 2>/dev/null
cp -r "${ROOT}/modules/elk/config/pipeline" "$TD/b/config/" 2>/dev/null
mkdir -p "$TD/b/config/setup-kibana-user.sh"
( _load; _u_precheck_compose_sources "$TD/b" ) >/dev/null 2>&1
[[ -e "$TD/b/config/setup-kibana-user.sh" ]]     && fail "the fabricated empty directory is removed"     || ok "the fabricated empty directory is removed"
[[ -d "$TD/b/config/pipeline" ]]     && ok "a legitimate directory mount is left alone"     || fail "a legitimate directory mount is left alone" "this would delete real config"

echo
echo "== every module's per-box files have an upgrade-time generator =="
# The portainer failure was an install-time generator with no upgrade-time
# equivalent. Assert the equivalents exist for every untracked source.
for pair in "portainer:agent.env" "portainer:admin_password" "timesketch:postgres.env"; do
    mod="${pair%%:*}"; f="${pair#*:}"
    if grep -rqs "$f" "${ROOT}/lib/upgrade/"; then
        ok "${mod}: ${f} is ensured during an upgrade"
    else
        fail "${mod}: ${f} is ensured during an upgrade"              "no package can ship it — CI's secret scan rejects secrets/"
    fi
done

echo "== the packager refuses to SHIP a fabricated directory =="
# The engine can recover one on the target, but only if the package carries the
# real file. intact-20260811 did not: something on the build box had an empty
# directory where modules/elk/config/setup-kibana-user.sh belongs, copytree
# packaged the directory, and every install of that asset produced exit 126.
# Refusing at build time is the only place this is cheap to fix.
K="${ROOT}/scripts/ci/packager/package.py"
if grep -q "_reject_fabricated_mount_dirs" "$K"; then
    ok "the packager runs the fabricated-directory check"
else
    fail "the packager runs the fabricated-directory check" \
         "a build box that ever ran the stack can ship a directory where a file belongs"
fi
if grep -q "REFUSING TO BUILD" "$K"; then
    ok "it refuses the build rather than warning"
else
    fail "it refuses the build rather than warning" "a warning in a CI log is a warning nobody reads"
fi
# Only EMPTY directories: elk's config/pipeline is a legitimate directory mount
# and rejecting it would make every build fail.
if grep -q "os.path.isdir(src) and not os.listdir(src)" "$K"; then
    ok "only EMPTY directories are rejected"
else
    fail "only EMPTY directories are rejected" "config/pipeline is a real directory mount"
fi
# env_file counts too — that is the half that was missed for portainer.
if grep -q "envfile_hdr" "$K"; then
    ok "env_file entries are checked as well as ./ mounts"
else
    fail "env_file entries are checked as well as ./ mounts"
fi

# The decision itself, on real paths.
_verdict() {  # <path> -> ship | refuse
    if [[ -d "$1" && -z "$(ls -A "$1" 2>/dev/null)" ]]; then echo refuse; else echo ship; fi
}
GT="$(mktemp -d)"; trap 'rm -rf "$GT"' EXIT
mkdir -p "$GT/pipeline" && touch "$GT/pipeline/main.conf"
printf '#!/bin/bash\n' > "$GT/setup.sh"
mkdir -p "$GT/fabricated"
check "a real file ships"                    "$(_verdict "$GT/setup.sh")"    "ship"
check "a non-empty directory mount ships"    "$(_verdict "$GT/pipeline")"    "ship"
check "a fabricated empty directory refuses" "$(_verdict "$GT/fabricated")"  "refuse"

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
