#!/bin/bash
# Intact.AI — re-point the backend at the operator's codex install.
#
# The backend runs in a container, so it can only see what compose bind-mounted
# into it. lib/config.sh works out where codex lives on the host and stamps
# three paths into modules/backend/.env; docker turns those into mounts.
#
# TWO THINGS MAKE THAT GO STALE, AND NEITHER ANNOUNCES ITSELF:
#
#   1. The stamp only runs during install, change_ip and upgrade. Install the
#      appliance first and codex second — the documented order for most people —
#      and .env still names the empty placeholder that install.sh created.
#
#   2. `docker restart` DOES NOT RE-READ .env. Compose resolves ${VAR} mounts
#      when the container is CREATED; a restart faithfully reproduces the mounts
#      the container already had. So even a correct .env changes nothing until
#      the container is recreated — measured on a live box: .env said
#      /home/<op>/.codex/packages/standalone/releases while the running
#      container still had the empty placeholder mounted at /host/codex-pkg.
#
# Symptom of either: the Settings panel says codex is not installed while
# `codex --version` works perfectly in the operator's own shell.
#
# This script re-stamps and then RECREATES the backend, which is the only
# sequence that actually takes effect. It is safe to run at any time and as
# often as you like — it changes no data and no configuration beyond the mounts.
#
# Usage: sudo ./scripts/refresh_codex.sh
#
# If codex lives somewhere the search cannot reach (a shared /opt tree, another
# account's home, a custom prefix), declare it in config.yaml instead and re-run:
#
#   agentic:
#     codex_path: /opt/codex/bin/codex     # the binary, or the directory holding it

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/refresh_codex_$(date +%Y%m%d_%H%M%S).log"
export INTACT_HOST_PATH="$SCRIPT_DIR"

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/docker.sh"

BACKEND_ENV="${SCRIPT_DIR}/modules/backend/.env"
COMPOSE_FILE="${SCRIPT_DIR}/modules/backend/docker-compose.yaml"

usage() {
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

check_root

[[ -f "$BACKEND_ENV" ]] || { log_error "not an installed appliance: ${BACKEND_ENV} is missing"; exit 1; }

log_info "Re-detecting the operator's codex install…"
_stamp_host_codex_paths "$BACKEND_ENV"

# Recreate, not restart. See the header: a restart reproduces the mounts the
# container already has, so it would report success and change nothing.
log_info "Recreating intact_backend so the new mounts take effect…"
if ! ( cd "$(dirname "$COMPOSE_FILE")" && \
       docker compose up -d --force-recreate --no-deps --no-build backend 2>&1 \
         | tee -a "$LOG_FILE" ); then
    log_error "backend recreate failed — check: docker ps -a | grep intact_backend"
    exit 1
fi

# Ask the backend itself, from inside the container, whether it can now see and
# RUN codex. Its own resolver is the only answer that counts: a mount that looks
# right from out here still proves nothing about what the process can exec.
log_info "Asking the backend whether it can see codex now…"
for _ in $(seq 1 30); do
    docker exec intact_backend true 2>/dev/null && break
    sleep 2
done
if docker exec intact_backend sh -lc \
       'PYTHONPATH=/app python3 -c "
from services.agentic import subscription_cli as s
d = s.detect(\"codex-subscription\")
print(\"PATH:\", d.get(\"path\") or \"(not found)\")
print(\"INSTALLED:\", bool(d.get(\"installed\")))
print(\"VERSION:\", d.get(\"version\") or \"-\")
raise SystemExit(0 if d.get(\"installed\") else 1)
"' 2>&1 | tee -a "$LOG_FILE"; then
    log_success "codex is visible to the backend."
else
    log_error "the backend still cannot find codex."
    log_info  "Stamped into ${BACKEND_ENV}:"
    grep -E '^INTACT_HOST_CODEX' "$BACKEND_ENV" 2>/dev/null | sed 's/^/    /' | tee -a "$LOG_FILE"
    log_info  "If codex is outside those directories, set agentic.codex_path in config.yaml"
    log_info  "to the binary (or its directory) and run this script again."
    exit 1
fi
