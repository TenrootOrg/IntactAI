#!/bin/bash
# Intact.AI — change the platform IP/domain after install.
#
# config.yaml's `domain:` is the single source of truth for the platform
# IP. install.sh propagates it into modules/velociraptor/.env, the TLS
# certs (CN), the Velociraptor client installers, and VolWeb's Django CSRF
# trusted origins (modules/volweb/.env); every other module talks over
# Docker DNS and holds no literal IP. This script repoints all of that to a
# new IP in one shot and restarts the affected containers so the platform is
# reachable on the new address.
#
# Usage: sudo ./scripts/change_ip.sh <NEW_IP> [-y|--yes]
#
# It re-derives from config.yaml (re-running the same install helpers)
# rather than blindly find/replacing, then runs a safety-net sweep for any
# stray literal occurrences of the OLD IP.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
# The sourced log_* helpers append to $LOG_FILE (install.sh sets this too).
LOG_FILE="${SCRIPT_DIR}/change_ip_$(date +%Y%m%d_%H%M%S).log"
export INTACT_HOST_PATH="$SCRIPT_DIR"

# Same libs install.sh sources — gives us read_config, update_env_files,
# generate_certificates, refresh_nginx_upstreams, log_* and check_root.
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
source "${SCRIPT_DIR}/lib/modules.sh"
source "${SCRIPT_DIR}/lib/health.sh"

ASSUME_YES=false
NEW_IP=""

usage() {
    cat <<EOF
Usage: sudo ./scripts/change_ip.sh <NEW_IP> [-y|--yes]

Repoint the Intact.AI platform to a new IP after install.

Arguments:
  <NEW_IP>      The new IPv4 address (e.g. 192.168.120.11)

Options:
  -y, --yes     Don't prompt for confirmation (non-interactive)
  -h, --help    Show this help

What it does:
  1. Sets domain: <NEW_IP> in config.yaml
  2. Re-propagates into modules/velociraptor/.env (update_env_files)
  3. Sweeps modules/ + scripts/ for stray old-IP literals and replaces them
  4. Regenerates the TLS certs with CN=<NEW_IP>
  5. Recreates Velociraptor, restarts the backend, refreshes nginx
  6. Regenerates the Velociraptor client installers
EOF
}

# Strict IPv4 validation: four octets, each 0-255.
valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[@]:1:4}"; do
        # Force base-10 so octets like "08" don't trip octal arithmetic.
        ((10#$o >= 0 && 10#$o <= 255)) || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -y|--yes)  ASSUME_YES=true; shift ;;
        -*)        log_error "Unknown option: $1"; usage; exit 1 ;;
        *)
            if [[ -n "$NEW_IP" ]]; then
                log_error "Unexpected extra argument: $1"; usage; exit 1
            fi
            NEW_IP="$1"; shift ;;
    esac
done

if [[ -z "$NEW_IP" ]]; then
    log_error "Missing required <NEW_IP> argument."
    usage
    exit 1
fi

if ! valid_ipv4 "$NEW_IP"; then
    log_error "Invalid IPv4 address: '$NEW_IP'"
    exit 1
fi

check_root

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "config.yaml not found at $CONFIG_FILE — run this from an installed Intact.AI tree."
    exit 1
fi

OLD_IP="$(read_config "['domain']")"
if [[ -z "$OLD_IP" ]]; then
    log_error "Could not read current 'domain' from config.yaml."
    exit 1
fi

if [[ "$OLD_IP" == "$NEW_IP" ]]; then
    log_success "Platform IP is already $NEW_IP — nothing to do."
    exit 0
fi

echo
log_info "About to change the platform IP:"
echo "    OLD: $OLD_IP"
echo "    NEW: $NEW_IP"
echo
if [[ "$ASSUME_YES" != true ]]; then
    read -r -p "Proceed? This will edit configs, regenerate certs, and restart containers. [y/N] " reply
    case "${reply,,}" in
        y|yes) ;;
        *) log_warn "Aborted by user."; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# 1. Update the source of truth
# ---------------------------------------------------------------------------
log_info "Updating config.yaml domain → $NEW_IP"
sed -i "s|^domain:.*|domain: ${NEW_IP}|" "$CONFIG_FILE"

# ---------------------------------------------------------------------------
# 2. Re-propagate into module .env files (velociraptor VELOX_* vars)
# ---------------------------------------------------------------------------
update_env_files

# ---------------------------------------------------------------------------
# 3. Safety-net sweep for any stray literal old-IP occurrences.
#    config.yaml + velociraptor/.env are already updated above, so this only
#    catches hand-edits elsewhere (e.g. volweb/.env's CSRF origins). -I skips
#    binaries; we exclude certs + MSI/binary installers (regenerated
#    separately, never text-edited). We MUST also skip test dirs/fixtures:
#    the fusion test fixtures embed forensic data (e.g. browser-history URLs)
#    that legitimately contains the platform IP as DATA — rewriting it would
#    silently corrupt the fixtures and break the fusion tests.
# ---------------------------------------------------------------------------
log_info "Sweeping for stray occurrences of $OLD_IP …"
old_esc="${OLD_IP//./\\.}"
sweep_hits=()
while IFS= read -r f; do
    [[ -n "$f" ]] && sweep_hits+=("$f")
done < <(grep -rIl -F \
    --exclude-dir=.git --exclude-dir=node_modules \
    --exclude-dir=tests --exclude-dir=fixtures \
    --exclude='*.msi' --exclude='*.crt' --exclude='*.pem' --exclude='*.key' \
    -- "$OLD_IP" \
    "${SCRIPT_DIR}/modules" "${SCRIPT_DIR}/scripts" "$CONFIG_FILE" 2>/dev/null)

if [[ ${#sweep_hits[@]} -eq 0 ]]; then
    log_success "  No stray occurrences found."
else
    for f in "${sweep_hits[@]}"; do
        sed -i "s|${old_esc}|${NEW_IP}|g" "$f"
        log_success "  Replaced in ${f#"$SCRIPT_DIR"/}"
    done
fi

# ---------------------------------------------------------------------------
# 4. Regenerate TLS certs with the new CN. generate_certificates skips when
#    the cert already exists, so remove the old nginx + IRIS web certs first
#    (the generic IRIS Root CA is reused). DOMAIN drives the CN.
# ---------------------------------------------------------------------------
log_info "Regenerating TLS certificates for CN=$NEW_IP"
rm -f "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.crt" \
      "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.key"
# generate_certificates only re-syncs the IRIS web cert when IRIS is enabled
# (gated in lib/modules.sh). Removing it unconditionally would delete a cert
# nothing regenerates when IRIS is disabled, leaving an empty web_certificates/
# dir — so when IRIS is later enabled, intact_iris_nginx crash-loops on a
# missing cert. Gate the removal the same way the regeneration is gated.
if is_enabled "$(read_config "['modules']['iris']['enabled']")"; then
    rm -f "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_cert.pem" \
          "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem"
fi
export DOMAIN="$NEW_IP"
generate_certificates

# ---------------------------------------------------------------------------
# 5. Restart the affected containers.
# ---------------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
    log_warn "Docker does not appear to be running — skipping container restarts."
    log_warn "Start the stacks yourself, then re-run: bash scripts/generate_clients.sh"
else
    # Velociraptor: its server.config.yaml lives in the host bind-mount
    # data/velociraptor/ (was a named volume pre-2026-06-23) and the entrypoint
    # only generates it when ABSENT — so a plain recreate keeps the OLD IP, and
    # client.config.yaml (regenerated every start) inherits it.
    # Patch the persisted server config in place (only the server_urls /
    # public_url / hostname lines hold the IP; the CA/cert blocks don't, and
    # clients pin the CA not the hostname), then restart so the entrypoint
    # regenerates client.config.yaml + api.config.yaml and repacks installers.
    log_info "Bringing Velociraptor up so its config volume is available…"
    ( cd "${SCRIPT_DIR}/modules/velociraptor" && docker compose up -d ) >/dev/null 2>&1

    velo_cfg="/velociraptor/server.config.yaml"
    log_info "Waiting for Velociraptor server config…"
    for _ in $(seq 1 30); do
        docker exec intact_velociraptor test -f "$velo_cfg" 2>/dev/null && break
        sleep 2
    done

    if docker exec intact_velociraptor test -f "$velo_cfg" 2>/dev/null; then
        log_info "Patching Velociraptor server config ($OLD_IP → $NEW_IP)…"
        # sed is a no-op on a freshly-generated config that already has NEW_IP.
        docker exec intact_velociraptor sed -i "s|${old_esc}|${NEW_IP}|g" "$velo_cfg" \
            && log_success "  Patched server.config.yaml" \
            || log_warn "  Failed to patch server.config.yaml"
        log_info "Restarting Velociraptor to regenerate client/api config + installers…"
        docker restart intact_velociraptor >/dev/null 2>&1 \
            && log_success "  Velociraptor restarted" \
            || log_warn "  Velociraptor restart failed — check 'docker logs intact_velociraptor'"
        # Gate on client.config.yaml actually carrying the NEW IP before we let
        # generate_clients.sh repack — it only checks the file *exists* (it
        # always does), so without this it could repack the stale config.
        log_info "Waiting for client.config.yaml to pick up $NEW_IP…"
        for _ in $(seq 1 30); do
            docker exec intact_velociraptor grep -q "$NEW_IP" /velociraptor/client.config.yaml 2>/dev/null && break
            sleep 2
        done
        if docker exec intact_velociraptor grep -q "$NEW_IP" /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  client.config.yaml now points at $NEW_IP"
        else
            log_warn "  client.config.yaml did not update to $NEW_IP — check 'docker logs intact_velociraptor'"
        fi
    else
        log_warn "  server.config.yaml never appeared — check 'docker logs intact_velociraptor'"
    fi

    # Backend: restart so it reloads config.yaml.
    if docker ps -a --format '{{.Names}}' | grep -q '^intact_backend$'; then
        log_info "Restarting backend…"
        docker restart intact_backend >/dev/null 2>&1 \
            && log_success "  Backend restarted" \
            || log_warn "  Backend restart failed — check 'docker logs intact_backend'"
    fi

    # VolWeb (memory-forensics): Django's CSRF trusted origins are derived from
    # the platform IP (VOLWEB_CSRF_TRUSTED_ORIGINS in modules/volweb/.env, which
    # the sweep above repointed to $NEW_IP). The backend reads it at startup, so
    # a recreate is required — without it, browser POSTs through the proxy fail
    # CSRF on the new IP. `up -d --force-recreate` re-reads the updated .env.
    if docker ps -a --format '{{.Names}}' | grep -q '^intact_volweb_backend$'; then
        log_info "Recreating VolWeb so its CSRF origins pick up $NEW_IP…"
        ( cd "${SCRIPT_DIR}/modules/volweb" && docker compose up -d --force-recreate ) >/dev/null 2>&1 \
            && log_success "  VolWeb recreated" \
            || log_warn "  VolWeb recreate failed — re-run: (cd modules/volweb && docker compose up -d --force-recreate)"
    fi

    # nginx: clears stale upstream DNS cache AND makes them serve the new cert.
    refresh_nginx_upstreams

    # ---------------------------------------------------------------------
    # 6. Regenerate Velociraptor client installers with the new server IP.
    #    generate_clients.sh self-waits for the fresh client.config.yaml.
    # ---------------------------------------------------------------------
    log_info "Regenerating Velociraptor client installers…"
    if bash "${SCRIPT_DIR}/scripts/generate_clients.sh"; then
        log_success "  Client installers regenerated"
    else
        log_warn "  Client installer regeneration failed — re-run: bash scripts/generate_clients.sh"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo
log_success "Platform IP changed: $OLD_IP → $NEW_IP"
echo
echo "  Access:"
echo "    Dashboard:   https://${NEW_IP}"
echo "    IRIS:        https://${NEW_IP}:8443"
echo "    Timesketch:  https://${NEW_IP}:5000"
echo
log_warn "Already-deployed Velociraptor agents baked in the OLD IP ($OLD_IP) and"
log_warn "will NOT reconnect. Redeploy endpoints with the freshly generated"
log_warn "installers in client_installers/, or keep $OLD_IP reachable as an alias."
log_warn "Browser TLS warnings are expected (self-signed cert with the new CN)."
