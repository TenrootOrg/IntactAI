#!/bin/bash
# Intact.AI — change the platform IP and/or the public ports after install.
#
# config.yaml is the single source of truth. `domain:` is the platform IP:
# install.sh propagates it into modules/velociraptor/.env, the TLS certs (CN),
# the Velociraptor client installers, and VolWeb's Django CSRF trusted origins
# (modules/volweb/.env); every other module talks over Docker DNS and holds no
# literal IP. The per-module public ports (modules.elk.kibana_port,
# modules.{iris,portainer,timesketch,volweb}.port, modules.velociraptor.agent_port)
# land in modules/nginx/.env and modules/velociraptor/.env.
#
# Usage: sudo bash scripts/change_ip.sh [NEW_IP] [-y|--yes] [--force]
#
# One shot: it compares NEW_IP (default: config.yaml domain) and the ports in
# config.yaml with what the box applies NOW (the .env files, not config.yaml,
# because Settings writes config.yaml before it runs this) and does only what
# differs: the IP pipeline, the ports, or both. Nothing differs -> it says so
# and touches no container.
#
# The IP pipeline re-derives from config.yaml (re-running the same install
# helpers) rather than blindly find/replacing, then runs a safety-net sweep for
# any stray literal occurrences of the OLD IP.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"

# Same libs install.sh sources — gives us read_config, update_env_files,
# config_public_ports, generate_certificates, log_* and check_root.
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
# Only generate_certificates is used here, from the shared module-plumbing
# file (lib/modules/*.sh is split one-file-per-module; this script needs
# none of the per-module deploy_* logic).
source "${SCRIPT_DIR}/lib/modules/shared.sh"
source "${SCRIPT_DIR}/lib/health.sh"

usage() {
    cat <<EOF
Usage: sudo bash scripts/change_ip.sh [NEW_IP] [-y|--yes] [--force]

Apply a new platform IP and/or the public ports set in config.yaml, in one run.

Arguments:
  NEW_IP        The new IPv4 address (default: config.yaml domain)

Options:
  -y, --yes     Accepted for back-compat; no-op (the script never prompts)
  --force       Re-run the full IP pipeline even when nothing changed — the
                repair tool when certs/containers drifted out of sync
  -h, --help    Show this help

It applies only what differs from what the box runs now:
  IP changed:    config.yaml domain, module .env files, stray old-IP literals,
                 TLS certs (CN=NEW_IP), Velociraptor, backend, VolWeb, the
                 cert consumers, Velociraptor client installers
  Ports changed: modules/nginx/.env + modules/velociraptor/.env, recreates
                 intact_nginx; an agent_port change also patches Velociraptor
                 and regenerates the client installers
  Nothing:       says so and exits 0 without touching a container

Ports must be 1-65535, all different, and not 80/443/8080; an unusable one
stops the run before anything is changed.
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

# The IP the box serves now. Not config.yaml: Settings writes the new domain
# there before it runs this script. Velociraptor's .env is stamped from domain
# on every install/change; the cert CN covers boxes without Velociraptor (but
# never "localhost" -- pre-fix installs issued that CN, and sweeping the literal
# "localhost" through modules/ would wreck every config).
_applied_ip() {
    local ip=""
    if is_enabled "$(read_config "['modules']['velociraptor']['enabled']")"; then
        ip="$(sed -n 's/^VELOX_PUBLIC_IP=//p' "${SCRIPT_DIR}/modules/velociraptor/.env" 2>/dev/null | tail -1)"
    fi
    if [[ -z "$ip" ]]; then
        ip="$(openssl x509 -noout -subject -in "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.crt" 2>/dev/null \
            | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')"
        valid_ipv4 "$ip" || ip=""
    fi
    echo "${ip:-$(read_config "['domain']")}"
}

# VAR=port as compose publishes it now: the .env value, else the compose
# default. config_public_ports on an empty config prints exactly those defaults.
_applied_ports() {
    local var def cur env
    while IFS='=' read -r var def; do
        env="${SCRIPT_DIR}/modules/nginx/.env"
        [[ "$var" == VELOX_AGENT_PORT ]] && env="${SCRIPT_DIR}/modules/velociraptor/.env"
        # No Velociraptor .env: nothing publishes the agent port, so it never differs.
        [[ -f "$env" ]] || def="$(public_port "$var")"
        cur="$(sed -n "s/^${var}=//p" "$env" 2>/dev/null | tail -1)"
        echo "${var}=${cur:-$def}"
    done < <(CONFIG_FILE=/dev/null config_public_ports)
}

# Write VAR=port lines back into the .env compose reads them from. Used to undo
# a port that failed to apply: the .env is what the next run compares against,
# so leaving the new value there would make it report "Nothing to change".
_write_ports() {
    local var val env
    while IFS='=' read -r var val; do
        [[ -n "$var" ]] || continue
        env="${SCRIPT_DIR}/modules/nginx/.env"
        [[ "$var" == VELOX_AGENT_PORT ]] && env="${SCRIPT_DIR}/modules/velociraptor/.env"
        [[ -f "$env" ]] && UPDATE_ENV_ADD_ONLY=0 update_env_var "$env" "$var" "$val"
    done <<< "$1"
}

# The backend bind-mounts config.yaml by inode: sed -i (new file + rename)
# would leave it reading the old content, so rewrite through the same inode.
_replace_in_place() {  # _replace_in_place <file> <sed-expr>
    local out
    out="$(sed "$2" "$1")" && printf '%s\n' "$out" > "$1"
}

# The persisted server.config.yaml holds the agent URL and the entrypoint only
# writes it when absent, so a recreate alone would keep handing out the old port.
_apply_agent_port() {
    local old="$1" new="$2" ip="$3" cfg="/velociraptor/server.config.yaml"
    local velo_env="${SCRIPT_DIR}/modules/velociraptor/.env"
    log_warn "=================================================================="
    log_warn "Velociraptor agent port changes ${old} -> ${new}."
    log_warn "Every agent ALREADY DEPLOYED connects to ${old} and is cut off until"
    log_warn "it is redeployed with the new installers in client_installers/."
    log_warn "=================================================================="
    # server.config.yaml still says ${old} on every failure below: put the .env
    # (and so the published port) back too, or the box listens on one port while
    # telling agents another, and a re-run would see nothing left to change.
    _agent_port_undo() {
        _write_ports "VELOX_AGENT_PORT=${old}"
        UPDATE_ENV_ADD_ONLY=0 update_env_var "$velo_env" VELOX_SERVER_URL "https://${ip}:${old}/"
        ( cd "${SCRIPT_DIR}/modules/velociraptor" && docker compose up -d --pull never ) >/dev/null 2>&1
        log_error "Agent port left at ${old}. Fix the cause, then re-run: sudo bash scripts/change_ip.sh"
        return 1
    }
    ( cd "${SCRIPT_DIR}/modules/velociraptor" && docker compose up -d --pull never ) \
        || { log_error "Recreating intact_velociraptor failed (is port ${new} free?)"; _agent_port_undo; return 1; }
    local _
    for _ in $(seq 1 30); do
        docker exec intact_velociraptor test -f "$cfg" 2>/dev/null && break
        sleep 2
    done
    # This file holds the Velociraptor CA: losing it orphans every enrolled agent.
    # Keep a copy, change only the agent URL lines, and put the copy back if
    # anything else differs afterwards.
    local bak="${cfg}.before-port-${old}-to-${new}"
    docker exec intact_velociraptor cp -p "$cfg" "$bak" \
        || { log_error "Could not back up ${cfg}; nothing changed"; _agent_port_undo; return 1; }
    if ! docker exec intact_velociraptor sed -i "s#\(https://[^/:]*\):${old}/#\1:${new}/#g" "$cfg"; then
        docker exec intact_velociraptor cp -p "$bak" "$cfg"
        log_error "Could not patch ${cfg}: agents would still be told port ${old}"
        _agent_port_undo; return 1
    fi
    # Every changed line must be an agent URL line; otherwise undo.
    if docker exec intact_velociraptor sh -c "diff '$bak' '$cfg' | grep '^[<>]' | grep -v ':${old}/\|:${new}/'" | grep -q .; then
        docker exec intact_velociraptor cp -p "$bak" "$cfg"
        log_error "Patching ${cfg} changed more than the agent URL; restored the original. Nothing else was changed in it."
        _agent_port_undo; return 1
    fi
    log_info "  ${cfg} patched (copy kept as ${bak})"
    docker restart intact_velociraptor >/dev/null || { log_error "Restarting intact_velociraptor failed"; return 1; }
    # generate_clients.sh only checks client.config.yaml exists (it always
    # does), so wait for the restart to rewrite it or it repacks the old port.
    for _ in $(seq 1 30); do
        docker exec intact_velociraptor grep -q ":${new}/" /velociraptor/client.config.yaml 2>/dev/null && break
        sleep 2
    done
    bash "${SCRIPT_DIR}/scripts/generate_clients.sh" \
        || log_warn "Client installers not regenerated -- re-run: bash scripts/generate_clients.sh"
}

# The IP half's file work: everything on disk that holds the literal IP.
_apply_ip_files() {
    local old_ip="$1" new_ip="$2"

    # Re-propagate into module .env files (velociraptor VELOX_* vars, and the
    # public ports, so VELOX_SERVER_URL gets the new agent port too).
    update_env_files

    # Safety-net sweep for any stray literal old-IP occurrences.
    # config.yaml + velociraptor/.env are already updated above, so this only
    # catches hand-edits elsewhere (e.g. volweb/.env's CSRF origins). -I skips
    # binaries; we exclude certs + MSI/binary installers (regenerated
    # separately, never text-edited). We MUST also skip test dirs/fixtures:
    # the fusion test fixtures embed forensic data (e.g. browser-history URLs)
    # that legitimately contains the platform IP as DATA — rewriting it would
    # silently corrupt the fixtures and break the fusion tests.
    log_info "Sweeping for stray occurrences of $old_ip …"
    local old_esc="${old_ip//./\\.}" f
    local sweep_hits=()
    while IFS= read -r f; do
        [[ -n "$f" ]] && sweep_hits+=("$f")
    done < <(grep -rIl -F \
        --exclude-dir=.git --exclude-dir=node_modules \
        --exclude-dir=tests --exclude-dir=fixtures \
        --exclude='*.msi' --exclude='*.crt' --exclude='*.pem' --exclude='*.key' \
        -- "$old_ip" \
        "${SCRIPT_DIR}/modules" "${SCRIPT_DIR}/scripts" "$CONFIG_FILE" 2>/dev/null)
    if [[ ${#sweep_hits[@]} -eq 0 ]]; then
        log_success "  No stray occurrences found."
    else
        for f in "${sweep_hits[@]}"; do
            _replace_in_place "$f" "s|${old_esc}|${new_ip}|g"
            log_success "  Replaced in ${f#"$SCRIPT_DIR"/}"
        done
    fi

    # Regenerate TLS certs with the new CN, IN PLACE. We do NOT `rm` the old
    # certs first: FORCE_CERT_REGEN=1 makes generate_certificates overwrite the
    # existing files (openssl -out / cp truncate, keeping the inode), so the
    # containers that bind-mount the cert pick up the new content on restart.
    # Deleting+recreating would orphan those bind mounts at the old inode and a
    # restart would keep serving the OLD cert — the bug behind the broken
    # Timesketch/Kibana UIs after an IP change. DOMAIN drives the CN; the IRIS
    # web cert is re-synced (in place) by generate_certificates when enabled.
    log_info "Regenerating TLS certificates for CN=$new_ip (in place)"
    export DOMAIN="$new_ip"
    export FORCE_CERT_REGEN=1
    generate_certificates
    unset FORCE_CERT_REGEN
}

# The IP half's container work, before nginx and the cert consumers reload.
_apply_ip_containers() {
    local old_esc="${1//./\\.}" new_ip="$2"
    # Velociraptor: its server.config.yaml lives in the host bind-mount
    # data/velociraptor/ (was a named volume pre-2026-06-23) and the entrypoint
    # only generates it when ABSENT — so a plain recreate keeps the OLD IP, and
    # client.config.yaml (regenerated every start) inherits it.
    # Patch the persisted server config in place (only the server_urls /
    # public_url / hostname lines hold the IP; the CA/cert blocks don't, and
    # clients pin the CA not the hostname), then restart so the entrypoint
    # regenerates client.config.yaml + api.config.yaml and repacks installers.
    log_info "Bringing Velociraptor up so its config volume is available…"
    # --pull never: images are already loaded post-install; never reach a
    # registry, so this works on air-gapped hosts.
    ( cd "${SCRIPT_DIR}/modules/velociraptor" && docker compose up -d --pull never ) >/dev/null 2>&1

    local velo_cfg="/velociraptor/server.config.yaml" _
    log_info "Waiting for Velociraptor server config…"
    for _ in $(seq 1 30); do
        docker exec intact_velociraptor test -f "$velo_cfg" 2>/dev/null && break
        sleep 2
    done

    if docker exec intact_velociraptor test -f "$velo_cfg" 2>/dev/null; then
        log_info "Patching Velociraptor server config (→ $new_ip)…"
        # sed is a no-op on a freshly-generated config that already has new_ip.
        docker exec intact_velociraptor sed -i "s|${old_esc}|${new_ip}|g" "$velo_cfg" \
            && log_success "  Patched server.config.yaml" \
            || log_warn "  Failed to patch server.config.yaml"
        log_info "Restarting Velociraptor to regenerate client/api config + installers…"
        docker restart intact_velociraptor >/dev/null 2>&1 \
            && log_success "  Velociraptor restarted" \
            || log_warn "  Velociraptor restart failed — check 'docker logs intact_velociraptor'"
        # Gate on client.config.yaml actually carrying the NEW IP before we let
        # generate_clients.sh repack — it only checks the file *exists* (it
        # always does), so without this it could repack the stale config.
        log_info "Waiting for client.config.yaml to pick up $new_ip…"
        for _ in $(seq 1 30); do
            docker exec intact_velociraptor grep -q "$new_ip" /velociraptor/client.config.yaml 2>/dev/null && break
            sleep 2
        done
        if docker exec intact_velociraptor grep -q "$new_ip" /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  client.config.yaml now points at $new_ip"
        else
            log_warn "  client.config.yaml did not update to $new_ip — check 'docker logs intact_velociraptor'"
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
    # the sweep repointed). The backend reads it at startup, so a recreate is
    # required — without it, browser POSTs through the proxy fail CSRF on the
    # new IP. `up -d --force-recreate` re-reads the updated .env.
    if docker ps -a --format '{{.Names}}' | grep -q '^intact_volweb_backend$'; then
        log_info "Recreating VolWeb so its CSRF origins pick up $new_ip…"
        ( cd "${SCRIPT_DIR}/modules/volweb" && docker compose up -d --force-recreate --pull never ) >/dev/null 2>&1 \
            && log_success "  VolWeb recreated" \
            || log_warn "  VolWeb recreate failed — re-run: (cd modules/volweb && docker compose up -d --force-recreate --pull never)"
    fi
}

change_ip_main() {
    # The sourced log_* helpers append to $LOG_FILE (install.sh sets this too).
    : "${LOG_FILE:=${SCRIPT_DIR}/change_ip_$(date +%Y%m%d_%H%M%S).log}"
    export INTACT_HOST_PATH="$SCRIPT_DIR"

    local new_ip="" force=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; return 0 ;;
            -y|--yes)  shift ;;
            --force)   force=true; shift ;;
            -*)        log_error "Unknown option: $1"; usage; return 1 ;;
            *)
                if [[ -n "$new_ip" ]]; then
                    log_error "Unexpected extra argument: $1"; usage; return 1
                fi
                new_ip="$1"; shift ;;
        esac
    done

    check_root

    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "config.yaml not found at $CONFIG_FILE — run this from an installed Intact.AI tree."
        return 1
    fi

    local config_domain
    config_domain="$(read_config "['domain']")"
    new_ip="${new_ip:-$config_domain}"
    if ! valid_ipv4 "$new_ip"; then
        log_error "Invalid IPv4 address: '$new_ip'"
        return 1
    fi

    # Validate before anything is written, so a typo cannot leave the box half-moved.
    local errs l
    if ! errs="$(config_public_ports 2>&1 >/dev/null)"; then
        log_error "config.yaml has an unusable public port; nothing was changed:"
        while IFS= read -r l; do log_error "  $l"; done <<< "$errs"
        log_error "  Ports must be 1-65535, all different, and not 80/443/8080."
        return 1
    fi

    local old_ip old_ports new_ports old_agent new_agent
    old_ip="$(_applied_ip)"
    old_ports="$(_applied_ports)"
    new_ports="$(config_public_ports)"
    old_agent="$(sed -n 's/^VELOX_AGENT_PORT=//p' <<< "$old_ports")"
    new_agent="$(sed -n 's/^VELOX_AGENT_PORT=//p' <<< "$new_ports")"

    local ip_changed=false ports_changed=false
    [[ "$old_ip" != "$new_ip" || "$force" == true ]] && ip_changed=true
    [[ "$old_ports" != "$new_ports" ]] && ports_changed=true

    if [[ "$ip_changed" == false && "$ports_changed" == false ]]; then
        log_success "Nothing to change: the box already serves IP ${new_ip} and the ports in config.yaml."
        log_info "  To re-apply the IP pipeline anyway (repair), add --force."
        return 0
    fi

    echo
    [[ "$ip_changed" == true ]] && log_info "IP: ${old_ip} -> ${new_ip}$([[ "$old_ip" == "$new_ip" ]] && echo " (--force: re-applying)")"
    if [[ "$ports_changed" == true ]]; then
        local var old new
        while IFS='=' read -r var new; do
            old="$(sed -n "s/^${var}=//p" <<< "$old_ports")"
            [[ "$old" != "$new" ]] && log_info "Port ${var}: ${old} -> ${new}"
        done <<< "$new_ports"
    fi
    echo

    # config.yaml is the source of truth: make it say what is being applied
    # (Settings has already written it; a plain CLI run has not).
    if [[ "$config_domain" != "$new_ip" ]]; then
        log_info "Updating config.yaml domain → $new_ip"
        _replace_in_place "$CONFIG_FILE" "s|^domain:.*|domain: ${new_ip}|"
    fi

    if [[ "$ip_changed" == true ]]; then
        _apply_ip_files "$old_ip" "$new_ip"
    else
        # Overwrite, never add-only: this run exists to change the values.
        UPDATE_ENV_ADD_ONLY=0 write_public_port_env || return 1
        if [[ "$old_agent" != "$new_agent" && -f "${SCRIPT_DIR}/modules/velociraptor/.env" ]]; then
            UPDATE_ENV_ADD_ONLY=0 update_env_var "${SCRIPT_DIR}/modules/velociraptor/.env" \
                VELOX_SERVER_URL "https://${new_ip}:${new_agent}/"
        fi
        log_success "Ports written to modules/nginx/.env and modules/velociraptor/.env"
    fi

    if ! docker info >/dev/null 2>&1; then
        log_warn "Docker does not appear to be running — skipping container restarts."
        log_warn "Start the stacks yourself, then re-run: bash scripts/generate_clients.sh"
        return 0
    fi

    [[ "$ip_changed" == true ]] && _apply_ip_containers "$old_ip" "$new_ip"

    local rc=0
    if [[ "$ports_changed" == true ]]; then
        # compose recreates intact_nginx only when its ports actually changed.
        if ( cd "${SCRIPT_DIR}/modules/nginx" && docker compose up -d --pull never ); then
            log_success "intact_nginx is up with the configured ports"
        else
            # Usually a port already taken on the host; compose has then removed
            # the old container and the dashboard is down. Bring it back on the
            # old ports and keep the .env at those, so a re-run retries. The IP
            # half below still runs: it is independent of the ports.
            log_error "Recreating intact_nginx failed (a port in use?) -- check: docker logs intact_nginx"
            _write_ports "$(grep -v '^VELOX_AGENT_PORT=' <<< "$old_ports")"
            ( cd "${SCRIPT_DIR}/modules/nginx" && docker compose up -d --pull never ) \
                && log_warn "  intact_nginx is back on the previous ports" \
                || log_error "  intact_nginx is down -- check: docker logs intact_nginx"
            rc=1
        fi
    fi

    # Reload every TLS cert consumer so it serves the freshly-rotated cert:
    # restarts each (clearing stale upstream DNS too), verifies it comes back
    # healthy, and recreates any that don't.
    [[ "$ip_changed" == true ]] && recreate_cert_consumers

    if [[ "$old_agent" != "$new_agent" ]] && is_enabled "$(read_config "['modules']['velociraptor']['enabled']")"; then
        # Last, after any IP patch, so its "only the agent URL lines changed"
        # check sees just the port move. It regenerates the installers itself.
        _apply_agent_port "$old_agent" "$new_agent" "$new_ip" || return 1
    elif [[ "$ip_changed" == true ]]; then
        # generate_clients.sh self-waits for the fresh client.config.yaml.
        log_info "Regenerating Velociraptor client installers…"
        if bash "${SCRIPT_DIR}/scripts/generate_clients.sh"; then
            log_success "  Client installers regenerated"
        else
            log_warn "  Client installer regeneration failed — re-run: bash scripts/generate_clients.sh"
        fi
    fi

    echo
    if [[ "$rc" -ne 0 ]]; then
        log_error "The module ports were NOT applied (above); everything else was. Fix the cause and re-run."
        return "$rc"
    fi
    log_success "Applied: IP ${new_ip}$([[ "$ports_changed" == true ]] && echo ", ports from config.yaml")"
    echo
    echo "  Access:"
    echo "    Dashboard:   https://${new_ip}"
    echo "    Kibana:      https://${new_ip}:$(public_port KIBANA_PORT)"
    echo "    IRIS:        https://${new_ip}:$(public_port IRIS_PORT)"
    echo "    Portainer:   https://${new_ip}:$(public_port PORTAINER_PORT)"
    echo "    Timesketch:  https://${new_ip}:$(public_port TIMESKETCH_PORT)"
    echo "    VolWeb:      https://${new_ip}:$(public_port VOLWEB_PORT)"
    echo "    Agents:      https://${new_ip}:${new_agent}/"
    echo
    if [[ "$old_ip" != "$new_ip" ]]; then
        log_warn "Already-deployed Velociraptor agents baked in the OLD IP ($old_ip) and"
        log_warn "will NOT reconnect. Redeploy endpoints with the freshly generated"
        log_warn "installers in client_installers/, or keep $old_ip reachable as an alias."
        log_warn "Browser TLS warnings are expected (self-signed cert with the new CN)."
    fi
    return 0
}

# Sourced by tests/test_change_ip_ports.sh; run directly on the box.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    change_ip_main "$@"
fi
