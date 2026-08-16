#!/bin/bash
# Intact.AI Platform Installer - Health Check Functions
# Verification, summary, and reporting

# ============================================================================
# Post-Install Initialization
# ============================================================================

run_post_install_init() {
    log_info "Running post-install initialization..."

    # Wait for backend to be healthy (up to 60 seconds)
    local max_wait=60
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if curl -sf --max-time 5 http://localhost:5001/health > /dev/null 2>&1; then
            log_success "Backend API is ready"
            break
        fi
        sleep 5
        waited=$((waited + 5))
        log_info "Waiting for backend... (${waited}s)"
    done

    if [[ $waited -ge $max_wait ]]; then
        log_warn "Backend not ready after ${max_wait}s, skipping maintenance"
        log_warn "You can run maintenance later via Dashboard > Settings > Maintenance"
        return
    fi

    # Run maintenance tasks directly (no workflow created in GUI)
    log_info "Running maintenance tasks (artifact import, tool download)..."
    log_info "This may take a few minutes..."

    # Run the maintenance script inside the backend container. Keep a raw
    # copy so child-process warnings/errors can be added to the final
    # ATTENTION report; array writes inside a pipeline subshell would be lost.
    local maintenance_output
    maintenance_output=$(mktemp)
    if docker exec intact_backend python /app/scripts/run_maintenance.py 2>&1 | while IFS= read -r line; do
        echo "  $line"
        echo "  $line" >> "$LOG_FILE"
        printf '%s\n' "$line" >> "$maintenance_output"
    done; then
        scan_child_output_for_issues "run_maintenance.py" "$maintenance_output"
        log_success "Maintenance tasks completed"
    else
        scan_child_output_for_issues "run_maintenance.py" "$maintenance_output"
        log_warn "Maintenance had issues - check logs above"
    fi
    rm -f "$maintenance_output"

    # Last thing before the service tests: Kibana has been up for minutes by
    # now, so its indices exist and can finally be swept. See
    # elk_settle_single_node_replicas() for why this cannot live in the ELK init
    # container. Non-fatal by design.
    elk_settle_single_node_replicas || true
}

# ============================================================================
# Installation Verification
# ============================================================================

verify_installation() {
    log_info "Verifying installation..."

    # Grace period before probing — bumped from 3s to 15s. TimeSketch
    # gunicorn worker cold-start, IRIS app boot, and OpenSearch reaching
    # green can each take 8-12s on a fresh install; 3s landed us in
    # false-negative territory on slow VMs.
    sleep 15

    # Run post-install initialization (artifact import, tool download)
    run_post_install_init

    echo ""
    echo "Container Status:"
    docker ps --filter "name=intact_*" --format "table {{.Names}}\t{{.Status}}" | head -20

    echo ""
    log_info "Testing services..."

    # Test backend (with timeout)
    if curl -sf --max-time 5 http://localhost:5001/api/health > /dev/null 2>&1; then
        log_success "Backend API: Running"
    else
        log_warn "Backend API: Not responding (may still be starting)"
        UNHEALTHY_MODULES+=("Backend API")
        capture_diagnostic_logs "Backend API" intact_backend
    fi

    # Test nginx (with timeout)
    if curl -sf --max-time 5 http://localhost:80 > /dev/null 2>&1; then
        log_success "Nginx: Running"
    else
        log_warn "Nginx: Not responding"
        UNHEALTHY_MODULES+=("Nginx")
        capture_diagnostic_logs "Nginx" intact_nginx
    fi

    # Test Velociraptor — checks the gRPC API port (8001) is listening on the
    # host. Velociraptor's web UI is HTTPS-behind-self-signed-cert so a curl
    # is unreliable; we just confirm the container is up AND the port is open.
    # Failure here means the offline-collector / agentic flows won't work.
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velo_enabled" || [[ -z "$velo_enabled" ]]; then
        if docker ps --filter "name=^intact_velociraptor$" --filter "status=running" \
                --format '{{.Names}}' | grep -q .; then
            # Try gRPC port (most authoritative — that's what the backend uses)
            if (echo > /dev/tcp/localhost/8001) >/dev/null 2>&1; then
                log_success "Velociraptor: Running (gRPC port 8001 reachable)"
            else
                log_warn "Velociraptor: Container up but gRPC port 8001 not reachable"
                UNHEALTHY_MODULES+=("Velociraptor")
                capture_diagnostic_logs "Velociraptor (port unreachable)" intact_velociraptor
            fi
        else
            log_warn "Velociraptor: Container not running"
            UNHEALTHY_MODULES+=("Velociraptor")
            capture_diagnostic_logs "Velociraptor (container down)" intact_velociraptor
        fi
    fi

    # Test elasticsearch (with timeout) - check if ELK module is enabled
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        local elk_user=$(read_config "['modules']['elk']['id']")
        local elk_pass=$(read_config "['modules']['elk']['password']")
        if curl -sf --max-time 5 -u "${elk_user:-elastic}:${elk_pass}" http://localhost:9200 > /dev/null 2>&1; then
            log_success "Elasticsearch: Running"
        else
            log_warn "Elasticsearch: Not responding"
            UNHEALTHY_MODULES+=("ELK Stack")
            capture_diagnostic_logs "ELK Stack" intact_elasticsearch
        fi
    else
        log_info "Elasticsearch: Not installed (disabled in config)"
    fi

    # Test TimeSketch — bumped from --max-time 5 to 30. The web service
    # cold-starts gunicorn workers on first request and the NL2Q/Gemini
    # libs lazy-import there; first hit can take 10-20s. 5s gave us
    # false negatives even when the service was healthy.
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$ts_enabled"; then
        if curl -skf --max-time 30 https://localhost:5000 > /dev/null 2>&1; then
            log_success "TimeSketch: Running"
        else
            log_warn "TimeSketch: Not responding"
            UNHEALTHY_MODULES+=("TimeSketch")
            capture_diagnostic_logs "TimeSketch" intact_timesketch_nginx intact_timesketch_web
        fi
    else
        log_info "TimeSketch: Not installed (disabled in config)"
    fi

    # Test IRIS (with timeout, using HTTPS) - check if module is enabled.
    # Bumped to --max-time 30 — IRIS web interface can take 10-15s on
    # the first request after a cold compose-up.
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        local iris_http_code=$(curl -sk --max-time 30 "https://localhost:8443/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$iris_http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            log_success "IRIS: Running (HTTP $iris_http_code)"
        else
            # Check if containers are at least running
            if docker ps --filter "name=intact_iris_nginx" --filter "status=running" --format "{{.Names}}" | grep -q "intact_iris_nginx"; then
                if [[ "$iris_http_code" == "000" ]]; then
                    # Initializing is a soft state — give it room before
                    # marking as unhealthy. We still mark it though, because
                    # if it's still 000 by the time the install ends, the
                    # operator deserves a clear "not yet up" signal.
                    log_warn "IRIS: Container running, web interface initializing..."
                else
                    log_warn "IRIS: Unexpected response (HTTP $iris_http_code)"
                fi
            else
                log_warn "IRIS: Not responding (container may be starting)"
            fi
            UNHEALTHY_MODULES+=("IRIS")
            capture_diagnostic_logs "IRIS" intact_iris_nginx intact_iris_app
        fi
    else
        log_info "IRIS: Not installed (disabled in config)"
    fi
}

# capture_diagnostic_logs() lives in lib/common.sh — sourced before this
# file, available to both health.sh and modules.sh deploy steps.

# ============================================================================
# Installation Summary
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]] || [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]] || [[ ${#INSTALL_ERRORS[@]} -gt 0 ]]; then
        echo -e "${RED}Intact.AI Platform Installation Finished With Errors${NC}"
    elif [[ ${#INSTALL_WARNINGS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Intact.AI Platform Installation Finished With Warnings${NC}"
    else
        echo -e "${GREEN}Intact.AI Platform Installation Complete${NC}"
    fi
    echo "=============================================="
    echo ""

    local domain=$(read_config "['domain']")
    if [[ -z "$domain" ]]; then
        domain="localhost"
        log_warn "Could not read domain from config, using localhost"
    fi

    echo "Access your services:"
    echo ""
    echo -e "  Dashboard:     ${BLUE}http://${domain}${NC}"
    echo -e "  Velociraptor:  ${BLUE}https://${domain}/velociraptor${NC}"
    echo -e "  TimeSketch:    ${BLUE}https://${domain}:5000${NC}"
    echo -e "  IRIS:          ${BLUE}https://${domain}:8443${NC}"
    echo -e "  Kibana:        ${BLUE}https://${domain}:5601${NC}"
    echo -e "  Portainer:     ${BLUE}https://${domain}:9443${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Access the dashboard to verify all services"
    echo "  2. Check backend logs: sudo docker logs intact_backend"
    echo "  3. Download Velociraptor clients from: https://${domain}/velociraptor"
    echo ""
    echo "Note: IRIS may take 2-5 minutes on first startup for database initialization."
    echo ""

    # Log completion message (appears in both terminal and log file)
    log_success "=============================================="
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]] || [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]] || [[ ${#INSTALL_ERRORS[@]} -gt 0 ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Intact.AI Platform Installation Finished With Errors" >> "$LOG_FILE"
    elif [[ ${#INSTALL_WARNINGS[@]} -gt 0 ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Intact.AI Platform Installation Finished With Warnings" >> "$LOG_FILE"
    else
        log_success "Intact.AI Platform Installation Complete!"
    fi
    log_success "=============================================="
}

# ============================================================================
# Installation Notes
# ============================================================================

# Prints the neutral notes recorded via record_install_note(). Separate from
# print_final_issues_report() on purpose: that block is for things that went
# wrong and is styled to alarm. This is for expected behaviour worth
# remembering, and is styled not to. Called between print_summary and
# print_final_issues_report, so it reads after the success banner and before
# any ATTENTION block.
print_install_notes() {
    [[ ${#INSTALL_NOTES[@]} -eq 0 ]] && return 0

    echo ""
    echo "=============================================="
    echo -e "${BLUE}For your information${NC}"
    echo "=============================================="
    local note
    for note in "${INSTALL_NOTES[@]}"; do
        echo ""
        echo -e "$note"
    done
    echo ""
}

# ============================================================================
# Installation Report
# ============================================================================

print_installation_report() {
    echo ""
    echo "=============================================="
    if [[ ${#FAILED_MODULES[@]} -eq 0 && ${#UNHEALTHY_MODULES[@]} -eq 0 ]]; then
        echo -e "${GREEN}Installation Completed Successfully${NC}"
    elif [[ ${#FAILED_MODULES[@]} -eq 0 ]]; then
        # Deploy succeeded across the board, but at least one module didn't
        # pass its end-to-end health check. Operator needs to know — the
        # "Successfully" headline used to hide this.
        echo -e "${YELLOW}Deploy Succeeded — Health Checks Pending${NC}"
    else
        echo -e "${YELLOW}Installation Completed with Errors${NC}"
    fi
    echo "=============================================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    # Show succeeded modules
    if [[ ${#SUCCEEDED_MODULES[@]} -gt 0 ]]; then
        echo -e "${GREEN}Succeeded (${#SUCCEEDED_MODULES[@]}):${NC}"
        for mod in "${SUCCEEDED_MODULES[@]}"; do
            echo "  + $mod"
        done
        echo ""
    fi

    # Show failed modules
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        echo -e "${RED}Failed (${#FAILED_MODULES[@]}):${NC}"
        for mod in "${FAILED_MODULES[@]}"; do
            echo "  - $mod"
        done
        echo ""
        echo -e "${YELLOW}To repair failed modules, re-run the installer (idempotent),${NC}"
        echo -e "${YELLOW}or re-apply the full config + cert + container pipeline:${NC}"
        echo "  sudo bash install.sh"
        echo "  sudo bash scripts/change_ip.sh \"$(read_config \"['domain']\")\""
        echo ""
        echo -e "${YELLOW}Check log file for details: $LOG_FILE${NC}"
        echo ""
    fi

    # Show modules whose deploy succeeded but health check didn't pass.
    # These are commonly transient (still warming up) but never were before
    # — silence here used to mean "everything's fine" when nothing was
    # actually responding. Now the operator sees the list and can decide.
    if [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Deployed but not responding to health probes (${#UNHEALTHY_MODULES[@]}):${NC}"
        for mod in "${UNHEALTHY_MODULES[@]}"; do
            echo "  ! $mod"
        done
        echo ""
        echo -e "${YELLOW}These modules' containers are running but their endpoints"
        echo -e "didn't answer within the verification window. Re-check in a"
        echo -e "minute or two — many services finish initialization after"
        echo -e "the install script returns. If still down, see logs:${NC}"
        echo "  sudo docker logs <container_name>"
        echo ""
    fi
}

# ============================================================================
# End-of-install nginx refresh — fixes the stale-upstream race
# ============================================================================
#
# Each per-module nginx (intact_timesketch_nginx, intact_iris_nginx, the
# main intact_nginx) resolves its upstream hostname ONCE at startup. If
# the upstream container is recreated after nginx starts (which happens
# during install when compose brings services up in parallel), nginx
# keeps the stale IP and returns 502 forever — caught us with TimeSketch
# on a fresh install today.
#
# A `docker restart` on each *_nginx at the end of install is idempotent
# and clears the cache. Restart on already-healthy containers is a
# ~2-second no-op; on a stale-upstream nginx it fixes the bug instantly.
# Returns 0 unconditionally — a failed restart is logged loudly but
# doesn't abort the install (operator constraint: no new failure paths).

refresh_nginx_upstreams() {
    log_info "Refreshing per-module nginx DNS caches…"

    local nginx_containers
    nginx_containers=$(docker ps --filter 'name=intact_.*_nginx' --format '{{.Names}}' 2>/dev/null)
    # Also include the main reverse-proxy (named just intact_nginx, doesn't match the *_nginx glob).
    if docker ps --filter 'name=^intact_nginx$' --format '{{.Names}}' 2>/dev/null | grep -q .; then
        nginx_containers=$(printf '%s\nintact_nginx\n' "$nginx_containers" | sort -u | sed '/^$/d')
    fi

    if [[ -z "$nginx_containers" ]]; then
        log_info "  No nginx containers found to refresh."
        return 0
    fi

    local container
    while IFS= read -r container; do
        [[ -z "$container" ]] && continue
        if docker restart "$container" >/dev/null 2>&1; then
            log_success "  Restarted $container (cleared upstream DNS cache)"
        else
            log_warn "  Failed to restart $container — check 'docker logs $container'"
        fi
    done <<< "$nginx_containers"

    return 0
}

# ============================================================================
# Cert-consumer reload + verify (used after a TLS cert rotation)
# ============================================================================
#
# After change_ip.sh regenerates the shared cert IN PLACE, every container that
# bind-mounts it must re-read it. With the inode preserved (see
# generate_certificates / FORCE_CERT_REGEN) a plain `docker restart` is enough;
# if a consumer still isn't healthy we fall back to a full recreate (which
# re-binds the mount unconditionally). Only the containers that actually serve
# the shared cert are touched, and only if they're running. Velociraptor (its
# own cert) and VolWeb (CSRF) are handled separately by change_ip.
#
# Returns 0 always — failures are logged loudly (and recorded for the final
# issues report) but never abort the caller (operator constraint).

# True if $1 is Up and neither Restarting nor (unhealthy), within ~30s.
_cert_consumer_healthy() {
    local c="$1" i status
    for i in $(seq 1 15); do
        status=$(docker ps -a --filter "name=^${c}$" --format '{{.Status}}' 2>/dev/null)
        if [[ "$status" == Up* && "$status" != *Restarting* && "$status" != *'(unhealthy)'* ]]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

recreate_cert_consumers() {
    log_info "Reloading TLS cert consumers (nginx, timesketch, kibana, iris, portainer)…"

    # container -> module dir. The recreate fallback is `docker rm -f` + a
    # `compose up -d` in the module dir, so we don't need the compose service
    # name — compose just recreates the one container that's now missing.
    # --pull never keeps it air-gap-safe (images are already loaded).
    local consumers=(
        "intact_nginx:modules/nginx"
        "intact_timesketch_nginx:modules/timesketch"
        "intact_iris_nginx:modules/iris"
        "intact_kibana:modules/elk"
        "intact_portainer:modules/portainer"
    )

    local entry c dir
    for entry in "${consumers[@]}"; do
        c="${entry%%:*}"
        dir="${SCRIPT_DIR}/${entry#*:}"

        # Skip consumers that aren't running (module disabled / not installed).
        if ! docker ps --filter "name=^${c}$" --format '{{.Names}}' 2>/dev/null | grep -q .; then
            continue
        fi

        log_info "  $c: restarting to pick up the rotated cert…"
        docker restart "$c" >/dev/null 2>&1 || true
        if _cert_consumer_healthy "$c"; then
            log_success "  $c healthy"
            continue
        fi

        # Restart didn't bring it back — recreate (re-binds the cert mount).
        log_warn "  $c unhealthy after restart — recreating…"
        docker rm -f "$c" >/dev/null 2>&1 || true
        ( cd "$dir" && docker compose up -d --pull never >/dev/null 2>&1 ) || true
        if _cert_consumer_healthy "$c"; then
            log_success "  $c healthy after recreate"
        else
            log_warn "  $c STILL unhealthy — check 'docker logs $c'"
        fi
    done

    return 0
}

# ============================================================================
# Final ATTENTION report — surfaces every warning/error that scrolled past
# ============================================================================
#
# Operators currently miss yellow [WARN] lines that scrolled past during
# install — the green "Installation Complete!" banner makes them think
# everything is fine. This function prints a loud red block listing
# every entry that hit log_warn / log_error during the install, so the
# operator sees the issues right above the success banner. Pure
# formatter — no side effects on flow.

print_final_issues_report() {
    local n_w=${#INSTALL_WARNINGS[@]}
    local n_e=${#INSTALL_ERRORS[@]}

    if (( n_e + n_w == 0 )); then
        log_success "No warnings or errors during install."
        return 0
    fi

    # Tee every line of the final summary into the install log too.
    # Previously these were raw `echo` calls — they painted the terminal
    # but the install log captured nothing past "Installation Complete!".
    # Operators who only have the log file (no terminal scrollback)
    # couldn't see which errors/warnings tripped the summary. `_tee`
    # writes to both stdout (with ANSI for the terminal) and to the log
    # file (stripped of ANSI so grep + future re-reads stay clean).
    local _strip_ansi='s/\x1b\[[0-9;]*m//g'
    _tee() {
        local line="$1"
        echo -e "$line"
        if [[ -n "${LOG_FILE:-}" ]]; then
            echo -e "$line" | sed -E "$_strip_ansi" >> "$LOG_FILE"
        fi
    }

    _tee ""
    _tee "${RED}============================================================${NC}"
    _tee "${RED}  ATTENTION — install completed with ${n_e} error(s), ${n_w} warning(s)${NC}"
    _tee "${RED}============================================================${NC}"

    if (( n_e > 0 )); then
        _tee ""
        _tee "${RED}ERRORS:${NC}"
        local entry
        for entry in "${INSTALL_ERRORS[@]}"; do
            _tee "  $entry"
        done
    fi

    if (( n_w > 0 )); then
        _tee ""
        _tee "${YELLOW}WARNINGS:${NC}"
        # Count "↳ resolved: …" breadcrumbs that pull_compose_with_retry
        # and _pull_image_with_retry leave when a retry attempt succeeds
        # after an earlier failure. Surface them as a one-line summary so
        # the operator can tell transient retries apart from real issues
        # at a glance.
        local resolved_count=0
        local entry
        for entry in "${INSTALL_WARNINGS[@]}"; do
            [[ "$entry" == *"↳ resolved:"* ]] && ((resolved_count++))
        done
        if (( resolved_count > 0 )); then
            _tee "${YELLOW}  (${resolved_count} of these were transient and already auto-resolved on retry — shown below as ↳ entries)${NC}"
        fi
        for entry in "${INSTALL_WARNINGS[@]}"; do
            _tee "  $entry"
        done
    fi

    _tee ""
    _tee "${RED}  Full log: ${LOG_FILE}${NC}"
    _tee "${RED}============================================================${NC}"
    _tee ""

    return 0
}
