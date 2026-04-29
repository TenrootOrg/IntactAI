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

    # Run the maintenance script inside the backend container
    if docker exec intact_backend python /app/scripts/run_maintenance.py 2>&1 | while IFS= read -r line; do
        echo "  $line"
        echo "  $line" >> "$LOG_FILE"
    done; then
        log_success "Maintenance tasks completed"
    else
        log_warn "Maintenance had issues - check logs above"
    fi
}

# ============================================================================
# Installation Verification
# ============================================================================

verify_installation() {
    log_info "Verifying installation..."

    # Give services a moment to stabilize
    sleep 3

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
    fi

    # Test nginx (with timeout)
    if curl -sf --max-time 5 http://localhost:80 > /dev/null 2>&1; then
        log_success "Nginx: Running"
    else
        log_warn "Nginx: Not responding"
        UNHEALTHY_MODULES+=("Nginx")
    fi

    # Test elasticsearch (with timeout) - check if ELK module is enabled
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        if curl -sf --max-time 5 http://localhost:9200 > /dev/null 2>&1; then
            log_success "Elasticsearch: Running"
        else
            log_warn "Elasticsearch: Not responding"
            UNHEALTHY_MODULES+=("ELK Stack")
        fi
    else
        log_info "Elasticsearch: Not installed (disabled in config)"
    fi

    # Test TimeSketch (with timeout) - check if module is enabled
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$ts_enabled"; then
        if curl -sf --max-time 5 http://localhost:5000 > /dev/null 2>&1; then
            log_success "TimeSketch: Running"
        else
            log_warn "TimeSketch: Not responding"
            UNHEALTHY_MODULES+=("TimeSketch")
        fi
    else
        log_info "TimeSketch: Not installed (disabled in config)"
    fi

    # Test IRIS (with timeout, using HTTPS) - check if module is enabled
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        local iris_http_code=$(curl -sk --max-time 5 "https://localhost:8443/" -o /dev/null -w "%{http_code}" 2>/dev/null)
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
        fi
    else
        log_info "IRIS: Not installed (disabled in config)"
    fi
}

# ============================================================================
# Installation Summary
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}Intact.AI Platform Installation Complete${NC}"
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
    echo -e "  Velociraptor:  ${BLUE}http://${domain}/velociraptor/${NC}"
    echo -e "  TimeSketch:    ${BLUE}http://${domain}:5000${NC}"
    echo -e "  IRIS:          ${BLUE}https://${domain}:8443${NC}"
    echo -e "  Kibana:        ${BLUE}http://${domain}:5601${NC}"
    echo -e "  Portainer:     ${BLUE}https://${domain}:9443${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Access the dashboard to verify all services"
    echo "  2. Check backend logs: sudo docker logs intact_backend"
    echo "  3. Download Velociraptor clients from: http://${domain}/velociraptor/"
    echo ""
    echo "Note: IRIS may take 2-5 minutes on first startup for database initialization."
    echo ""

    # Log completion message (appears in both terminal and log file)
    log_success "=============================================="
    log_success "Intact.AI Platform Installation Complete!"
    log_success "=============================================="
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
        echo -e "${YELLOW}To repair failed modules, run:${NC}"
        echo "  sudo bash scripts/repair_modules.sh"
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
