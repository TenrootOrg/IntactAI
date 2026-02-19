#!/bin/bash
# MSSP Platform Installer - Health Check Functions
# Verification, summary, and reporting

# ============================================================================
# Installation Verification
# ============================================================================

verify_installation() {
    log_info "Verifying installation..."

    # Give services a moment to stabilize
    sleep 3

    echo ""
    echo "Container Status:"
    docker ps --filter "name=mssp_*" --format "table {{.Names}}\t{{.Status}}" | head -20

    echo ""
    log_info "Testing services..."

    # Test backend (with timeout)
    if curl -sf --max-time 5 http://localhost:5001/api/health > /dev/null 2>&1; then
        log_success "Backend API: Running"
    else
        log_warn "Backend API: Not responding (may still be starting)"
    fi

    # Test nginx (with timeout)
    if curl -sf --max-time 5 http://localhost:80 > /dev/null 2>&1; then
        log_success "Nginx: Running"
    else
        log_warn "Nginx: Not responding"
    fi

    # Test elasticsearch (with timeout) - check if ELK module is enabled
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        if curl -sf --max-time 5 http://localhost:9200 > /dev/null 2>&1; then
            log_success "Elasticsearch: Running"
        else
            log_warn "Elasticsearch: Not responding"
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
            if docker ps --filter "name=mssp_iris_nginx" --filter "status=running" --format "{{.Names}}" | grep -q "mssp_iris_nginx"; then
                if [[ "$iris_http_code" == "000" ]]; then
                    log_warn "IRIS: Container running, web interface initializing..."
                else
                    log_warn "IRIS: Unexpected response (HTTP $iris_http_code)"
                fi
            else
                log_warn "IRIS: Not responding (container may be starting)"
            fi
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
    echo -e "${GREEN}MSSP Platform Installation Complete${NC}"
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
    echo -e "  Velociraptor:  ${BLUE}https://${domain}:8000${NC}"
    echo -e "  TimeSketch:    ${BLUE}http://${domain}:5000${NC}"
    echo -e "  IRIS:          ${BLUE}https://${domain}:8443${NC}"
    echo -e "  Kibana:        ${BLUE}http://${domain}:5601${NC}"
    echo ""
    echo "Storage Configuration:"
    echo "  - SQLite database: ${SCRIPT_DIR}/data/mssp.db"
    echo "  - Export/Import API: /api/db/export, /api/db/import"
    echo "  - Backup: cp ${SCRIPT_DIR}/data/mssp.db <backup-path>"
    echo "  - Elasticsearch used only for ELK/Kibana"
    echo ""

    # Show IRIS credentials if available
    local iris_pass_file="${SCRIPT_DIR}/modules/iris/secrets/IRIS_ADM_PASSWORD"
    if [[ -f "$iris_pass_file" ]]; then
        local iris_pass=$(cat "$iris_pass_file" 2>/dev/null)
        echo "IRIS Credentials:"
        echo "  Username: administrator"
        echo "  Password: $iris_pass"
        echo ""
    fi

    echo "Next steps:"
    echo "  1. Access the dashboard to verify all services"
    echo "  2. Check backend logs: sudo docker logs mssp_backend"
    echo "  3. Download Velociraptor clients from: https://${domain}:8000"
    echo ""
    echo "Note: IRIS may take 2-5 minutes on first startup for database initialization."
    echo ""
}

# ============================================================================
# Installation Report
# ============================================================================

print_installation_report() {
    echo ""
    echo "=============================================="
    if [[ ${#FAILED_MODULES[@]} -eq 0 ]]; then
        echo -e "${GREEN}Installation Completed Successfully${NC}"
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
}
