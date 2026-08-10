#!/bin/bash
# Intact.AI Platform Installer — Velociraptor module.

# ============================================================================
# Velociraptor Module
# ============================================================================
#
# NOTE: /velociraptor is host-mounted at data/velociraptor/ (see the module's
# docker-compose.yaml). A FRESH install has no legacy named volume to migrate —
# the bind-mount starts empty and entrypoint.sh generates server.config.yaml
# into it. The named-volume → host-mount MIGRATION (which preserves the CA for
# older-release deployments) lives ONLY in the upgrade path
# (services/upgrade/velociraptor.migrate_velociraptor_config_to_host), since
# that's the only place a legacy volume exists.

deploy_velociraptor() {
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if ! is_enabled "$velo_enabled"; then
        log_info "[3/8] Velociraptor: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_velociraptor; then
        log_info "[3/8] Velociraptor: already installed + running (skipping)"
        return 0
    fi

    log_info "[3/8] Starting Velociraptor..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/velociraptor"
    cd "${SCRIPT_DIR}/modules/velociraptor"

    if ! preflight_host_check "Velociraptor"; then
        log_error "Velociraptor: host pre-flight FAILED — see warnings above"
        track_module_failure "Velociraptor"
        return 1
    fi

    local velo_version=$(read_config "['versions']['velociraptor']")
    log_info "  Velociraptor version: ${velo_version:-latest}"

    # Pre-stage the four binaries (linux server + mac/win clients) that
    # the Dockerfile COPYs at build time. The Dockerfile no longer
    # curls during build — it expects these files already in the build
    # context, which is the contract for the offline-upgrade workflow.
    # Initial install needs internet here; same as before, just at a
    # different layer (host curl vs in-container curl).
    if ! stage_velociraptor_client_binaries "$velo_version" "${SCRIPT_DIR}/modules/velociraptor"; then
        log_error "  Failed to stage Velociraptor binaries — see warnings above."
        track_module_failure "Velociraptor"
        return 1
    fi

    if ! run_compose_up_with_retry "Velociraptor" 600; then
        log_error "  Docker compose failed!"
        track_module_failure "Velociraptor"
        return 1
    fi

    # Show container status
    show_container_status "intact_velociraptor"

    # Wait for container to be ready
    log_info "  Waiting for Velociraptor container..."
    if ! wait_for_container "intact_velociraptor" 60; then
        log_warn "  Velociraptor container may not be fully ready"
        capture_diagnostic_logs "Velociraptor (container start timeout)" intact_velociraptor
    fi

    # Wait for Velociraptor configuration to be generated
    log_info "  Waiting for Velociraptor configuration..."
    local velo_config_wait=0
    while [[ $velo_config_wait -lt 90 ]]; do
        if docker exec intact_velociraptor test -f /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  Velociraptor configuration ready (${velo_config_wait}s)"
            break
        fi
        sleep 5
        ((velo_config_wait+=5))
    done
    if [[ $velo_config_wait -ge 90 ]]; then
        log_warn "  Velociraptor configuration not ready after 90s"
        capture_diagnostic_logs "Velociraptor (config generation timeout)" intact_velociraptor
    fi

    # Generate client installers
    log_info "  Generating pre-configured client installers..."
    if [[ -f "${SCRIPT_DIR}/scripts/generate_clients.sh" ]]; then
        bash "${SCRIPT_DIR}/scripts/generate_clients.sh" 2>&1 | tee -a "$LOG_FILE"
        if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
            log_warn "  Client installer generation had issues"
        fi
    else
        log_warn "  Client installer script not found, skipping"
    fi

    track_module_success "Velociraptor"
}
