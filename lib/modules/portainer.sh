#!/bin/bash
# Intact.AI Platform Installer — Portainer module.

# The password config.yaml used to ship (1234qwer!@#$) is refused with every
# other public value by secret_check (INTACT_KNOWN_DEFAULT_PASSWORDS in
# lib/secrets.sh).

generate_portainer_secrets() {
    # Portainer CE locks itself after a 5-minute "initial setup" window if no
    # admin account is created. Seed the admin account via --admin-password-file
    # so the very first container boot skips the interactive setup entirely
    # and the install works unattended.
    log_info "Generating Portainer secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/portainer/secrets"
    ( umask 077; mkdir -p "$secrets_dir" )

    # The admin password is written by ensure_module_credentials
    # (lib/config.sh): typed, from config.yaml (checked: 12+ characters is
    # Portainer's own minimum -- a shorter one leaves the admin uncreated and
    # the UI stuck in its timed-out "initial setup"), or generated. Portainer
    # reads the file at FIRST start only, so ensure_module_credentials refuses
    # to mint one for a Portainer that already has data.
    if [[ ! -s "$secrets_dir/admin_password" ]]; then
        ensure_module_credentials portainer || return 1
        sync
        log_info "  Created Portainer admin password file"
    else
        log_info "  Portainer admin password file exists, skipping"
    fi

    # AGENT_SECRET — the ONLY thing authenticating callers to portainer-agent.
    # The agent is a full Docker API proxy holding /var/run/docker.sock as root
    # (its own README documents /browse/* endpoints that read anywhere on the
    # host filesystem), so an unauthenticated agent reachable over the network
    # is a direct container-to-host-root path: create a container binding / and
    # you own the box.
    #
    # It was previously unset. `docker inspect intact_portainer_agent` showed an
    # environment of exactly PATH — no secret — while the agent sat on the
    # shared intact_network alongside 24 other containers.
    #
    # Both server and agent load this same file; a mismatch means Portainer
    # cannot see its environment, which is loud and immediate rather than
    # silent. Generated once and then left alone -- rotating it on every install
    # would unpair an already-working server/agent.
    #
    # Deliberately NOT modules/portainer/.env: that file is git-TRACKED, so a
    # credential written there gets staged by the next `git add` (the same trap
    # that once staged a live GitHub PAT). secrets/ is gitignored.
    local agent_env="$secrets_dir/agent.env"
    if [[ ! -s "$agent_env" ]]; then
        printf 'AGENT_SECRET=%s\n' "$(openssl rand -hex 32)" > "$agent_env"
        chmod 600 "$agent_env"
        sync
        log_info "  Generated Portainer agent secret"
    else
        log_info "  Portainer agent secret exists, skipping"
    fi

    log_success "Portainer secrets ready"
}

# ============================================================================
# Portainer Module
# ============================================================================

deploy_portainer() {
    local portainer_enabled=$(read_config "['modules']['portainer']['enabled']")
    if ! is_enabled "$portainer_enabled"; then
        log_info "[5/8] Portainer: SKIPPED (disabled in config)"
        return
    fi

    log_info "[5/8] Starting Portainer (Container Management)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/portainer"
    cd "${SCRIPT_DIR}/modules/portainer"

    # Portainer mounts the shared Nginx TLS cert via --tlscert/--tlskey so the
    # UI on :9443 presents the same certificate as the rest of the stack.
    # generate_certificates() runs before this step, so the cert should exist —
    # but bail out loud if it doesn't rather than letting Docker create empty
    # bind-mount dirs and Portainer fail to start with an unhelpful error.
    local nginx_ssl="${SCRIPT_DIR}/modules/nginx/ssl"
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" ]] || [[ ! -f "$nginx_ssl/nginx-cert.key" ]]; then
        log_error "  Shared Nginx TLS cert not found at $nginx_ssl/"
        log_error "  Expected generate_certificates() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    # Admin password file must exist; without it the first boot falls into the
    # 5-minute initial-setup window and times out before anyone can click.
    local portainer_secret="${SCRIPT_DIR}/modules/portainer/secrets/admin_password"
    if [[ ! -s "$portainer_secret" ]]; then
        log_error "  Portainer admin password file missing at $portainer_secret"
        log_error "  Expected generate_portainer_secrets() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    local portainer_version=$(read_config "['versions']['portainer']")
    log_info "  Portainer version: ${portainer_version:-latest}"

    if ! pull_compose_with_retry "Portainer"; then
        track_module_failure "Portainer"
        return 1
    fi
    if ! run_compose_up_with_retry "Portainer"; then
        log_error "  Docker compose failed!"
        track_module_failure "Portainer"
        return 1
    fi

    # Show container status
    show_container_status "intact_portainer"

    # Wait for Portainer container
    log_info "  Waiting for Portainer container..."
    if wait_for_container "intact_portainer" 30; then
        log_success "  Portainer is ready"
        track_module_success "Portainer"
    else
        log_warn "  Portainer may not be fully ready"
        capture_diagnostic_logs "Portainer (container timeout)" intact_portainer
        track_module_success "Portainer"
    fi
}
