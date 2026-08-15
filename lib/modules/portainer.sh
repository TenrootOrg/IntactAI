#!/bin/bash
# Intact.AI Platform Installer — Portainer module.

# The password config.yaml used to ship. Still refused, deliberately: it is
# publicly known, and a box whose config still carries it must keep getting a
# random password rather than inheriting a weak one from this change.
#
# Single-quoted so the `$` is a literal and needs no escaping.
_PORTAINER_RETIRED_DEFAULT='1234qwer!@#$'

generate_portainer_secrets() {
    # Portainer CE locks itself after a 5-minute "initial setup" window if no
    # admin account is created. Seed the admin account via --admin-password-file
    # so the very first container boot skips the interactive setup entirely
    # and the install works unattended.
    log_info "Generating Portainer secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/portainer/secrets"
    mkdir -p "$secrets_dir"

    if [[ ! -s "$secrets_dir/admin_password" ]]; then
        local portainer_password reason=""
        portainer_password=$(read_config "['modules']['portainer']['password']")

        # SAY WHICH CONDITION FIRED. This was one message covering four
        # branches, and on a default install it named the two that had NOT
        # happened: config.yaml shipped `1234qwer!@#$`, which is exactly 12
        # characters, so it passed the length test and tripped the literal
        # match instead -- while the operator was told "missing or < 12 chars"
        # and could see a 12-character password sitting in the file. Every
        # default install printed that.
        #
        # Portainer enforces a 12-character minimum even when the password is
        # seeded via --admin-password-file. Short values silently cause the
        # admin user to never be created and the UI falls back to the
        # timed-out "initial setup" state — exactly what we're trying to avoid.
        if [[ -z "$portainer_password" || "$portainer_password" == "None" ]]; then
            reason="no Portainer password is set in config.yaml"
        elif (( ${#portainer_password} < 12 )); then
            reason="the Portainer password in config.yaml is shorter than Portainer's 12-character minimum"
        elif [[ "$portainer_password" == "$_PORTAINER_RETIRED_DEFAULT" ]]; then
            reason="config.yaml still carries the retired shipped default, which is publicly known"
        fi

        if [[ -n "$reason" ]]; then
            # Random rather than a hardcoded fallback: a constant here would
            # ship one credential to every install that took this branch, and
            # the string would be visible in this open-source file. Same
            # treatment as every other auto-provisioned secret in this codebase
            # (see IRIS_SECRET_KEY / POSTGRES_*_PASSWORD above).
            portainer_password=$(openssl rand -hex 16)
            log_warn "  ${reason}; generated a random one instead"
            log_warn "  Retrieve it with: cat ${secrets_dir}/admin_password"
            log_warn "  Change it from the Portainer UI after first login (Settings -> Users)"
        fi
        printf '%s' "$portainer_password" > "$secrets_dir/admin_password"
        chmod 600 "$secrets_dir/admin_password"
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
