#!/bin/bash
# Intact.AI Platform Installer — Nginx module (web server & reverse proxy).

# Nginx HTTP Basic Auth generation used to live here (generate_nginx_secrets +
# _write_nginx_htpasswd, ~80 lines). Both are gone: nginx no longer gates the
# site with auth_basic, so nothing reads an htpasswd file. The dashboard login is
# now an application-level session the operator creates in the browser on first
# visit, driven by config.yaml's top-level `first_login: true` — see
# modules/backend/services/auth_service.py and modules/nginx/config/nginx.conf.
#
# A box installed BEFORE that change still has its old generated password on disk
# at modules/nginx/secrets/nginx_basic_auth_password. It is not orphaned: the
# upgrade path hashes it into the new login so the operator keeps signing in with
# the password they already use, rather than being shown a claimable setup page
# mid-upgrade. That migration is the last remaining consumer of these files and
# lives in services/upgrade/intact.py:migrate_basic_auth_to_app_login().

deploy_nginx() {
    log_info "[8/8] Starting Nginx (Web Server & Reverse Proxy)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/nginx"
    cd "${SCRIPT_DIR}/modules/nginx"

    if ! pull_compose_with_retry "Nginx"; then
        track_module_failure "Nginx"
        return 1
    fi
    if ! run_compose_up_with_retry "Nginx"; then
        log_error "  Docker compose failed!"
        track_module_failure "Nginx"
        return 1
    fi

    # Show container status
    show_container_status "intact_nginx"

    # Wait for Nginx
    log_info "  Waiting for Nginx container..."
    if wait_for_container "intact_nginx" 30; then
        log_success "  Nginx is ready"
        track_module_success "Nginx"
    else
        log_warn "  Nginx may not be fully ready"
        capture_diagnostic_logs "Nginx (container timeout)" intact_nginx
        track_module_success "Nginx"
    fi
}
