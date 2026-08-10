#!/bin/bash
# Intact.AI Platform Installer — main service deployment orchestration.
#
# The single entry point install.sh calls: generate the secrets and
# certificates every module needs before its deploy_* runs, then bring the
# 8 modules up in dependency order (IRIS's API key and VolWeb's YARA seed
# both need intact_backend, so those two steps run after deploy_backend
# rather than inside deploy_iris / deploy_volweb).

# ============================================================================
# Main Service Deployment Orchestration
# ============================================================================

start_services() {
    log_info "=========================================="
    log_info "Starting Intact.AI Services"
    log_info "=========================================="
    echo ""

    cd "${SCRIPT_DIR}"

    # Generate secrets and certificates before starting services
    generate_iris_secrets
    echo ""
    generate_portainer_secrets
    echo ""
    # No nginx Basic Auth secret to generate any more — the dashboard login is
    # now an application-level session set up in the browser on first visit
    # (config.yaml's top-level `first_login: true`, handled by
    # modules/backend/services/auth_service.py). Nothing reads an htpasswd file.
    generate_certificates
    echo ""
    ensure_shared_volumes
    echo ""

    # Deploy in order — 8 numbered steps [1/8]..[8/8]:
    # ELK, TimeSketch, Velociraptor, IRIS, Portainer, VolWeb, Backend, Nginx.
    deploy_elk
    echo ""
    deploy_timesketch
    echo ""
    deploy_velociraptor
    echo ""
    deploy_iris
    echo ""
    deploy_portainer
    echo ""
    deploy_volweb
    echo ""
    deploy_backend
    echo ""
    # IRIS api_key bootstrap — runs HERE (not inside deploy_iris) because
    # it writes into the backend container's SQLite secrets DB via
    # `docker exec intact_backend …`. Calling it before deploy_backend
    # meant intact_backend didn't exist yet and set_secret failed 100% of
    # the time on fresh installs. The IRIS-DB read inside the function
    # blocks until the admin row is populated, so it's safe to run here
    # even if IRIS's own migrations are still finishing.
    bootstrap_iris_api_key
    # Re-assert the IRIS admin password from config.yaml (IRIS only honours it at
    # first-init, so this fixes the "config password doesn't work" case).
    enforce_iris_admin_password
    echo ""
    # Same reason as the IRIS bootstrap above: seed_yara_rulesets' bundled
    # path needs intact_backend, which does not exist until the deploy_backend
    # call above. Self-guards on volweb enabled/running (see its own comment).
    if ! seed_yara_rulesets; then
        log_warn "  YARA ruleset seeding had issues — refresh via Maintenance later"
    fi
    echo ""
    deploy_nginx
    echo ""

    # Summary
    log_info "=========================================="
    log_info "Service deployment completed"
    log_info "=========================================="

    # Show all running containers
    echo ""
    log_info "Running Intact.AI containers:"
    docker ps --filter "name=intact_" --format "  {{.Names}}: {{.Status}}" 2>/dev/null

    cd "${SCRIPT_DIR}"
}
