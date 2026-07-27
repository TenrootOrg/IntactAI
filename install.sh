#!/bin/bash
# Intact.AI Platform Installer
# For Ubuntu 24.04
#
# This script installs and configures the Intact.AI platform.
#
# Usage: sudo bash install.sh

set -o pipefail

# ============================================================================
# Script Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

# Export the real install path so each module's docker-compose.yaml can bind
# mount from the correct host location even when the user extracts the
# project outside the default /home/tenroot/intact (the backend compose
# reads ${INTACT_HOST_PATH:-...}).
export INTACT_HOST_PATH="$SCRIPT_DIR"

# ============================================================================
# Load Library Modules
# ============================================================================

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
source "${SCRIPT_DIR}/lib/modules.sh"
source "${SCRIPT_DIR}/lib/health.sh"
source "${SCRIPT_DIR}/lib/upgrade_check.sh"

# ============================================================================
# Main Installation Flow
# ============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "       Intact.AI Platform Installer"
    echo "=============================================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    log_info "Starting Intact.AI installation..."

    # -------------------------------------------------------------------------
    # Prerequisites
    # -------------------------------------------------------------------------
    check_root
    check_initialization_marker
    check_ubuntu
    check_config
    # Authenticate this install's GitHub API calls (module-update polling,
    # quota pre-flights, release lookups) when the operator set
    # options.github_token in config.yaml — raises the shared anonymous
    # 60 req/hr per-IP cap to 5,000 req/hr. Read-only-public token; see the
    # comment on github_token in config.yaml. Env var (if already exported)
    # wins so CI can override.
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        _cfg_gh_token=$(read_config "['options']['github_token']")
        if [[ -n "$_cfg_gh_token" && "$_cfg_gh_token" != "None" ]]; then
            export GITHUB_TOKEN="$_cfg_gh_token"
            log_info "GitHub API: authenticated via options.github_token (5,000 req/hr)"
        fi
    fi
    print_installation_config_summary
    if ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    fi

    # -------------------------------------------------------------------------
    # Optional: poll upstream for newer module releases and offer to bump
    # the pinned versions in config.yaml. Controlled by
    # options.check_module_updates in config.yaml; default false so an
    # unattended install never blocks on a prompt. Must run AFTER
    # check_config (config.yaml exists + parses) and AFTER the network
    # check (we're about to hit api.github.com), but BEFORE any module
    # is deployed, so the new pins drive the install.
    # -------------------------------------------------------------------------
    local check_updates_flag
    check_updates_flag=$(read_config "['options']['check_module_updates']")
    if [[ "$check_updates_flag" == "True" ]]; then
        # Pre-flight: check_module_updates polls api.github.com once
        # per pinned module (6 calls today). Refuse early if quota is
        # too low so the operator gets a clear "wait N minutes" message
        # instead of a confusing 403 mid-poll.
        if ! check_github_quota 6 "module update check"; then
            log_warn "  Skipping update check; install will proceed with pinned versions"
        else
            check_module_updates
        fi
        echo ""
    fi

    # -------------------------------------------------------------------------
    # Core Dependencies
    # -------------------------------------------------------------------------
    install_dependencies
    prefer_ipv4_dns
    if ! install_docker; then
        log_error "=============================================="
        log_error "Docker installation failed — aborting install."
        log_error ""
        log_error "Fix the underlying issue (DNS, firewall, apt, etc.),"
        log_error "then re-run this script. Nothing below this point will"
        log_error "work without a functional docker daemon."
        log_error "=============================================="
        exit 1
    fi
    # Defensive: install_docker can log success for an unhealthy daemon if
    # something exotic happens mid-install. Gate the rest of the flow on a
    # real `docker version` call so we don't cascade through 'command not
    # found' errors for every module if Docker isn't actually usable.
    if ! command -v docker &>/dev/null || ! docker version &>/dev/null; then
        log_error "Docker reports installed but 'docker version' fails — aborting"
        exit 1
    fi
    # Advisory: warn (never block) if the daemon is below the supported floor.
    # Matters mainly when Docker was pre-installed (a fresh install pulls the
    # current release from download.docker.com, which is always new enough).
    check_docker_min_version
    configure_docker_resolver
    create_network

    # -------------------------------------------------------------------------
    # Timeline Processing (Plaso/Timesketch) - Air-gap Support
    # -------------------------------------------------------------------------
    local timesketch_enabled
    timesketch_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$timesketch_enabled"; then
        pull_plaso_image
        pull_python_alpine_image
        download_timesketch_packages
    else
        log_info "Timeline Processing pre-downloads: SKIPPED (TimeSketch disabled)"
    fi

    # -------------------------------------------------------------------------
    # Forensic Collection (Velociraptor/Offline Collector) - Air-gap Support
    # -------------------------------------------------------------------------
    local velociraptor_enabled
    velociraptor_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velociraptor_enabled"; then
        download_offline_collector_binaries
        download_legacy_velociraptor_binaries
        create_velociraptor_collector
        pull_velociraptor_base_image
    else
        log_info "Velociraptor/offline-collector pre-downloads: SKIPPED (Velociraptor disabled)"
    fi

    # -------------------------------------------------------------------------
    # IRIS — pre-pull all runtime images so compose up doesn't depend on the
    # registry being reachable mid-deploy.
    # -------------------------------------------------------------------------
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        pull_iris_images
    else
        log_info "IRIS image pre-pull: SKIPPED (IRIS disabled)"
    fi

    # -------------------------------------------------------------------------
    # Azure Security Tools (SIGMA Rules + DFIR-O365RC)
    # -------------------------------------------------------------------------
    download_sigma_rules
    pull_dfir_o365rc_image
    generate_azure_certificate

    # -------------------------------------------------------------------------
    # AWS DFIR (CloudTrail + SIGMA) — native, no image to pull. boto3 is
    # installed into the backend by install_deps.py; the SIGMA AWS rule pack
    # is fetched by download_sigma_rules() above when the cloudtrail (or
    # azure) module is enabled in config.yaml.

    # -------------------------------------------------------------------------
    # Backend base image — always built, so always pre-pull. Keeps the
    # ~46 MB python:3.11-slim out of the build's wall-clock budget on
    # slow-uplink VMs.
    # -------------------------------------------------------------------------
    pull_backend_base_image

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------
    update_env_files
    create_data_directory

    # -------------------------------------------------------------------------
    # Services
    # -------------------------------------------------------------------------
    start_services

    # -------------------------------------------------------------------------
    # Verification & Reports
    # -------------------------------------------------------------------------
    # Refresh per-module nginx DNS caches BEFORE the health probes — fixes
    # the stale-upstream race where nginx cached an upstream container's
    # IP at startup and never noticed the upstream was recreated. Caught
    # us with TimeSketch on a fresh install (intact_timesketch_nginx
    # was returning 502 for a perfectly-healthy backend). Restart is
    # idempotent so this is also a no-op on already-healthy nginxes.
    refresh_nginx_upstreams

    verify_installation
    print_installation_report
    create_initialization_marker

    # -------------------------------------------------------------------------
    # Fix Permissions (for development/upgrades)
    # -------------------------------------------------------------------------
    fix_source_permissions

    print_summary
    # Final ATTENTION block listing every warning/error tracked anywhere
    # during the install. Operators currently miss yellow [WARN] lines
    # that scrolled past — this surfaces them right after the success
    # banner so they can't be missed. Pure formatter, no side effects.
    print_final_issues_report
}

# ============================================================================
# Fix Source File Permissions
# ============================================================================
# After upgrades, source files may be owned by root. Fix them so they remain
# editable for development and future upgrades.

fix_source_permissions() {
    log_info "Fixing source file permissions..."
    local uid=$(stat -c '%u' "${SCRIPT_DIR}")
    local gid=$(stat -c '%g' "${SCRIPT_DIR}")

    # Fix ownership for entire project
    chown -R "${uid}:${gid}" "${SCRIPT_DIR}" 2>/dev/null || true

    # Fix directory permissions (755 = rwxr-xr-x)
    find "${SCRIPT_DIR}" -type d -exec chmod 755 {} \; 2>/dev/null || true

    # Fix file permissions (644 = rw-r--r--), but leave secret material that
    # earlier steps in this same run deliberately hardened to a tighter mode
    # untouched: module secrets/ dirs (Portainer admin password, IRIS
    # IRIS_SECRET_KEY/POSTGRES_*_PASSWORD, ...), module .env files (DB/
    # session secrets, GitHub token), the shared Nginx/Kibana TLS private
    # key, the IRIS web TLS private key (a copy of that same shared key),
    # the IRIS Root CA private key, and the Azure cert bundle. Without
    # these exclusions this blanket sweep silently reverted all of that
    # hardening to world-readable 644 on every install/upgrade.
    find "${SCRIPT_DIR}" -type f \
        -not -path "*/modules/*/secrets/*" \
        -not -path "*/modules/*/.env" \
        -not -path "*/modules/nginx/ssl/*.key" \
        -not -path "*/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" \
        -not -path "*/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" \
        -not -path "*/data/azure_cert.pfx" \
        -exec chmod 644 {} \; 2>/dev/null || true

    # Re-assert the restrictive modes (and, for the IRIS web key, the
    # root:33 ownership the iris-nginx container's www-data gid needs) on
    # those same secret files in case any of them predate this run and
    # weren't already at the intended mode (e.g. left over from an older
    # install), or had their ownership reset by the chown -R above.
    find "${SCRIPT_DIR}/modules" -type f \( -path "*/secrets/*" -o -name ".env" \) -exec chmod 600 {} \; 2>/dev/null || true
    [[ -f "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.key" ]] && chmod 640 "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.key" 2>/dev/null || true
    [[ -f "${SCRIPT_DIR}/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" ]] && chmod 600 "${SCRIPT_DIR}/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" 2>/dev/null || true
    if [[ -f "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" ]]; then
        chown root:33 "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" 2>/dev/null || true
        chmod 640 "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" 2>/dev/null || true
    fi
    [[ -f "${SCRIPT_DIR}/data/azure_cert.pfx" ]] && chmod 600 "${SCRIPT_DIR}/data/azure_cert.pfx" 2>/dev/null || true

    # Restore execute permission on scripts
    chmod +x "${SCRIPT_DIR}/install.sh" 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/lib/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/scripts/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/iris/scripts/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/backend/scripts/"*.py 2>/dev/null || true

    log_info "Source file permissions fixed"
}

# ============================================================================
# Entry Point
# ============================================================================

# Initialize log file
touch "$LOG_FILE"

# Run main installation
main "$@"

# Exit with appropriate code. Non-zero on either:
#   - any module's deploy step failed (FAILED_MODULES) — same as before, OR
#   - any deployed module didn't pass its end-to-end health probe
#     (UNHEALTHY_MODULES). Previously the script exited 0 in that case,
#     which lied about the actual state of the platform.
#
# When we DO exit non-zero, list which modules tripped the gate so the
# operator doesn't have to re-grep the install log. Previously this was
# a silent `exit 1` which is unfriendly for both humans and CI logs.
if [[ ${#FAILED_MODULES[@]} -gt 0 ]] || [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]]; then
    log_error "=============================================="
    log_error "Installation finished with critical failures"
    log_error "=============================================="
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        log_error "Failed to deploy (${#FAILED_MODULES[@]} module(s)):"
        for m in "${FAILED_MODULES[@]}"; do
            log_error "  - $m"
        done
    fi
    if [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]]; then
        log_error "Deployed but unhealthy (${#UNHEALTHY_MODULES[@]} module(s)):"
        for m in "${UNHEALTHY_MODULES[@]}"; do
            log_error "  - $m"
        done
    fi
    log_error "Fix the underlying issue and re-run install.sh."
    log_error "Install log: $LOG_FILE"
    exit 1
fi
exit 0
