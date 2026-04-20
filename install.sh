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
    if ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    fi

    # -------------------------------------------------------------------------
    # Core Dependencies
    # -------------------------------------------------------------------------
    install_dependencies
    install_docker
    create_network

    # -------------------------------------------------------------------------
    # Timeline Processing (Plaso/Timesketch) - Air-gap Support
    # -------------------------------------------------------------------------
    pull_plaso_image
    pull_python_alpine_image
    download_timesketch_packages

    # -------------------------------------------------------------------------
    # Forensic Collection (Velociraptor/Offline Collector) - Air-gap Support
    # -------------------------------------------------------------------------
    download_offline_collector_binaries
    create_velociraptor_collector

    # -------------------------------------------------------------------------
    # Azure Security Tools (SIGMA Rules + DFIR-O365RC)
    # -------------------------------------------------------------------------
    download_sigma_rules
    pull_dfir_o365rc_image
    generate_azure_certificate

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
    verify_installation
    print_installation_report
    create_initialization_marker

    # -------------------------------------------------------------------------
    # Fix Permissions (for development/upgrades)
    # -------------------------------------------------------------------------
    fix_source_permissions

    print_summary
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

    # Fix file permissions (644 = rw-r--r--)
    find "${SCRIPT_DIR}" -type f -exec chmod 644 {} \; 2>/dev/null || true

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

# Exit with appropriate code
if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
    exit 1
fi
exit 0
