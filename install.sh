#!/bin/bash
# MSSP Platform Installer
# For Ubuntu 24.04
#
# This script installs and configures the MSSP platform.
#
# Usage: sudo bash install.sh

set -o pipefail

# ============================================================================
# Script Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

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
    echo "       MSSP Platform Installer"
    echo "=============================================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    log_info "Starting MSSP installation..."

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
    print_summary
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
