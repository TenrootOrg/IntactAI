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

    # Prerequisites
    check_root
    check_ubuntu
    check_config

    # Check network connectivity (for online installs)
    if ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    fi

    # Install dependencies
    install_dependencies
    install_docker

    # Setup
    create_network

    # Pull required images
    pull_plaso_image

    # Configure
    update_env_files

    # Create data directory for SQLite database
    create_data_directory

    # Install services
    start_services

    # Verify
    verify_installation

    # Reports
    print_installation_report
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
