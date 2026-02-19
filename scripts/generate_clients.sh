#!/bin/bash

# Generate Velociraptor Client Installers
# This script generates client installers during platform installation
# Clients are stored in a persistent location for the backend to serve

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[CLIENT-GEN]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[CLIENT-GEN]${NC} $1"
}

log_error() {
    echo -e "${RED}[CLIENT-GEN]${NC} $1"
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MSSP_ROOT="$(dirname "$SCRIPT_DIR")"

# Output directory - will be mounted to backend container
OUTPUT_DIR="${MSSP_ROOT}/client_installers"
VELOCIRAPTOR_CONTAINER="mssp_velociraptor"

# ============================================================================
# Main Generation Function
# ============================================================================

generate_clients() {
    log_info "============================================================"
    log_info "Generating Velociraptor Client Installers"
    log_info "============================================================"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Check if Velociraptor container is running
    if ! docker ps | grep -q "$VELOCIRAPTOR_CONTAINER"; then
        log_error "Velociraptor container is not running!"
        log_error "Please ensure Velociraptor is started before generating clients"
        exit 1
    fi

    # Wait for Velociraptor to be fully ready (check for client config file)
    log_info "Waiting for Velociraptor to initialize..."
    local wait_count=0
    local max_wait=30
    while [ $wait_count -lt $max_wait ]; do
        if docker exec "$VELOCIRAPTOR_CONTAINER" test -f /velociraptor/client.config.yaml 2>/dev/null; then
            log_info "Velociraptor is ready"
            break
        fi
        sleep 2
        ((wait_count+=2))
    done

    if [ $wait_count -ge $max_wait ]; then
        log_error "Velociraptor did not initialize in time"
        exit 1
    fi

    local success_count=0
    local total_count=2

    # Generate Windows MSI (use ORIGINAL binary from /opt, not repacked one)
    log_info "Generating Windows MSI..."
    if docker exec "$VELOCIRAPTOR_CONTAINER" \
        /velociraptor/velociraptor config repack \
        --msi /opt/velociraptor/windows/velociraptor_client.msi \
        /velociraptor/client.config.yaml \
        /tmp/velociraptor-client-windows.msi 2>&1; then

        if docker cp "${VELOCIRAPTOR_CONTAINER}:/tmp/velociraptor-client-windows.msi" \
            "${OUTPUT_DIR}/velociraptor-client-windows.msi" > /dev/null 2>&1; then
            local size=$(stat -c%s "${OUTPUT_DIR}/velociraptor-client-windows.msi" 2>/dev/null)
            local size_mb=$((size / 1024 / 1024))
            log_success "✓ Windows MSI: Generated successfully (${size_mb}MB)"
            ((success_count++))
        else
            log_error "✗ Windows MSI: Failed to copy from container"
        fi
    else
        log_error "✗ Windows MSI: Repacking command failed"
    fi

    # Generate Linux (use ORIGINAL binary from /opt, not repacked one)
    log_info "Generating Linux client..."
    if docker exec "$VELOCIRAPTOR_CONTAINER" \
        /velociraptor/velociraptor config repack \
        --exe /opt/velociraptor/linux/velociraptor \
        /velociraptor/client.config.yaml \
        /tmp/velociraptor-client-linux 2>&1; then

        if docker cp "${VELOCIRAPTOR_CONTAINER}:/tmp/velociraptor-client-linux" \
            "${OUTPUT_DIR}/velociraptor-client-linux" > /dev/null 2>&1; then
            local size=$(stat -c%s "${OUTPUT_DIR}/velociraptor-client-linux" 2>/dev/null)
            local size_mb=$((size / 1024 / 1024))
            log_success "✓ Linux: Generated successfully (${size_mb}MB)"
            ((success_count++))
        else
            log_error "✗ Linux: Failed to copy from container"
        fi
    else
        log_error "✗ Linux: Repacking command failed"
    fi

    # Summary
    log_info "============================================================"
    if [ $success_count -eq $total_count ]; then
        log_success "All clients generated successfully (${success_count}/${total_count})"
        log_info "Clients stored in: ${OUTPUT_DIR}"
        return 0
    elif [ $success_count -gt 0 ]; then
        log_info "Partial success: ${success_count}/${total_count} clients generated"
        log_info "Clients stored in: ${OUTPUT_DIR}"
        return 0
    else
        log_error "Failed to generate any clients"
        return 1
    fi
}

# ============================================================================
# Run
# ============================================================================

generate_clients
