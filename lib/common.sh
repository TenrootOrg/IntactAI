#!/bin/bash
# Intact.AI Platform Installer - Common Functions
# Logging, tracking, and utility functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Module tracking arrays
FAILED_MODULES=()
SUCCEEDED_MODULES=()

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

# ============================================================================
# Module Tracking Functions
# ============================================================================

track_module_success() {
    SUCCEEDED_MODULES+=("$1")
    log_success "$1 deployed successfully"
}

track_module_failure() {
    FAILED_MODULES+=("$1")
    log_error "$1 deployment FAILED"
}

# ============================================================================
# Utility Functions
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if a value is truthy (handles yaml boolean variations)
# Usage: if is_enabled "$value"; then ...
is_enabled() {
    local val="${1,,}"  # Convert to lowercase
    [[ "$val" == "true" || "$val" == "yes" || "$val" == "1" ]]
}

# Wait for a condition with timeout (replaces fixed sleep)
# Usage: wait_for_condition "description" timeout_seconds "command to check"
wait_for_condition() {
    local description="$1"
    local timeout="$2"
    local check_cmd="$3"
    local interval="${4:-2}"  # Default 2 second interval
    local waited=0

    log_info "Waiting for ${description}..."

    while ! eval "$check_cmd" > /dev/null 2>&1; do
        if [[ $waited -ge $timeout ]]; then
            log_warn "${description} not ready after ${timeout}s"
            return 1
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done

    log_success "${description} is ready (${waited}s)"
    return 0
}

# Wait for container to be running
# Usage: wait_for_container "container_name" timeout_seconds
wait_for_container() {
    local container="$1"
    local timeout="${2:-60}"

    wait_for_condition "container ${container}" "$timeout" \
        "docker ps --filter 'name=${container}' --filter 'status=running' --format '{{.Names}}' | grep -q '${container}'"
}

# Wait for HTTP endpoint to respond
# Usage: wait_for_http "url" timeout_seconds
wait_for_http() {
    local url="$1"
    local timeout="${2:-60}"

    wait_for_condition "HTTP endpoint ${url}" "$timeout" \
        "curl -sf --max-time 5 '${url}'"
}

# ============================================================================
# Network Connectivity Check
# ============================================================================

check_network_connectivity() {
    log_info "Checking network connectivity..."
    local has_issues=false

    # Test 1: Can we reach the internet at all? (IP connectivity)
    if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
        log_error "No internet connectivity (cannot ping 8.8.8.8)"
        log_error "Please check your network configuration"
        return 1
    fi
    log_success "Internet connectivity: OK"

    # Test 2: Does DNS resolution work?
    if ! ping -c 1 -W 3 google.com &> /dev/null; then
        log_error "DNS resolution not working (cannot resolve google.com)"
        log_error "Please configure DNS in /etc/resolv.conf"
        log_error "Quick fix: echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
        has_issues=true
    else
        log_success "DNS resolution: OK"
    fi

    # Test 3: Can we reach Docker's download server?
    if ! curl -sf --max-time 5 -o /dev/null https://download.docker.com 2>/dev/null; then
        log_error "Cannot reach download.docker.com"
        if command -v docker &> /dev/null; then
            log_warn "Docker is already installed, continuing..."
        else
            log_error "Docker installation will fail without access to download.docker.com"
            has_issues=true
        fi
    else
        log_success "Docker download server: Reachable"
    fi

    if [[ "$has_issues" == "true" ]]; then
        log_error "Network issues detected - installation may fail"
        return 1
    fi

    return 0
}

# ============================================================================
# Installation Marker Functions
# ============================================================================

check_initialization_marker() {
    local marker="/etc/mssp-initialized"
    if [[ -f "$marker" ]]; then
        log_warn "Intact.AI was previously initialized on this system"
        cat "$marker"
        echo ""
        read -p "Re-initialize? This will reconfigure services. (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            log_info "Installation cancelled by user"
            exit 0
        fi
    fi
}

create_initialization_marker() {
    local marker="/etc/mssp-initialized"
    local domain=$(read_config "['domain']")
    echo "Intact.AI Platform initialized on $(date)" > "$marker"
    echo "Domain: $domain" >> "$marker"
    log_info "Created initialization marker: $marker"
}
