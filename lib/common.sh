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
# Modules whose containers came up but failed end-to-end health probes after
# deploy. Populated by verify_installation() in lib/health.sh. Distinct from
# FAILED_MODULES because the deploy step succeeded — only the runtime check
# didn't. Lets the final summary distinguish "compose up failed" from
# "compose up succeeded but the service isn't actually serving requests".
UNHEALTHY_MODULES=()

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

# Run a command (e.g. `docker compose build`) with heartbeat logging and a
# hard timeout. Catches the failure mode we hit on 2026-04-29 where install.sh
# stopped writing to the log mid-Backend-build at 08:39 with no error and no
# timeout — operator had no visibility into whether the build was alive.
#
# Usage: run_with_heartbeat <description> <timeout_seconds> <command...>
# Behavior:
#   - Runs <command...> in the foreground; output streams to the log as normal.
#   - Spawns a background heartbeat that emits "[INFO] still <description>
#     (<elapsed>s elapsed)" every 60s, so silence in the build output doesn't
#     look like the script froze.
#   - If the command runs longer than <timeout_seconds>, kills it (and its
#     process group) and returns 124, matching the convention in coreutils
#     `timeout(1)`.
#   - Otherwise returns the command's own exit code.
run_with_heartbeat() {
    local description="$1"
    local timeout_secs="$2"
    shift 2

    local start_ts=$SECONDS
    local heartbeat_interval=60

    # Background heartbeat loop. Exits when its parent (the wrapping shell
    # function) goes away, but we also explicitly kill it on completion.
    (
        while sleep "$heartbeat_interval"; do
            local elapsed=$((SECONDS - start_ts))
            log_info "  ... still ${description} (${elapsed}s elapsed)"
        done
    ) &
    local heartbeat_pid=$!
    # Make sure the heartbeat dies even if we're killed/interrupted.
    # shellcheck disable=SC2064
    trap "kill ${heartbeat_pid} 2>/dev/null; trap - RETURN INT TERM" RETURN INT TERM

    # `timeout` from coreutils handles the hard kill cleanly, including the
    # process group via --foreground when invoked from a non-tty context.
    timeout --foreground "${timeout_secs}" "$@"
    local rc=$?

    kill "${heartbeat_pid}" 2>/dev/null
    wait "${heartbeat_pid}" 2>/dev/null

    if [[ $rc -eq 124 ]]; then
        log_error "  ${description} exceeded ${timeout_secs}s timeout — killed"
    fi
    return $rc
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
    local marker="/etc/intact-initialized"
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
    local marker="/etc/intact-initialized"
    local domain=$(read_config "['domain']")
    echo "Intact.AI Platform initialized on $(date)" > "$marker"
    echo "Domain: $domain" >> "$marker"
    log_info "Created initialization marker: $marker"
}
