#!/bin/bash
# ============================================================================
# Intact.AI Clean/Uninstall Script
# ============================================================================
# Removes all Intact.AI containers, volumes, networks, and optionally data.
# Use with caution - this is destructive!
#
# Usage: sudo bash scripts/clean.sh [options]
#        sudo bash scripts/clean.sh              # Interactive mode
#        sudo bash scripts/clean.sh --all        # Remove everything
#        sudo bash scripts/clean.sh --containers # Remove only containers
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Stop all Intact.AI containers
stop_containers() {
    log_info "Stopping all Intact.AI containers..."

    local modules=("elk" "timesketch" "velociraptor" "iris" "portainer" "backend" "nginx")

    for module in "${modules[@]}"; do
        local module_dir="${SCRIPT_DIR}/modules/${module}"
        if [[ -d "$module_dir" ]] && [[ -f "$module_dir/docker-compose.yaml" ]]; then
            log_info "  Stopping $module..."
            cd "$module_dir"
            docker compose down 2>/dev/null || true
        fi
    done

    log_success "All containers stopped"
}

# Remove all Intact.AI containers
remove_containers() {
    log_info "Removing all Intact.AI containers..."

    # Remove by name pattern
    local containers=$(docker ps -a --filter "name=intact_" --filter "name=velociraptor" --filter "name=iriswebapp" --filter "name=portainer" -q 2>/dev/null)

    if [[ -n "$containers" ]]; then
        docker rm -f $containers 2>/dev/null || true
        log_success "Containers removed"
    else
        log_info "  No Intact.AI containers found"
    fi
}

# Remove all Intact.AI volumes
remove_volumes() {
    log_info "Removing all Intact.AI Docker volumes..."

    # List of volume prefixes to remove
    local volume_patterns=(
        "elk_"
        "timesketch_"
        "velociraptor_"
        "iris_"
        "portainer_"
        "backend_"
        "nginx_"
        "intact_"
    )

    local removed=0
    for pattern in "${volume_patterns[@]}"; do
        local volumes=$(docker volume ls -q --filter "name=${pattern}" 2>/dev/null)
        if [[ -n "$volumes" ]]; then
            for vol in $volumes; do
                docker volume rm "$vol" 2>/dev/null && ((removed++)) || true
            done
        fi
    done

    if [[ $removed -gt 0 ]]; then
        log_success "Removed $removed volumes"
    else
        log_info "  No Intact.AI volumes found"
    fi
}

# Remove Intact.AI network
remove_network() {
    log_info "Removing Intact.AI network..."

    if docker network inspect intact_network &>/dev/null; then
        docker network rm intact_network 2>/dev/null || true
        log_success "Network removed"
    else
        log_info "  Network not found"
    fi
}

# Remove Intact.AI images
remove_images() {
    log_info "Removing Intact.AI Docker images..."

    local image_patterns=(
        "velociraptor-server"
        "intact_"
    )

    local removed=0
    for pattern in "${image_patterns[@]}"; do
        local images=$(docker images --filter "reference=*${pattern}*" -q 2>/dev/null)
        if [[ -n "$images" ]]; then
            for img in $images; do
                docker rmi -f "$img" 2>/dev/null && ((removed++)) || true
            done
        fi
    done

    if [[ $removed -gt 0 ]]; then
        log_success "Removed $removed images"
    else
        log_info "  No Intact.AI images found"
    fi
}

# Remove data directory
remove_data() {
    log_info "Removing data directory..."

    if [[ -d "${SCRIPT_DIR}/data" ]]; then
        rm -rf "${SCRIPT_DIR}/data"/*.json 2>/dev/null || true
        log_success "Data files removed"
    else
        log_info "  Data directory not found"
    fi
}

# Remove client installers
remove_client_installers() {
    log_info "Removing client installers..."

    if [[ -d "${SCRIPT_DIR}/client_installers" ]]; then
        rm -rf "${SCRIPT_DIR}/client_installers"
        log_success "Client installers removed"
    else
        log_info "  Client installers directory not found"
    fi
}

# Note: .env files are tracked in git and should NOT be deleted
# They are templates that get updated (not generated) during installation

# Remove log files
remove_logs() {
    log_info "Removing log files..."

    rm -f "${SCRIPT_DIR}"/install_*.log 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/scripts/prepare_offline_*.log 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/scripts/repair_*.log 2>/dev/null || true

    log_success "Log files removed"
}

# Full cleanup
clean_all() {
    echo ""
    log_warn "This will remove ALL Intact.AI components:"
    echo "  - All containers"
    echo "  - All Docker volumes (DATA WILL BE LOST)"
    echo "  - Intact.AI network"
    echo "  - Docker images"
    echo "  - Client installers"
    echo "  - Log files"
    echo "  (Note: .env files are preserved)"
    echo ""

    if [[ "$FORCE" != "true" ]]; then
        read -p "Are you sure you want to continue? (yes/no) " -r
        echo
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log_info "Aborted"
            exit 0
        fi
    fi

    stop_containers
    remove_containers
    remove_volumes
    remove_network
    remove_images
    remove_data
    remove_client_installers
    remove_logs

    echo ""
    log_success "=============================================="
    log_success "  Intact.AI cleanup completed"
    log_success "=============================================="
    echo ""
    echo "To reinstall, run: sudo bash install.sh"
    echo ""
}

# Containers only cleanup
clean_containers_only() {
    log_info "Removing containers only (keeping volumes and data)..."
    stop_containers
    remove_containers
    log_success "Container cleanup completed"
}

# Show usage
show_usage() {
    echo "Intact.AI Clean/Uninstall Script"
    echo ""
    echo "Usage: sudo bash scripts/clean.sh [options]"
    echo ""
    echo "Options:"
    echo "  --all              Remove everything (containers, volumes, data, configs)"
    echo "  --containers       Remove containers only (keep volumes and data)"
    echo "  --volumes          Remove Docker volumes only"
    echo "  --images           Remove Docker images only"
    echo "  --data             Remove data directory only"
    echo "  --logs             Remove log files only"
    echo "  --force            Skip confirmation prompts"
    echo "  --help, -h         Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo bash scripts/clean.sh --all           # Full cleanup"
    echo "  sudo bash scripts/clean.sh --containers    # Stop and remove containers"
    echo "  sudo bash scripts/clean.sh --all --force   # Full cleanup without prompts"
    echo ""
}

# Interactive mode
interactive_mode() {
    echo ""
    echo "=============================================="
    echo "       Intact.AI Clean/Uninstall Script"
    echo "=============================================="
    echo ""
    echo "What would you like to remove?"
    echo ""
    echo "  1) Everything (full cleanup)"
    echo "  2) Containers only (keep data)"
    echo "  3) Volumes only"
    echo "  4) Images only"
    echo "  5) Logs only"
    echo "  6) Cancel"
    echo ""
    read -p "Select option [1-6]: " -r choice
    echo ""

    case $choice in
        1) clean_all ;;
        2) clean_containers_only ;;
        3) remove_volumes ;;
        4) remove_images ;;
        5) remove_logs ;;
        6) log_info "Cancelled" ;;
        *) log_error "Invalid option" ;;
    esac
}

# Main
main() {
    check_root

    FORCE=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                clean_all
                exit 0
                ;;
            --containers)
                clean_containers_only
                exit 0
                ;;
            --volumes)
                remove_volumes
                exit 0
                ;;
            --images)
                remove_images
                exit 0
                ;;
            --data)
                remove_data
                exit 0
                ;;
            --logs)
                remove_logs
                exit 0
                ;;
            --force)
                FORCE=true
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
        shift
    done

    # If no arguments, run interactive mode
    interactive_mode
}

main "$@"
