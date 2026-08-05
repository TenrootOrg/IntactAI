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

    # volweb was missing here: its six containers were only ever caught by the
    # `name=intact_` force-rm below, so `docker compose down` never ran for it
    # and its networks/volumes were left behind.
    local modules=("elk" "timesketch" "velociraptor" "iris" "portainer" "volweb" "backend" "nginx")

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

    # List of volume prefixes to remove.
    #
    # `volweb_` was absent, so a "full" clean left volweb_volweb_postgres_data,
    # _media, _redis_data and _staticfiles behind -- observed on 2026-08-05,
    # where --all reported success and 7 volumes survived. A prefix list also
    # cannot match ANONYMOUS volumes (bare 64-hex names), of which that same
    # run left three; those are swept separately below.
    local volume_patterns=(
        "elk_"
        "timesketch_"
        "velociraptor_"
        "iris_"
        "portainer_"
        "volweb_"
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

    # Anonymous volumes: a compose service with an unnamed volume gets a
    # 64-hex-character name no prefix can match, and they are pure Intact.AI
    # leftovers once the containers above are gone. `docker volume prune`
    # only ever removes volumes no container references, so this cannot touch
    # anything still in use by something else on the box.
    local dangling
    dangling=$(docker volume ls -qf dangling=true 2>/dev/null \
               | grep -E '^[0-9a-f]{64}$' || true)
    if [[ -n "$dangling" ]]; then
        local anon=0
        for vol in $dangling; do
            docker volume rm "$vol" 2>/dev/null && anon=$((anon + 1)) || true
        done
        (( anon > 0 )) && log_success "Removed $anon anonymous volume(s)"
        removed=$((removed + anon))
    fi

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

    # iris_internal is created by IRIS's compose. `docker compose down` should
    # remove it, but clean it up here too in case compose-down was skipped or
    # interrupted, leaving an orphan that blocks the next install.
    if docker network inspect iris_internal &>/dev/null; then
        docker network rm iris_internal 2>/dev/null || true
        log_success "iris_internal network removed"
    fi
}

# Remove the state install.sh writes OUTSIDE the install tree.
#
# Neither of these was ever cleaned, so "--all then reinstall" was not a fresh
# install: the marker made install.sh prompt "Re-initialize? (y/N)" (QA works
# around it with an explicit `rm -f`, see qa/phases/platform.py), and
# /opt/sigma-rules survived to be reused instead of re-cloned at the pinned
# tag. Both are created by the installer and belong to it alone.
remove_host_state() {
    log_info "Removing host-level Intact.AI state..."

    if [[ -e /etc/intact-initialized ]]; then
        rm -f /etc/intact-initialized && \
            log_success "  Removed /etc/intact-initialized (next install runs clean)"
    fi

    # Cloned by download_sigma_rules() into a fixed path; nothing else owns it.
    if [[ -d /opt/sigma-rules ]]; then
        rm -rf /opt/sigma-rules && log_success "  Removed /opt/sigma-rules"
    fi
}

# Remove Intact.AI images
remove_images() {
    log_info "Removing Intact.AI Docker images..."

    # ASK COMPOSE, don't guess. These two patterns matched only the images we
    # BUILD -- every upstream image the platform pulls (elasticsearch, kibana,
    # logstash, timesketch, opensearch, iris, rabbitmq, postgres, redis, nginx,
    # portainer, volweb, tusd, plaso) is named by its own vendor and matched
    # neither. Measured 2026-08-05: `--all` reported success having removed
    # 1 image of 29, leaving 15.5 GB on disk.
    #
    # `docker compose config --images` resolves each module's compose file
    # with its .env and prints exactly the images that module uses -- which is
    # the authoritative list, stays correct when a pin changes, and cannot
    # sweep up an unrelated `nginx:latest` the operator happens to have.
    local image_patterns=(
        "velociraptor-server"
        "intact_"
        "intact-backend"
    )

    local -a compose_images=()
    local _m _img
    for _m in elk timesketch velociraptor iris portainer volweb backend nginx; do
        local _dir="${SCRIPT_DIR}/modules/${_m}"
        [[ -f "$_dir/docker-compose.yaml" ]] || continue
        while IFS= read -r _img; do
            [[ -n "$_img" ]] && compose_images+=("$_img")
        done < <(cd "$_dir" && docker compose config --images 2>/dev/null || true)
    done

    local removed=0
    for _img in "${compose_images[@]}"; do
        # By exact reference: no globbing, so `nginx:1.31.2-alpine` goes and a
        # different nginx tag stays.
        local ids
        ids=$(docker images -q "$_img" 2>/dev/null)
        if [[ -n "$ids" ]]; then
            for img in $ids; do
                docker rmi -f "$img" 2>/dev/null && ((removed++)) || true
            done
        fi
    done

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
    echo "  - All Docker volumes (DATA WILL BE LOST), incl. anonymous ones"
    echo "  - Intact.AI networks"
    echo "  - Docker images used by every module's compose file"
    echo "  - Client installers"
    echo "  - Log files"
    echo "  - /etc/intact-initialized and /opt/sigma-rules"
    echo "  (Note: .env files and config.yaml are preserved)"
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
    remove_host_state

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

    # TWO PASSES, and it matters. This loop used to run the action AND
    # `exit 0` inline, so `--force` was only honoured when it came FIRST:
    # the documented `clean.sh --all --force` dispatched clean_all before it
    # ever reached the --force case, hit the confirmation prompt, and aborted.
    # A "skip confirmation" flag that silently does nothing depending on
    # argument order is worse than no flag. Collect flags first, then act.
    local action=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all|--containers|--volumes|--images|--data|--logs)
                if [[ -n "$action" && "$action" != "$1" ]]; then
                    log_error "Pick one action; got both $action and $1"
                    exit 1
                fi
                action="$1"
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

    case "$action" in
        --all)        clean_all ;;
        --containers) clean_containers_only ;;
        --volumes)    remove_volumes ;;
        --images)     remove_images ;;
        --data)       remove_data ;;
        --logs)       remove_logs ;;
        # If no action was given, run interactive mode
        "")           interactive_mode ;;
    esac
}

main "$@"
