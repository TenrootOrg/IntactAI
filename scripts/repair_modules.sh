#!/bin/bash
# ============================================================================
# Intact.AI Module Repair Script
# ============================================================================
# Checks for failed/missing modules and attempts to repair them.
#
# Usage: sudo bash scripts/repair_modules.sh [module_name]
#        sudo bash scripts/repair_modules.sh          # Check and repair all
#        sudo bash scripts/repair_modules.sh elk      # Repair specific module
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/repair_$(date +%Y%m%d_%H%M%S).log"

# Logging
log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $1"
    echo -e "${GREEN}[OK]${NC} $1"
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

# Read value from config.yaml
read_config() {
    local key=$1
    python3 -c "import yaml; print(yaml.safe_load(open('${CONFIG_FILE}'))${key})" 2>/dev/null || echo ""
}

# Check if a module's containers are running
check_module_status() {
    local module=$1
    local container_prefix=$2

    local running=$(docker ps --filter "name=${container_prefix}" --format "{{.Names}}" 2>/dev/null | wc -l)
    local total=$(docker ps -a --filter "name=${container_prefix}" --format "{{.Names}}" 2>/dev/null | wc -l)

    if [[ $running -eq 0 ]]; then
        echo "stopped"
    elif [[ $running -lt $total ]]; then
        echo "partial"
    else
        echo "running"
    fi
}

# Repair a specific module
repair_module() {
    local module=$1
    local module_dir=""
    local container_prefix=""

    case $module in
        elk)
            module_dir="${SCRIPT_DIR}/modules/elk"
            container_prefix="intact_elasticsearch\|intact_kibana\|intact_logstash"
            ;;
        timesketch)
            module_dir="${SCRIPT_DIR}/modules/timesketch"
            container_prefix="intact_timesketch"
            ;;
        velociraptor)
            module_dir="${SCRIPT_DIR}/modules/velociraptor"
            container_prefix="velociraptor"
            ;;
        iris)
            module_dir="${SCRIPT_DIR}/modules/iris"
            container_prefix="iriswebapp"
            ;;
        portainer)
            module_dir="${SCRIPT_DIR}/modules/portainer"
            container_prefix="portainer"
            ;;
        backend)
            module_dir="${SCRIPT_DIR}/modules/backend"
            container_prefix="intact_backend"
            ;;
        nginx)
            module_dir="${SCRIPT_DIR}/modules/nginx"
            container_prefix="intact_nginx"
            ;;
        *)
            log_error "Unknown module: $module"
            return 1
            ;;
    esac

    log_info "Repairing module: $module"

    if [[ ! -d "$module_dir" ]]; then
        log_error "Module directory not found: $module_dir"
        return 1
    fi

    cd "$module_dir"

    # Stop existing containers
    log_info "  Stopping existing containers..."
    docker compose down 2>/dev/null || true

    # Remove any failed containers
    log_info "  Cleaning up..."
    docker compose rm -f 2>/dev/null || true

    # Start fresh
    log_info "  Starting module..."
    if docker compose up -d 2>> "$LOG_FILE"; then
        sleep 10
        log_success "  Module $module repaired successfully"
        return 0
    else
        log_error "  Failed to repair module $module"
        return 1
    fi
}

# Check all modules and report status
check_all_modules() {
    echo ""
    echo "=============================================="
    echo "          Intact.AI Module Status Check"
    echo "=============================================="
    echo ""

    local modules=("elk" "timesketch" "velociraptor" "iris" "portainer" "backend" "nginx")
    local prefixes=("intact_elasticsearch" "intact_timesketch" "velociraptor" "iriswebapp" "portainer" "intact_backend" "intact_nginx")
    local failed_modules=()

    for i in "${!modules[@]}"; do
        local module="${modules[$i]}"
        local prefix="${prefixes[$i]}"
        local status=$(check_module_status "$module" "$prefix")

        case $status in
            running)
                echo -e "  ${GREEN}✓${NC} $module: Running"
                ;;
            partial)
                echo -e "  ${YELLOW}⚠${NC} $module: Partially running"
                failed_modules+=("$module")
                ;;
            stopped)
                echo -e "  ${RED}✗${NC} $module: Stopped/Failed"
                failed_modules+=("$module")
                ;;
        esac
    done

    echo ""

    if [[ ${#failed_modules[@]} -eq 0 ]]; then
        echo -e "${GREEN}All modules are running correctly${NC}"
    else
        echo -e "${YELLOW}Failed/Stopped modules: ${failed_modules[*]}${NC}"
        echo ""
        echo "To repair all failed modules:"
        echo "  sudo bash scripts/repair_modules.sh --repair-failed"
        echo ""
        echo "To repair a specific module:"
        echo "  sudo bash scripts/repair_modules.sh <module_name>"
    fi

    echo ""

    # Return failed modules for potential repair
    echo "${failed_modules[@]}"
}

# Repair all failed modules
repair_failed_modules() {
    local failed=$(check_all_modules)
    local failed_array=($failed)

    if [[ ${#failed_array[@]} -eq 0 ]]; then
        log_info "No failed modules to repair"
        return 0
    fi

    echo ""
    echo "=============================================="
    echo "        Repairing Failed Modules"
    echo "=============================================="
    echo ""

    local repaired=0
    local still_failed=0

    for module in "${failed_array[@]}"; do
        if repair_module "$module"; then
            ((repaired++))
        else
            ((still_failed++))
        fi
    done

    echo ""
    echo "=============================================="
    echo "              Repair Summary"
    echo "=============================================="
    echo ""
    echo -e "  ${GREEN}Repaired: $repaired${NC}"
    echo -e "  ${RED}Still failed: $still_failed${NC}"
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""
}

# Show usage
show_usage() {
    echo "Intact.AI Module Repair Script"
    echo ""
    echo "Usage:"
    echo "  sudo bash scripts/repair_modules.sh              # Check module status"
    echo "  sudo bash scripts/repair_modules.sh --repair-failed  # Repair all failed"
    echo "  sudo bash scripts/repair_modules.sh <module>     # Repair specific module"
    echo ""
    echo "Available modules:"
    echo "  elk, timesketch, velociraptor, iris, portainer, backend, nginx"
    echo ""
    echo "Options:"
    echo "  --repair-failed    Automatically repair all failed modules"
    echo "  --help, -h         Show this help message"
    echo ""
}

# Main
main() {
    echo ""
    echo "Log file: $LOG_FILE"

    case "${1:-}" in
        --help|-h)
            show_usage
            ;;
        --repair-failed)
            repair_failed_modules
            ;;
        "")
            check_all_modules > /dev/null
            check_all_modules | head -n -1  # Remove the failed modules list from output
            ;;
        *)
            repair_module "$1"
            ;;
    esac
}

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

main "$@"
