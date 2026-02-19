#!/bin/bash
# MSSP Platform - VM Image Preparation Script
# Cleans all development artifacts before exporting VM for distribution
#
# Usage: sudo bash prepare-image.sh [--dry-run] [--keep-claude] [--keep-git]
#
# Options:
#   --dry-run      Preview what would be deleted without deleting
#   --keep-claude  Keep Claude Code files (conversation history, API keys)
#   --keep-git     Keep .git directory (allows git push after cleanup)
#
# What gets cleaned:
#   - Docker containers and volumes (client/case data)
#   - SQLite databases and reports
#   - Log files
#   - SSL certificates (regenerated on first-init)
#   - Client installers (regenerated on first-init)
#   - Claude Code files and API keys
#   - Development files (.git, .vscode-server, caches, history)
#
# What stays:
#   - config.yaml (client edits this)
#   - data/tools/ (forensic tools for air-gapped)
#   - All source code

# Don't use set -e, we handle errors ourselves

# ============================================================================
# Configuration
# ============================================================================

# Go up one level from scripts/ to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Get actual user's home (not root when using sudo)
if [[ -n "$SUDO_USER" ]]; then
    HOME_DIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    HOME_DIR="$HOME"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Flags
DRY_RUN=false
KEEP_CLAUDE=false
KEEP_GIT=false

# Counters
ITEMS_CLEANED=0

# ============================================================================
# Helper Functions
# ============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_dry() { echo -e "${YELLOW}[DRY-RUN]${NC} Would delete: $1"; }

get_size() {
    local path="$1"
    if [[ -e "$path" ]]; then
        du -sh "$path" 2>/dev/null | cut -f1
    else
        echo "0"
    fi
}

safe_remove() {
    local path="$1"
    local description="$2"

    if [[ -e "$path" ]]; then
        local size=$(get_size "$path")
        if [[ "$DRY_RUN" == true ]]; then
            log_dry "$path ($size)"
        else
            rm -rf "$path" 2>/dev/null || true
            log_success "Removed: $description ($size)"
            ((ITEMS_CLEANED++)) || true
        fi
    fi
}

safe_remove_glob() {
    local pattern="$1"
    local description="$2"

    local files=$(ls -d $pattern 2>/dev/null || true)
    if [[ -n "$files" ]]; then
        for file in $files; do
            safe_remove "$file" "$description"
        done
    fi
}

# ============================================================================
# Cleanup Functions
# ============================================================================

clean_containers() {
    log_info "Removing Docker containers..."

    # Get container count first
    local count=$(docker ps -aq --filter "name=mssp_" 2>/dev/null | wc -l)

    if [[ $count -gt 0 ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            log_dry "$count Docker containers"
        else
            log_info "  Found $count containers, removing one by one..."
            local removed=0
            for container in $(docker ps -aq --filter "name=mssp_" 2>/dev/null); do
                docker rm -f "$container" >/dev/null 2>&1 || true
                ((removed++)) || true
                # Show progress every 10 containers
                if [[ $((removed % 10)) -eq 0 ]]; then
                    log_info "  Removed $removed/$count containers..."
                fi
            done
            log_success "Removed $removed containers"
            ((ITEMS_CLEANED++)) || true
        fi
    else
        log_info "  No containers found"
    fi
}

clean_volumes() {
    log_info "Removing Docker volumes..."

    local volumes=(
        "velociraptor_data" "velociraptor_datastore" "velociraptor_tmp"
        "timesketch_postgres_data" "timesketch_opensearch_data" "timesketch_upload" "timesketch_logs"
        "iris_db_data" "iris_downloads" "iris_templates" "iris_server_data"
        "portainer_data" "elasticsearch_data"
    )

    local prefixes=("" "modules_" "mssp_" "iris_" "timesketch_" "velociraptor_" "elk_" "portainer_")

    for prefix in "${prefixes[@]}"; do
        for vol in "${volumes[@]}"; do
            local full_vol="${prefix}${vol}"
            if docker volume inspect "$full_vol" > /dev/null 2>&1; then
                if [[ "$DRY_RUN" == true ]]; then
                    log_dry "Volume: $full_vol"
                else
                    docker volume rm "$full_vol" 2>/dev/null || true
                    log_success "Removed volume: $full_vol"
                    ((ITEMS_CLEANED++)) || true
                fi
            fi
        done
    done
}

clean_databases() {
    log_info "Removing databases and reports..."

    safe_remove "$SCRIPT_DIR/data/mssp.db" "Main database"
    safe_remove "$SCRIPT_DIR/data/mssp.db-shm" "Database shm"
    safe_remove "$SCRIPT_DIR/data/mssp.db-wal" "Database wal"
    safe_remove "$SCRIPT_DIR/data/scheduler_jobs.db" "Scheduler database"
    safe_remove "$SCRIPT_DIR/data/frontend_data.db" "Frontend database"
    safe_remove "$SCRIPT_DIR/data/reports" "Reports directory"
    safe_remove_glob "$SCRIPT_DIR/data/*.json.migrated" "Migration artifacts"
    safe_remove_glob "$SCRIPT_DIR/data/*.json" "Legacy JSON data"
}

clean_logs() {
    log_info "Removing log files..."

    safe_remove_glob "$SCRIPT_DIR/install_*.log" "Install logs"
    safe_remove_glob "$SCRIPT_DIR/first-init_*.log" "First-init logs"
    safe_remove "/tmp/plaso" "Plaso temp files"
    safe_remove "$SCRIPT_DIR/modules/backend/logs" "Backend logs"
    safe_remove "/etc/mssp-initialized" "Initialization marker"
}

clean_certs() {
    log_info "Removing SSL certificates..."

    safe_remove "$SCRIPT_DIR/modules/nginx/ssl/nginx-cert.crt" "Nginx cert"
    safe_remove "$SCRIPT_DIR/modules/nginx/ssl/nginx-cert.key" "Nginx key"
    safe_remove_glob "$SCRIPT_DIR/modules/iris/config/certificates/rootCA/*.pem" "IRIS CA"
    safe_remove_glob "$SCRIPT_DIR/modules/iris/config/certificates/web_certificates/*.pem" "IRIS web cert"

    # IRIS secrets (keep .gitkeep)
    for f in "$SCRIPT_DIR/modules/iris/secrets/"*; do
        [[ ! -e "$f" ]] && continue
        [[ "$(basename "$f")" == ".gitkeep" ]] && continue
        safe_remove "$f" "IRIS secret"
    done
}

clean_installers() {
    log_info "Removing client installers..."

    if [[ -d "$SCRIPT_DIR/client_installers" ]]; then
        safe_remove_glob "$SCRIPT_DIR/client_installers/*" "Client installers"
    fi

    # Only remove generated MSI installers, keep everything else (velociraptor binaries, tools, etc.)
    if [[ -d "$SCRIPT_DIR/modules/nginx/html/downloads" ]]; then
        for f in "$SCRIPT_DIR/modules/nginx/html/downloads/"*.msi; do
            [[ ! -e "$f" ]] && continue
            safe_remove "$f" "MSI installer: $(basename "$f")"
        done
    fi
}

clean_claude() {
    log_info "Removing Claude Code files (includes API keys)..."

    safe_remove "$HOME_DIR/.claude" "Claude session data"
    safe_remove "$HOME_DIR/.claude.json" "Claude config (API key)"
    safe_remove_glob "$HOME_DIR/.claude.json.backup*" "Claude backups"
}

clean_dev() {
    log_info "Removing development files..."

    if [[ "$KEEP_GIT" == true ]]; then
        log_info "  Keeping .git (--keep-git)"
    else
        log_info "  Removing .git (this takes a while)..."
        safe_remove "$SCRIPT_DIR/.git" "Git repository"
    fi

    log_info "  Removing .vscode-server..."
    safe_remove "$HOME_DIR/.vscode-server" "VSCode server"
    safe_remove "$HOME_DIR/.cache" "Cache directory"
    safe_remove "$HOME_DIR/.gemini" "Gemini cache"
    safe_remove "$HOME_DIR/.dotnet" ".NET cache"
    safe_remove "$HOME_DIR/.docker" "Docker cache"
    safe_remove "$HOME_DIR/.antigravity-server" "Antigravity data"
    safe_remove "$HOME_DIR/.bash_history" "Bash history"
    safe_remove "$HOME_DIR/.zsh_history" "Zsh history"
    safe_remove "$HOME_DIR/.wget-hsts" "WGET cache"
    safe_remove "$HOME_DIR/.bashrc" "Bash config"
    safe_remove "$HOME_DIR/.profile" "Profile config"
    safe_remove "$HOME_DIR/.bash_logout" "Bash logout"
    safe_remove "$HOME_DIR/.sudo_as_admin_successful" "Sudo marker"
    if [[ "$KEEP_GIT" == true ]]; then
        log_info "  Keeping .ssh (needed for git push)"
    else
        safe_remove "$HOME_DIR/.ssh" "SSH keys"
    fi

    # Python cache
    if [[ "$DRY_RUN" == true ]]; then
        local pycache_count=$(find "$SCRIPT_DIR" -type d -name "__pycache__" 2>/dev/null | wc -l)
        [[ $pycache_count -gt 0 ]] && log_dry "$pycache_count __pycache__ directories"
    else
        find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
        log_success "Removed Python cache"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) DRY_RUN=true ;;
            --keep-claude) KEEP_CLAUDE=true ;;
            --keep-git) KEEP_GIT=true ;;
            -h|--help)
                head -26 "$0" | tail -23
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Usage: sudo bash prepare-image.sh [--dry-run] [--keep-claude] [--keep-git]"
                exit 1
                ;;
        esac
        shift
    done

    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi

    # Header
    echo ""
    echo "=============================================="
    echo "  MSSP Platform - Image Preparation"
    echo "=============================================="
    echo ""

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "DRY-RUN MODE - No files will be deleted"
        echo ""
    else
        echo "This will clean ALL development artifacts:"
        echo "  - Docker containers and volumes"
        echo "  - Databases, logs, certificates"
        if [[ "$KEEP_CLAUDE" == true ]]; then
            echo "  - Claude Code files: KEEPING (--keep-claude)"
        else
            echo "  - Claude Code files (API keys)"
        fi
        if [[ "$KEEP_GIT" == true ]]; then
            echo "  - Git repository: KEEPING (--keep-git)"
        else
            echo "  - Git repository, VSCode, SSH keys, caches"
        fi
        echo ""
        read -p "Continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Aborted"
            exit 0
        fi
        echo ""
    fi

    # Run all cleanup
    clean_containers
    echo ""
    clean_volumes
    echo ""
    clean_databases
    echo ""
    clean_logs
    echo ""
    clean_certs
    echo ""
    clean_installers
    echo ""
    if [[ "$KEEP_CLAUDE" == true ]]; then
        log_info "Skipping Claude Code files (--keep-claude)"
    else
        clean_claude
    fi
    echo ""
    clean_dev
    echo ""

    # Summary
    echo "=============================================="
    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry-run complete. Run without --dry-run to delete."
    else
        log_success "Cleanup complete! Items removed: $ITEMS_CLEANED"
        echo ""
        echo "What remains:"
        echo "  - config.yaml (client edits this)"
        echo "  - data/tools/ (forensic tools)"
        echo "  - All source code"
        [[ "$KEEP_GIT" == true ]] && echo "  - .git (can push changes)"
        [[ "$KEEP_CLAUDE" == true ]] && echo "  - Claude Code files"
        echo ""
        echo "Next: Export VM image"
    fi
    echo "=============================================="
}

main "$@"
