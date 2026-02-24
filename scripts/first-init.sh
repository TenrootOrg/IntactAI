#!/bin/bash
# MSSP Platform - First Time Initialization Script
# Run this after editing config.yaml with your IP/domain and passwords
#
# Usage: sudo bash first-init.sh
#
# Prerequisites:
#   1. Edit config.yaml and set your domain/IP
#   2. Edit config.yaml and set your passwords (optional, defaults work)
#   3. Run this script as root

# Don't use set -e, we handle errors ourselves

# ============================================================================
# Configuration
# ============================================================================

# Go up one level from scripts/ to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
MARKER_FILE="/etc/mssp-initialized"
LOG_FILE="$SCRIPT_DIR/first-init_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

read_config() {
    local key="$1"
    python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))$key)" 2>/dev/null
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

preflight_checks() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi

    # Check if already initialized
    if [[ -f "$MARKER_FILE" ]]; then
        log_warn "MSSP Platform has already been initialized!"
        log_info "Marker file exists: $MARKER_FILE"
        echo ""
        read -p "Re-initialize? This will regenerate certificates and restart services. (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Aborted."
            exit 0
        fi
    fi

    # Check config.yaml exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "config.yaml not found at $CONFIG_FILE"
        exit 1
    fi

    # Check Docker is running
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
}

# ============================================================================
# Configuration Reading
# ============================================================================

read_configuration() {
    log_info "Reading configuration from config.yaml..."

    # Read domain
    DOMAIN=$(read_config "['domain']")
    if [[ -z "$DOMAIN" || "$DOMAIN" == "None" ]]; then
        log_error "Domain not set in config.yaml"
        log_info "Please edit config.yaml and set: domain: your.ip.or.domain"
        exit 1
    fi
    log_info "  Domain: $DOMAIN"

    # Read module status
    ELK_ENABLED=$(read_config "['modules']['elk']['enabled']")
    TIMESKETCH_ENABLED=$(read_config "['modules']['timesketch']['enabled']")
    VELOCIRAPTOR_ENABLED=$(read_config "['modules']['velociraptor']['enabled']")
    IRIS_ENABLED=$(read_config "['modules']['iris']['enabled']")
    PORTAINER_ENABLED=$(read_config "['modules']['portainer']['enabled']")

    # Read credentials for display
    VELO_USER=$(read_config "['modules']['velociraptor']['id']")
    VELO_PASS=$(read_config "['modules']['velociraptor']['password']")
    TS_USER=$(read_config "['modules']['timesketch']['id']")
    TS_PASS=$(read_config "['modules']['timesketch']['password']")
    IRIS_PASS=$(read_config "['modules']['iris']['password']")

    log_success "Configuration loaded"
}

# ============================================================================
# Sync Velociraptor .env
# ============================================================================

sync_velociraptor_env() {
    log_info "Syncing Velociraptor configuration with domain..."

    local velo_env="$SCRIPT_DIR/modules/velociraptor/.env"

    if [[ -f "$velo_env" ]]; then
        # Update hostname and IP
        sed -i "s/VELOX_FRONTEND_HOSTNAME=.*/VELOX_FRONTEND_HOSTNAME=$DOMAIN/" "$velo_env"
        sed -i "s/VELOX_PUBLIC_IP=.*/VELOX_PUBLIC_IP=$DOMAIN/" "$velo_env"
        sed -i "s|VELOX_SERVER_URL=.*|VELOX_SERVER_URL=https://$DOMAIN:8000/|" "$velo_env"

        # Also sync user/password from config.yaml
        sed -i "s/VELOX_USER=.*/VELOX_USER=$VELO_USER/" "$velo_env"
        sed -i "s/VELOX_PASSWORD=.*/VELOX_PASSWORD=$VELO_PASS/" "$velo_env"

        log_success "Velociraptor .env updated"
    else
        log_warn "Velociraptor .env not found, will use defaults"
    fi
}

# ============================================================================
# Generate Certificates (from lib/modules.sh)
# ============================================================================

generate_certificates() {
    log_info "Generating SSL certificates..."

    # Nginx SSL
    local nginx_ssl="$SCRIPT_DIR/modules/nginx/ssl"
    mkdir -p "$nginx_ssl"
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" ]]; then
        log_info "  Generating Nginx SSL certificate for: $DOMAIN"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$nginx_ssl/nginx-cert.key" \
            -out "$nginx_ssl/nginx-cert.crt" \
            -subj "/CN=$DOMAIN/O=MSSP/C=US" 2>/dev/null
        log_success "  Nginx SSL certificate generated"
    else
        log_info "  Nginx SSL certificate exists, skipping"
    fi

    # IRIS Root CA
    local iris_ca="$SCRIPT_DIR/modules/iris/config/certificates/rootCA"
    mkdir -p "$iris_ca"
    if [[ ! -f "$iris_ca/irisRootCACert.pem" ]]; then
        log_info "  Generating IRIS Root CA..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$iris_ca/irisRootCAKey.pem" \
            -out "$iris_ca/irisRootCACert.pem" \
            -subj "/CN=IRIS Root CA/O=MSSP/C=US" 2>/dev/null
        log_success "  IRIS Root CA generated"
    else
        log_info "  IRIS Root CA exists, skipping"
    fi

    # IRIS Web Cert
    local iris_web="$SCRIPT_DIR/modules/iris/config/certificates/web_certificates"
    mkdir -p "$iris_web"
    if [[ ! -f "$iris_web/iris_dev_cert.pem" ]]; then
        log_info "  Generating IRIS web certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$iris_web/iris_dev_key.pem" \
            -out "$iris_web/iris_dev_cert.pem" \
            -subj "/CN=$DOMAIN/O=MSSP/C=US" 2>/dev/null
        chmod 644 "$iris_web"/*.pem
        log_success "  IRIS web certificate generated"
    else
        log_info "  IRIS web certificate exists, skipping"
    fi
}

# ============================================================================
# Generate IRIS Secrets (from lib/modules.sh)
# ============================================================================

generate_iris_secrets() {
    log_info "Generating IRIS secrets..."

    local secrets_dir="$SCRIPT_DIR/modules/iris/secrets"
    mkdir -p "$secrets_dir"

    local secrets_created=false

    # IRIS_ADM_PASSWORD should come from config.yaml, not be random
    if [[ ! -f "$secrets_dir/IRIS_ADM_PASSWORD" ]] || [[ ! -s "$secrets_dir/IRIS_ADM_PASSWORD" ]]; then
        local iris_password=$(read_config "['modules']['iris']['password']")
        if [[ -n "$iris_password" && "$iris_password" != "None" ]]; then
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_info "  Created IRIS_ADM_PASSWORD from config.yaml"
        else
            echo -n "123123" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_warn "  Created IRIS_ADM_PASSWORD with default"
        fi
        secrets_created=true
    fi

    if [[ ! -f "$secrets_dir/IRIS_SECRET_KEY" ]] || [[ ! -s "$secrets_dir/IRIS_SECRET_KEY" ]]; then
        openssl rand -hex 32 > "$secrets_dir/IRIS_SECRET_KEY"
        log_info "  Created IRIS_SECRET_KEY"
        secrets_created=true
    fi

    if [[ ! -f "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT" ]] || [[ ! -s "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT" ]]; then
        openssl rand -hex 32 > "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT"
        log_info "  Created IRIS_SECURITY_PASSWORD_SALT"
        secrets_created=true
    fi

    if [[ ! -f "$secrets_dir/POSTGRES_ADMIN_PASSWORD" ]] || [[ ! -s "$secrets_dir/POSTGRES_ADMIN_PASSWORD" ]]; then
        openssl rand -hex 32 > "$secrets_dir/POSTGRES_ADMIN_PASSWORD"
        log_info "  Created POSTGRES_ADMIN_PASSWORD"
        secrets_created=true
    fi

    if [[ ! -f "$secrets_dir/POSTGRES_PASSWORD" ]] || [[ ! -s "$secrets_dir/POSTGRES_PASSWORD" ]]; then
        openssl rand -hex 32 > "$secrets_dir/POSTGRES_PASSWORD"
        log_info "  Created POSTGRES_PASSWORD"
        secrets_created=true
    fi

    # Ensure flushed to disk
    if [[ "$secrets_created" == "true" ]]; then
        sync
        sleep 1
    fi

    log_success "IRIS secrets ready"
}

# ============================================================================
# Start Services
# ============================================================================

start_services() {
    log_info "Starting MSSP services..."

    local modules=("elk" "timesketch" "velociraptor" "iris" "portainer" "backend" "nginx")
    local total=${#modules[@]}
    local current=0

    for module in "${modules[@]}"; do
        ((current++)) || true
        local module_dir="$SCRIPT_DIR/modules/$module"

        if [[ -f "$module_dir/docker-compose.yaml" ]]; then
            log_info "  [$current/$total] Starting $module..."

            # Build if it's the backend (has custom Dockerfile)
            # Use --no-cache to ensure latest code is used (blueprints, etc.)
            if [[ "$module" == "backend" ]]; then
                (cd "$module_dir" && docker compose build --no-cache >> "$LOG_FILE" 2>&1) || true
            fi

            # Start
            if (cd "$module_dir" && docker compose up -d >> "$LOG_FILE" 2>&1); then
                log_success "  $module started"
            else
                log_warn "  $module may have issues, check logs"
            fi

            # Brief pause between services
            sleep 2
        fi
    done

    log_success "All services started"
}

# ============================================================================
# Wait for Services
# ============================================================================

wait_for_services() {
    log_info "Waiting for services to become healthy..."

    # Elasticsearch
    log_info "  Waiting for Elasticsearch..."
    local es_wait=0
    while [[ $es_wait -lt 90 ]]; do
        if curl -sf --max-time 5 "http://localhost:9200" > /dev/null 2>&1; then
            log_success "  Elasticsearch is ready (${es_wait}s)"
            break
        fi
        sleep 5
        ((es_wait+=5))
    done

    # Velociraptor
    log_info "  Waiting for Velociraptor..."
    local velo_wait=0
    while [[ $velo_wait -lt 90 ]]; do
        if docker exec mssp_velociraptor test -f /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  Velociraptor is ready (${velo_wait}s)"
            break
        fi
        sleep 5
        ((velo_wait+=5))
    done

    # Backend
    log_info "  Waiting for Backend API..."
    local be_wait=0
    while [[ $be_wait -lt 60 ]]; do
        if curl -sf --max-time 5 "http://localhost:5001/api/health" > /dev/null 2>&1; then
            log_success "  Backend API is ready (${be_wait}s)"
            break
        fi
        sleep 3
        ((be_wait+=3))
    done

    # Timesketch - wait for HTTP
    log_info "  Waiting for Timesketch HTTP..."
    local ts_wait=0
    while [[ $ts_wait -lt 90 ]]; do
        local http_code=$(curl -s --max-time 5 "http://localhost:5000/" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            log_success "  Timesketch HTTP is ready (${ts_wait}s)"
            break
        fi
        sleep 5
        ((ts_wait+=5))
    done

    # Timesketch - wait for database to be ready (tsctl needs working DB)
    log_info "  Waiting for Timesketch database..."
    local db_wait=0
    while [[ $db_wait -lt 60 ]]; do
        if docker exec mssp_timesketch_web tsctl list-users >/dev/null 2>&1; then
            log_success "  Timesketch database is ready (${db_wait}s)"
            break
        fi
        sleep 5
        ((db_wait+=5))
    done

    # Create Timesketch user with retries
    local ts_user=$(read_config "['modules']['timesketch']['id']")
    local ts_pass=$(read_config "['modules']['timesketch']['password']")
    log_info "  Creating Timesketch user: $ts_user"

    local ts_retry=0
    local ts_created=false
    while [[ $ts_retry -lt 5 ]]; do
        local result=$(docker exec mssp_timesketch_web tsctl create-user "$ts_user" --password "$ts_pass" 2>&1)
        if [[ "$result" == *"created/updated"* ]]; then
            # Ensure user is enabled (in case it was previously disabled)
            docker exec mssp_timesketch_web tsctl enable-user "$ts_user" >/dev/null 2>&1 || true
            log_success "  Timesketch user '$ts_user' created"
            ts_created=true
            break
        fi
        ((ts_retry++))
        log_info "  Retrying user creation... (attempt $ts_retry/5)"
        sleep 3
    done

    if [[ "$ts_created" != "true" ]]; then
        log_warn "  Failed to create Timesketch user after 5 attempts"
        log_warn "  Manual creation: docker exec mssp_timesketch_web tsctl create-user $ts_user --password <password>"
    fi

    # Nginx
    log_info "  Waiting for Nginx..."
    local nginx_wait=0
    while [[ $nginx_wait -lt 30 ]]; do
        if curl -sf --max-time 5 "http://localhost:80" > /dev/null 2>&1; then
            log_success "  Nginx is ready (${nginx_wait}s)"
            break
        fi
        sleep 3
        ((nginx_wait+=3))
    done
}

# ============================================================================
# Generate Client Installers
# ============================================================================

generate_client_installers() {
    log_info "Generating Velociraptor client installers..."

    local generate_script="$SCRIPT_DIR/scripts/generate_clients.sh"

    if [[ -f "$generate_script" ]]; then
        bash "$generate_script" 2>&1 | tee -a "$LOG_FILE"
        log_success "Client installers generated"
    else
        log_warn "generate_clients.sh not found, skipping"
    fi
}

# ============================================================================
# Create Marker File
# ============================================================================

create_marker() {
    echo "MSSP Platform initialized on $(date)" > "$MARKER_FILE"
    echo "Domain: $DOMAIN" >> "$MARKER_FILE"
    log_info "Created initialization marker: $MARKER_FILE"
}

# ============================================================================
# Print Summary
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}  MSSP Platform Initialization Complete!${NC}"
    echo "=============================================="
    echo ""
    echo "Access your services at:"
    echo -e "  Dashboard:     ${BLUE}http://$DOMAIN${NC}"
    echo -e "  Velociraptor:  ${BLUE}https://$DOMAIN:8000${NC}"
    echo -e "  Timesketch:    ${BLUE}http://$DOMAIN:5000${NC}"
    echo -e "  IRIS:          ${BLUE}https://$DOMAIN:8443${NC}"
    echo -e "  Kibana:        ${BLUE}http://$DOMAIN:5601${NC}"
    echo -e "  Portainer:     ${BLUE}http://$DOMAIN:9000${NC}"
    echo ""
    echo "Credentials (as configured in config.yaml):"
    echo "  Velociraptor:  $VELO_USER / $VELO_PASS"
    echo "  Timesketch:    $TS_USER / $TS_PASS"
    echo "  IRIS:          administrator / $IRIS_PASS"
    echo "  Portainer:     (set on first login)"
    echo ""
    echo "Client installers:"
    echo "  $SCRIPT_DIR/client_installers/"
    echo ""
    echo "Log file:"
    echo "  $LOG_FILE"
    echo ""
    echo "To change IP/domain later:"
    echo "  1. Edit config.yaml with new IP"
    echo "  2. Run: sudo bash scripts/first-init.sh"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Initialize log
    touch "$LOG_FILE"

    echo ""
    echo "=============================================="
    echo "  MSSP Platform - First Time Initialization"
    echo "=============================================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    # Steps
    preflight_checks
    echo ""
    read_configuration
    echo ""
    sync_velociraptor_env
    echo ""
    generate_certificates
    echo ""
    generate_iris_secrets
    echo ""
    start_services
    echo ""
    wait_for_services
    echo ""
    generate_client_installers
    echo ""
    create_marker
    echo ""
    print_summary
}

main "$@"
