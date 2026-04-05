#!/bin/bash
# MSSP Platform Installer - Docker Functions
# Docker installation and network setup

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi

    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu. Your OS: $ID"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    log_success "OS Check: $PRETTY_NAME"
}

install_dependencies() {
    log_info "Installing system dependencies..."

    if ! apt-get update -qq 2>> "$LOG_FILE"; then
        log_warn "apt-get update had issues, continuing..."
    fi

    if ! apt-get install -y -qq \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        python3-yaml \
        openssl \
        jq \
        2>> "$LOG_FILE"; then
        log_error "Failed to install some dependencies"
        return 1
    fi

    log_success "System dependencies installed"
}

# ============================================================================
# Docker Installation
# ============================================================================

install_docker_online() {
    log_info "Installing Docker from internet..."

    # Clean up any existing Docker apt sources and GPG keys to avoid conflicts
    log_info "Cleaning up any existing Docker apt configuration..."
    rm -f /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/docker*.list 2>/dev/null || true
    rm -f /usr/share/keyrings/docker-archive-keyring.gpg 2>/dev/null || true
    rm -f /etc/apt/keyrings/docker.asc 2>/dev/null || true
    rm -f /etc/apt/keyrings/docker*.gpg 2>/dev/null || true

    # Create keyrings directory if it doesn't exist
    install -m 0755 -d /etc/apt/keyrings

    # Add Docker's official GPG key (using modern location)
    log_info "Adding Docker GPG key..."
    if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc 2>> "$LOG_FILE"; then
        log_error "Failed to download Docker GPG key"
        return 1
    fi
    chmod a+r /etc/apt/keyrings/docker.asc

    # Set up the repository (using modern format)
    log_info "Adding Docker repository..."
    if ! echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null 2>> "$LOG_FILE"; then
        log_error "Failed to add Docker repository"
        return 1
    fi

    # Install Docker Engine
    log_info "Installing Docker packages..."
    if ! apt-get update -qq 2>> "$LOG_FILE"; then
        log_warn "apt-get update had issues"
    fi

    if ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>> "$LOG_FILE"; then
        log_error "Failed to install Docker packages"
        return 1
    fi

    # Configure Docker daemon to disable containerd snapshotter
    # This is required for docker save to work properly with multi-platform images
    log_info "Configuring Docker daemon..."
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'EOF'
{
  "features": {
    "containerd-snapshotter": false
  }
}
EOF
    log_success "Docker daemon configured (containerd-snapshotter disabled)"

    # Start and enable Docker with error checking
    log_info "Starting Docker service..."
    if ! systemctl start docker 2>> "$LOG_FILE"; then
        log_error "Failed to start Docker service"
        return 1
    fi

    if ! systemctl enable docker 2>> "$LOG_FILE"; then
        log_warn "Failed to enable Docker service on boot"
    fi

    # Verify Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker service started but not responding"
        return 1
    fi

    # Add the user who invoked sudo to the docker group
    if [[ -n "$SUDO_USER" ]]; then
        usermod -aG docker "$SUDO_USER"
        log_success "User $SUDO_USER added to docker group (logout/login required)"
    fi

    log_success "Docker installed successfully"
}

# ============================================================================
# Main Docker Installation Entry Point
# ============================================================================

install_docker() {
    if command -v docker &> /dev/null; then
        log_success "Docker already installed: $(docker --version)"

        # Ensure daemon.json config exists (for docker save to work properly)
        if [[ ! -f /etc/docker/daemon.json ]] || ! grep -q "containerd-snapshotter" /etc/docker/daemon.json 2>/dev/null; then
            log_info "Configuring Docker daemon for proper image export..."
            mkdir -p /etc/docker
            cat > /etc/docker/daemon.json << 'EOF'
{
  "features": {
    "containerd-snapshotter": false
  }
}
EOF
            log_info "Restarting Docker to apply configuration..."
            systemctl restart docker 2>> "$LOG_FILE" || true
            log_success "Docker daemon configured"
        fi

        # Check if user is in docker group
        if [[ -n "$SUDO_USER" ]] && ! groups "$SUDO_USER" | grep -q '\bdocker\b'; then
            log_info "Adding user $SUDO_USER to docker group..."
            usermod -aG docker "$SUDO_USER"
            log_success "User $SUDO_USER added to docker group (logout/login required)"
        fi
        return
    fi

    install_docker_online
}

# ============================================================================
# Docker Network Setup
# ============================================================================

create_network() {
    local network_name="mssp_network"

    if docker network inspect "$network_name" &> /dev/null; then
        log_info "Docker network '$network_name' already exists"
    else
        if docker network create "$network_name" 2>> "$LOG_FILE"; then
            log_success "Created Docker network: $network_name"
        else
            log_error "Failed to create Docker network: $network_name"
            return 1
        fi
    fi
}

# ============================================================================
# Pre-pull Required Images
# ============================================================================

pull_plaso_image() {
    local plaso_version=$(read_config "['versions']['plaso']")
    local plaso_image="log2timeline/plaso:${plaso_version:-20260119}"

    log_info "Pulling Plaso image for timeline processing..."

    if docker image inspect "$plaso_image" &> /dev/null; then
        log_info "Plaso image already exists: $plaso_image"
        return 0
    fi

    log_info "Downloading $plaso_image (this may take a few minutes)..."
    if docker pull "$plaso_image" 2>> "$LOG_FILE"; then
        log_success "Plaso image pulled successfully: $plaso_image"
    else
        log_warn "Failed to pull Plaso image - it will be downloaded on first use"
    fi
}

pull_python_alpine_image() {
    # Python Alpine image is used by Plaso decompression (plaso_service.py)
    # Pre-pull to avoid network access at runtime in air-gap environments

    local image="python:3-alpine"

    log_info "Pulling Python Alpine image for Plaso decompression..."

    if docker image inspect "$image" &> /dev/null; then
        log_info "  Python Alpine image already exists"
        return 0
    fi

    log_info "  Downloading $image..."
    if docker pull "$image" 2>> "$LOG_FILE"; then
        log_success "  Python Alpine image pulled successfully"
    else
        log_warn "  Failed to pull $image - Plaso decompression may fail offline"
    fi
}

download_timesketch_packages() {
    # Timesketch 20260311+ includes google-genai built-in (no external packages needed)
    # This function is kept for backwards compatibility but no longer downloads packages
    log_info "Timesketch LLM packages: included in Timesketch image (no download needed)"
}

download_offline_collector_binaries() {
    # Velociraptor v0.74.1 binaries for Offline Collector
    # NOTE: v0.74.x required because v0.75+ broke the -- pseudo-flag in Generic Collector
    # GitHub tag is "v0.74" but files contain "v0.74.1" in the filename

    local downloads_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local base_url="https://github.com/Velocidex/velociraptor/releases/download/v0.74"

    log_info "Checking Velociraptor v0.74.1 binaries for Offline Collector..."

    mkdir -p "$downloads_dir"

    local binaries=(
        "velociraptor-v0.74.1-windows-amd64.exe"
        "velociraptor-v0.74.1-linux-amd64"
        "velociraptor-v0.74.1-darwin-amd64"
    )

    local downloaded=0
    local skipped=0

    for binary in "${binaries[@]}"; do
        local dest_path="${downloads_dir}/${binary}"

        if [[ -f "$dest_path" ]] && [[ -s "$dest_path" ]]; then
            log_info "  Already exists: $binary"
            ((skipped++))
        else
            log_info "  Downloading: $binary"
            if curl -fsSL "${base_url}/${binary}" -o "$dest_path" 2>> "$LOG_FILE"; then
                chmod +x "$dest_path" 2>/dev/null || true
                log_success "  Downloaded: $binary"
                ((downloaded++))
            else
                log_warn "  Failed to download: $binary"
            fi
        fi
    done

    if [[ $downloaded -gt 0 ]]; then
        log_success "Offline Collector binaries: $downloaded downloaded, $skipped already existed"
    else
        log_info "Offline Collector binaries: all $skipped binaries already exist"
    fi
}

create_velociraptor_collector() {
    # Download the special velociraptor-collector binary from GitHub
    # This is a small (~80KB) template binary designed for config embedding
    # NOT the same as the regular velociraptor binary (70+ MB)
    # The file is placed in /data/tools/ where maintenance will configure it
    # in Velociraptor's inventory with serve_locally=true

    local collector_url="https://github.com/Velocidex/velociraptor/releases/download/v0.75/velociraptor-collector"
    local tools_dir="${SCRIPT_DIR}/data/tools"
    local dest_path="${tools_dir}/velociraptor-collector"
    local min_size=50000  # ~80KB expected

    log_info "Downloading Velociraptor collector template..."

    mkdir -p "$tools_dir"

    # Check if already exists with valid size
    if [[ -f "$dest_path" ]]; then
        local current_size=$(stat -c%s "$dest_path" 2>/dev/null || echo "0")
        if [[ "$current_size" -gt "$min_size" ]]; then
            log_info "  Already exists: velociraptor-collector ($(numfmt --to=iec $current_size))"
            return 0
        else
            log_info "  Existing file invalid, re-downloading..."
            rm -f "$dest_path"
        fi
    fi

    # Download the collector template from GitHub
    log_info "  Downloading from: $collector_url"
    if curl -fsSL "$collector_url" -o "$dest_path" 2>> "$LOG_FILE"; then
        chmod +x "$dest_path"
        local size=$(stat -c%s "$dest_path" 2>/dev/null || echo "0")
        if [[ "$size" -gt "$min_size" ]]; then
            log_success "  Downloaded: velociraptor-collector ($(numfmt --to=iec $size))"
            return 0
        else
            log_warn "  Downloaded file too small: $size bytes"
            rm -f "$dest_path"
            return 1
        fi
    else
        log_warn "  Failed to download velociraptor-collector"
        return 1
    fi
}

# =============================================================================
# Azure Security Tools
# =============================================================================

download_sigma_rules() {
    # Download SIGMA detection rules for Azure security automation
    # Clones SigmaHQ rules repository for offline use

    # Skip if azure module is disabled
    local azure_enabled=$(read_config "['modules']['azure']['enabled']")
    if ! is_enabled "$azure_enabled"; then
        log_info "Azure module disabled, skipping SIGMA rules download"
        return 0
    fi

    local sigma_dir="/opt/sigma-rules"

    log_info "Setting up SIGMA detection rules for Azure automation..."

    # Check if already exists and is valid
    if [[ -d "$sigma_dir/rules/cloud/azure" ]]; then
        local rule_count=$(find "$sigma_dir/rules/cloud/azure" -name "*.yml" | wc -l)
        if [[ $rule_count -gt 10 ]]; then
            log_info "SIGMA rules already installed: $rule_count Azure rules found"
            return 0
        fi
    fi

    # Clone or update SIGMA rules
    if [[ -d "$sigma_dir/.git" ]]; then
        log_info "Updating existing SIGMA rules..."
        cd "$sigma_dir"
        git pull --depth 1 2>> "$LOG_FILE" || true
        cd - > /dev/null
    else
        log_info "Cloning SIGMA rules repository..."
        rm -rf "$sigma_dir" 2>/dev/null || true
        if git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$sigma_dir" 2>> "$LOG_FILE"; then
            log_success "SIGMA rules cloned successfully"
        else
            log_warn "Failed to clone SIGMA rules - Azure detection will have limited rules"
            return 1
        fi
    fi

    # Verify installation
    if [[ -d "$sigma_dir/rules/cloud/azure" ]]; then
        local rule_count=$(find "$sigma_dir/rules/cloud/azure" -name "*.yml" | wc -l)
        log_success "SIGMA rules installed: $rule_count Azure/cloud rules"
    else
        log_warn "SIGMA Azure rules directory not found"
        return 1
    fi
}


pull_dfir_o365rc_image() {
    # Pull DFIR-O365RC image for Unified Audit Log collection

    local azure_enabled=$(read_config "['modules']['azure']['enabled']")
    if ! is_enabled "$azure_enabled"; then
        log_info "Azure module disabled, skipping DFIR-O365RC"
        return 0
    fi

    log_info "Pulling DFIR-O365RC image (Unified Audit Log collection)..."

    if docker image inspect anssi/dfir-o365rc:latest > /dev/null 2>&1; then
        log_info "DFIR-O365RC image already present"
        return 0
    fi

    if docker pull anssi/dfir-o365rc:latest 2>> "$LOG_FILE"; then
        log_success "DFIR-O365RC image pulled successfully"
    else
        log_warn "Failed to pull DFIR-O365RC image - Unified Audit Log collection will not be available"
        return 1
    fi
}


generate_azure_certificate() {
    # Generate self-signed certificate for DFIR-O365RC authentication
    # The public key must be uploaded to Azure App Registration by the user

    local azure_enabled=$(read_config "['modules']['azure']['enabled']")
    if ! is_enabled "$azure_enabled"; then
        return 0
    fi

    local cert_dir="${SCRIPT_DIR}/data"
    local pfx_path="${cert_dir}/azure_cert.pfx"
    local pub_path="${cert_dir}/azure_cert_public.pem"

    if [[ -f "$pfx_path" ]]; then
        log_info "Azure certificate already exists, skipping generation"
        return 0
    fi

    log_info "Generating Azure certificate for DFIR-O365RC..."
    mkdir -p "$cert_dir"

    # Generate self-signed cert (RSA 2048, valid 2 years)
    openssl req -x509 -newkey rsa:2048 \
        -keyout /tmp/azure_key.pem -out /tmp/azure_cert.pem \
        -days 730 -nodes -subj "/CN=RISX-MSSP-DFIR" 2>> "$LOG_FILE"

    # Create PFX (no password)
    openssl pkcs12 -export -out "$pfx_path" \
        -inkey /tmp/azure_key.pem -in /tmp/azure_cert.pem \
        -passout pass: 2>> "$LOG_FILE"

    # Export public key for user to upload to Azure
    cp /tmp/azure_cert.pem "$pub_path"

    # Cleanup temp files
    rm -f /tmp/azure_key.pem /tmp/azure_cert.pem

    if [[ -f "$pfx_path" ]]; then
        log_success "Azure certificate generated"
        log_info "  PFX certificate: $pfx_path"
        log_info "  Public key: $pub_path"
        log_info "  Upload the public key to Azure App Registration → Certificates & secrets"
    else
        log_warn "Failed to generate Azure certificate"
        return 1
    fi
}
