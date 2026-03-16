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

download_timesketch_packages() {
    # Download Python packages for Timesketch AI features (google-generativeai)
    # These are installed offline from local wheels in air-gap environments

    local packages_dir="${SCRIPT_DIR}/modules/timesketch/python-packages"

    log_info "Downloading Timesketch Python packages for offline use..."

    mkdir -p "$packages_dir"

    # Download google-generativeai and ALL its dependencies
    # Using pip download to get wheels for the target platform
    if python3 -m pip download google-generativeai \
        --dest "$packages_dir" \
        --only-binary=:all: \
        --platform manylinux2014_x86_64 \
        --platform manylinux_2_17_x86_64 \
        --python-version 312 \
        --no-deps 2>> "$LOG_FILE"; then
        log_info "  Downloaded google-generativeai"
    fi

    # Download all dependencies explicitly
    local deps=(
        "google-ai-generativelanguage"
        "google-api-core"
        "google-api-python-client"
        "google-auth"
        "google-auth-httplib2"
        "googleapis-common-protos"
        "grpcio"
        "grpcio-status"
        "httplib2"
        "proto-plus"
        "protobuf"
        "pyasn1"
        "pyasn1-modules"
        "rsa"
        "cachetools"
        "certifi"
        "charset-normalizer"
        "idna"
        "requests"
        "urllib3"
        "pydantic"
        "pydantic-core"
        "annotated-types"
        "typing-extensions"
        "tqdm"
        "pyparsing"
        "uritemplate"
        "cffi"
        "pycparser"
        "cryptography"
    )

    for dep in "${deps[@]}"; do
        if python3 -m pip download "$dep" \
            --dest "$packages_dir" \
            --only-binary=:all: \
            --platform manylinux2014_x86_64 \
            --platform manylinux_2_17_x86_64 \
            --python-version 312 \
            --no-deps 2>> "$LOG_FILE"; then
            log_info "  Downloaded $dep"
        else
            log_warn "  Could not download $dep (may already exist or not needed)"
        fi
    done

    local count=$(ls -1 "$packages_dir"/*.whl 2>/dev/null | wc -l)
    log_success "Timesketch packages: $count wheel files in $packages_dir"
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
