#!/bin/bash
# Intact.AI Platform Installer - Docker Functions
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
        dnsutils \
        2>> "$LOG_FILE"; then
        log_error "Failed to install some dependencies"
        return 1
    fi

    log_success "System dependencies installed"
}

# Bias getaddrinfo() to return IPv4 addresses before IPv6 ones so Docker pulls
# (and apt, curl, wget) try IPv4 first. IPv6 still works as fallback if the
# IPv4 endpoint fails — we just don't try it first. Avoids the common failure
# mode on IPv4-only networks (e.g. most ISPs in Israel) where Docker Hub's
# AAAA records resolve to IPv6 addresses the host can't route to, which
# manifests as "dial tcp [v6...]:443: connect: network is unreachable" mid-pull.
prefer_ipv4_dns() {
    local gai=/etc/gai.conf
    local rule='precedence ::ffff:0:0/96  100'

    # Idempotent: only add the rule if no uncommented `precedence ::ffff:0:0/96`
    # line is already present. We deliberately don't touch other gai.conf lines.
    if grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96' "$gai" 2>/dev/null; then
        log_info "DNS preference: IPv4-first already configured in $gai"
        return 0
    fi

    log_info "Configuring DNS to prefer IPv4 over IPv6 (with IPv6 fallback)..."
    {
        echo ""
        echo "# Added by Intact.AI installer: prefer IPv4 in DNS resolution."
        echo "# IPv6 still works as fallback — this only changes the order."
        echo "$rule"
    } >> "$gai" 2>> "$LOG_FILE" || {
        log_warn "Could not write to $gai (continuing anyway)"
        return 0
    }

    log_success "DNS prefers IPv4 (IPv6 retained as fallback)"
}

# Force the Docker daemon to use glibc's getaddrinfo() for DNS resolution
# instead of Go's pure-Go resolver. The pure-Go resolver does not read
# /etc/gai.conf, so prefer_ipv4_dns() above doesn't reach Docker's image-pull
# code path on its own. With GODEBUG=netdns=cgo, Docker's resolver delegates
# to glibc, which respects gai.conf and (on IPv4-only hosts where there's no
# global IPv6 address) naturally prefers IPv4 anyway under default RFC 6724.
# Pair with prefer_ipv4_dns() — they're complementary, not redundant.
configure_docker_resolver() {
    local override_dir=/etc/systemd/system/docker.service.d
    local override_file="${override_dir}/intact-cgo-resolver.conf"
    local desired_content='[Service]
Environment="GODEBUG=netdns=cgo"'

    # Idempotent: skip the file write + daemon restart if the override is
    # already in place exactly as we want it.
    if [[ -f "$override_file" ]] && [[ "$(cat "$override_file")" == "$desired_content" ]]; then
        log_info "Docker resolver: cgo override already in place"
        return 0
    fi

    log_info "Configuring Docker daemon to use cgo DNS resolver (forces gai.conf compliance)..."
    if ! mkdir -p "$override_dir" 2>> "$LOG_FILE"; then
        log_warn "Could not create $override_dir (continuing without resolver override)"
        return 0
    fi
    if ! printf '%s\n' "$desired_content" > "$override_file" 2>> "$LOG_FILE"; then
        log_warn "Could not write $override_file (continuing without resolver override)"
        return 0
    fi
    if ! systemctl daemon-reload 2>> "$LOG_FILE"; then
        log_warn "systemctl daemon-reload failed (continuing — override may not take effect until next reboot)"
        return 0
    fi
    if ! systemctl restart docker 2>> "$LOG_FILE"; then
        log_warn "Docker restart failed (override is on disk but not active until next restart)"
        return 0
    fi

    log_success "Docker daemon now using cgo resolver"
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

    # Add Docker's official GPG key (using modern location).
    # Retry 3x with backoff + IPv4 force — a fresh install often loses a
    # single DNS lookup to download.docker.com (we've seen the reachability
    # pre-check pass and the real curl fail ~30s later with "Could not
    # resolve host"). IPv4-only sidesteps IPv6 AAAA resolution bugs; the
    # final fallback resolves via public DNS and passes the IP explicitly
    # via --resolve, so a broken local resolver doesn't kill the install.
    log_info "Adding Docker GPG key..."

    # Log what the local resolver thinks, so the file shows a smoking gun if DNS is the cause.
    local current_ip
    current_ip=$(getent hosts download.docker.com 2>/dev/null | awk '{print $1; exit}')
    if [[ -n "$current_ip" ]]; then
        log_info "  Local DNS resolves download.docker.com -> $current_ip"
    else
        log_warn "  Local DNS could not resolve download.docker.com (will try public DNS fallback)"
    fi

    local gpg_url='https://download.docker.com/linux/ubuntu/gpg'
    local gpg_out=/etc/apt/keyrings/docker.asc
    local gpg_ok=false
    for attempt in 1 2 3; do
        if curl -fsSL -4 --retry 2 --retry-delay 3 --connect-timeout 15 --max-time 60 \
                "$gpg_url" -o "$gpg_out" 2>> "$LOG_FILE"; then
            gpg_ok=true
            break
        fi
        log_warn "  GPG download attempt $attempt/3 failed, retrying in 5s..."
        sleep 5
    done

    # Fallback: if all 3 attempts failed and local DNS is the likely culprit,
    # resolve via Cloudflare / Google DNS and pass the IP via --resolve.
    if [[ "$gpg_ok" != "true" ]]; then
        log_warn "  Trying public DNS fallback (system resolver failed)..."
        local public_ip=""
        for resolver in 1.1.1.1 8.8.8.8; do
            # Real nslookup output:
            #   Address:\t1.1.1.1#53          ← resolver header, must skip
            #   Address: 18.155.68.92         ← actual answer
            # Different distros' nslookup variants use space vs tab inconsistently,
            # so don't rely on the delimiter — match any "Address" line, drop
            # anything containing '#' (resolver header), take the first answer.
            public_ip=$(nslookup -q=A download.docker.com "$resolver" 2>/dev/null \
                        | awk '/^Address/ { print $2 }' \
                        | grep -v '#' \
                        | head -1)
            if [[ -n "$public_ip" && "$public_ip" != "0.0.0.0" ]]; then
                log_info "  Public resolver $resolver -> $public_ip"
                break
            fi
        done
        if [[ -n "$public_ip" ]]; then
            if curl -fsSL -4 --connect-timeout 15 --max-time 60 \
                    --resolve "download.docker.com:443:$public_ip" \
                    "$gpg_url" -o "$gpg_out" 2>> "$LOG_FILE"; then
                gpg_ok=true
                log_success "  GPG downloaded via public DNS fallback"
            fi
        fi
    fi

    if [[ "$gpg_ok" != "true" ]]; then
        log_error "Failed to download Docker GPG key after 3 attempts + public DNS fallback"
        log_error "  Check DNS config (/etc/resolv.conf), firewall egress on :443,"
        log_error "  or any outbound proxy/captive portal between this host and download.docker.com"
        return 1
    fi
    chmod a+r "$gpg_out"

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
    local network_name="intact_network"

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

# Generic image pull with retry. Backoff: 5s, 15s, 45s.
# Returns 0 if the image is local after the call (already present, or pulled);
# non-zero if every attempt failed.
_pull_image_with_retry() {
    local image="$1"
    local max_attempts=3
    local delay=5
    local attempt=1
    # See pull_compose_with_retry — same "↳ resolved" breadcrumb pattern,
    # so an operator scanning the end-of-install ATTENTION block can tell
    # transient retries from terminal failures at a glance.
    local had_failure=0

    while (( attempt <= max_attempts )); do
        # Stream progress to BOTH terminal and log file. Operator needs
        # to see the per-layer download bytes so a slow pull doesn't
        # look like a hang.
        if docker pull "$image" 2>&1 | tee -a "$LOG_FILE"; then
            if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
                if (( had_failure > 0 )); then
                    log_success "  $image pulled on attempt $attempt (previous failure was transient)"
                    INSTALL_WARNINGS+=("  ↳ resolved: $image pull succeeded on attempt $attempt")
                fi
                return 0
            fi
        fi
        had_failure=1
        if (( attempt < max_attempts )); then
            log_warn "  Pull failed for $image (attempt $attempt/$max_attempts); retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay * 3 ))
        fi
        ((attempt++))
    done
    return 1
}

pull_plaso_image() {
    local plaso_version=$(read_config "['versions']['plaso']")
    local plaso_image="log2timeline/plaso:${plaso_version:-20260119}"

    log_info "Pulling Plaso image for timeline processing..."

    if docker image inspect "$plaso_image" &> /dev/null; then
        log_info "Plaso image already exists: $plaso_image"
        return 0
    fi

    log_info "Downloading $plaso_image (this may take a few minutes)..."
    if docker pull "$plaso_image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            log_success "Plaso image pulled successfully: $plaso_image"
        else
            log_warn "Failed to pull Plaso image - it will be downloaded on first use"
        fi
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
    if docker pull "$image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            log_success "  Python Alpine image pulled successfully"
        else
            log_warn "  Failed to pull $image - Plaso decompression may fail offline"
        fi
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
    # Velociraptor offline-collector binaries — version follows
    # `versions.velociraptor` in `config.yaml` (single source of truth,
    # same pin used to build the server image). Bump that one value and
    # both the server and the offline-collector binaries move together
    # on the next install.
    #
    # Old binaries from a previous version pin are removed so the
    # downloads dir doesn't accumulate stale files. The backend's
    # offline-collector code (`services/offline_collector/constants.py`)
    # auto-discovers whatever binaries are present, so the cleanup +
    # download here is what drives which version actually gets used.

    local velo_version
    velo_version=$(read_config "['versions']['velociraptor']")
    if [[ -z "$velo_version" || "$velo_version" == "None" ]]; then
        log_error "Offline-Collector: versions.velociraptor is not set in config.yaml — cannot determine which binaries to download"
        return 0
    fi
    # GitHub tag is the major.minor (e.g. "v0.76"); patch versions live as
    # release assets within that tag.
    local velo_tag
    velo_tag=$(echo "$velo_version" | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')

    local downloads_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local base_url="https://github.com/Velocidex/velociraptor/releases/download/v${velo_tag}"

    log_info "Checking Velociraptor v${velo_version} binaries for Offline Collector..."

    mkdir -p "$downloads_dir"

    # Why the -musl variant for the modern version:
    # Even Velociraptor's current build (linux-amd64) imports GLIBC_2.28
    # symbols, so it crashes at load on any host with glibc < 2.28
    # (CentOS 7, RHEL 7, Sophos UTM, Ubuntu 16.04, etc.). The -musl
    # variant is statically linked against musl libc with zero shared-
    # library deps — runs on ANY Linux x86_64 with kernel >= 2.6.32.
    # The new "Linux (musl)" download button on the dashboard serves
    # this variant repacked with the live client.config.
    local binaries=(
        "velociraptor-v${velo_version}-windows-amd64.exe"
        "velociraptor-v${velo_version}-linux-amd64"
        "velociraptor-v${velo_version}-linux-amd64-musl"
        "velociraptor-v${velo_version}-darwin-amd64"
    )

    # Clean up any prior-version binaries so the downloads dir reflects
    # the current pin. Pattern matches `velociraptor-v<X>-<platform>`
    # for any version <X> — the loop below deletes only files whose
    # version segment differs from the configured one.
    local stale=0
    for old in "$downloads_dir"/velociraptor-v*-windows-amd64.exe \
               "$downloads_dir"/velociraptor-v*-linux-amd64 \
               "$downloads_dir"/velociraptor-v*-linux-amd64-musl \
               "$downloads_dir"/velociraptor-v*-darwin-amd64; do
        [[ -f "$old" ]] || continue
        if [[ "$old" != *"-v${velo_version}-"* ]]; then
            log_info "  Removing stale binary: $(basename "$old")"
            rm -f "$old"
            ((stale++))
        fi
    done
    if (( stale > 0 )); then
        log_info "  Cleaned up $stale stale offline-collector binar(y/ies) from prior version pin"
    fi

    local downloaded=0
    local skipped=0
    # Minimum credible binary size — permissive (1 MB) so legitimate
    # binaries pass even if upstream slims them down. The 1 MB floor
    # only catches HTTP 404 HTML pages, GitHub rate-limit JSON, and
    # badly-aborted partial transfers. Real binaries are 65-85 MB.
    local min_size=$((1 * 1024 * 1024))

    for binary in "${binaries[@]}"; do
        local dest_path="${downloads_dir}/${binary}"

        if [[ -f "$dest_path" ]] && [[ -s "$dest_path" ]]; then
            log_info "  Already exists: $binary"
            ((skipped++))
        else
            log_info "  Downloading: $binary  (from ${base_url}/${binary})"
            if curl -fsSL "${base_url}/${binary}" -o "$dest_path" 2>> "$LOG_FILE"; then
                chmod +x "$dest_path" 2>/dev/null || true
                log_success "  Downloaded: $binary"
                ((downloaded++))
            else
                log_warn "  Failed to download: $binary"
            fi
        fi
    done

    # Post-condition validation — function used to exit 0 even when every
    # download failed; the install would "succeed" with an empty downloads/
    # directory and the offline-collector path failed silently at runtime.
    # Loud errors here + the end-of-install ATTENTION report make the issue
    # visible without aborting installs that were going to succeed anyway.
    local missing=0
    for binary in "${binaries[@]}"; do
        local p="${downloads_dir}/${binary}"
        local sz=0
        [[ -f "$p" ]] && sz=$(stat -c%s "$p" 2>/dev/null || echo 0)
        if [[ ! -s "$p" ]] || (( sz < min_size )); then
            log_error "Offline-Collector binary missing or undersized: $binary"
            log_error "  Expected ≥1 MB at $p — got $sz bytes (real binaries are 65-85 MB)"
            log_error "  Manual fix: curl -fsSL ${base_url}/${binary} -o $p && chmod +x $p"
            ((missing++))
        fi
    done
    if (( missing > 0 )); then
        log_error "Offline-Collector: $missing/${#binaries[@]} binaries unusable. Offline-collector generation will fail until fixed."
    fi

    if [[ $downloaded -gt 0 ]]; then
        log_success "Offline Collector binaries (v${velo_version}): $downloaded downloaded, $skipped already existed"
    else
        log_info "Offline Collector binaries (v${velo_version}): all $skipped binaries already exist"
    fi
    return 0
}

download_legacy_velociraptor_binaries() {
    # Legacy Velociraptor binary for old Windows hosts (Server 2008 R2 SP1,
    # Win 7). Pin lives in `versions.velociraptor_legacy` in config.yaml.
    # Distinct namespace from the main pin so they coexist in the same
    # downloads dir — the legacy binary keeps its full GitHub-style filename
    # (e.g. velociraptor-v0.7.1-windows-amd64.exe) so the cleanup pattern in
    # download_offline_collector_binaries() (matches `*-v<MAIN_VER>-*`) does
    # NOT delete it. The two installs don't fight.

    local legacy_version
    legacy_version=$(read_config "['versions']['velociraptor_legacy']")
    if [[ -z "$legacy_version" || "$legacy_version" == "None" ]]; then
        log_info "Legacy Velociraptor: versions.velociraptor_legacy not set — skipping"
        return 0
    fi
    # Legacy releases (≤0.7.x) use FULL-version tags on GitHub (e.g. v0.7.1),
    # unlike modern releases (≥0.72) which use major.minor tags (e.g. v0.76).
    # The download_offline_collector_binaries() function above truncates to
    # major.minor because that matches the modern pin; here we keep the full
    # version because that matches the legacy pin.
    local legacy_tag="${legacy_version}"

    local downloads_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local base_url="https://github.com/Velocidex/velociraptor/releases/download/v${legacy_tag}"

    log_info "Checking Velociraptor LEGACY v${legacy_version} binaries..."
    mkdir -p "$downloads_dir"

    # Why -musl for linux:
    # The plain velociraptor-vX.Y.Z-linux-amd64 build is dynamically linked
    # and (even in v0.7.1) imports GLIBC_2.28 symbols, so it fails to load
    # on glibc-2.17 hosts (CentOS 7, RHEL 7, Ubuntu 16.04). The -musl
    # variant is statically linked against musl-libc with zero shared-lib
    # deps — runs on ANY Linux x86_64 with kernel >= 2.6.32. The legacy
    # service prefers -musl for the linux-legacy target; the non-musl
    # build is kept too for parity / debug.
    local binaries=(
        "velociraptor-v${legacy_version}-windows-amd64.exe"
        "velociraptor-v${legacy_version}-linux-amd64"
        "velociraptor-v${legacy_version}-linux-amd64-musl"
        "velociraptor-v${legacy_version}-darwin-amd64"
    )

    # Clean up stale legacy binaries from prior pin changes. Pattern is the
    # same as the main downloader but constrained to versions OLDER than the
    # current main version (anything <0.74 is legacy-territory in practice).
    # Simpler heuristic: just match "velociraptor-v0.7.*-*" and skip the
    # configured one.
    local stale=0
    for old in "$downloads_dir"/velociraptor-v0.[67].*-windows-amd64.exe \
               "$downloads_dir"/velociraptor-v0.[67].*-linux-amd64 \
               "$downloads_dir"/velociraptor-v0.[67].*-linux-amd64-musl \
               "$downloads_dir"/velociraptor-v0.[67].*-darwin-amd64; do
        [[ -f "$old" ]] || continue
        if [[ "$old" != *"-v${legacy_version}-"* ]]; then
            log_info "  Removing stale legacy binary: $(basename "$old")"
            rm -f "$old"
            ((stale++))
        fi
    done
    (( stale > 0 )) && log_info "  Cleaned up $stale stale legacy binar(y/ies)"

    local downloaded=0
    local skipped=0
    local min_size=$((1 * 1024 * 1024))   # 1 MB floor — real legacy bins are ~50 MB

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
                log_warn "  Failed to download: $binary (legacy support for that OS will require online mode)"
            fi
        fi
    done

    # Validate the two binaries the dashboard's legacy buttons actually
    # serve: Windows .exe (windows-legacy-exe) and Linux musl (linux-legacy).
    # macOS legacy is a "nice to have" — not validated; no UI button uses it.
    for plat_check in \
        "Windows:velociraptor-v${legacy_version}-windows-amd64.exe" \
        "Linux (musl-static):velociraptor-v${legacy_version}-linux-amd64-musl"; do
        local label="${plat_check%%:*}"
        local fname="${plat_check##*:}"
        local p="${downloads_dir}/${fname}"
        local sz=0
        [[ -f "$p" ]] && sz=$(stat -c%s "$p" 2>/dev/null || echo 0)
        if [[ ! -s "$p" ]] || (( sz < min_size )); then
            log_warn "Legacy Velociraptor: ${label} binary missing/undersized at $p ($sz bytes)."
            log_warn "  Manual fix: curl -fsSL ${base_url}/${fname} -o $p"
        else
            log_success "Legacy Velociraptor (v${legacy_version}): ${label} binary ready ($(numfmt --to=iec $sz))"
        fi
    done

    if [[ $downloaded -gt 0 ]]; then
        log_success "Legacy Velociraptor (v${legacy_version}): $downloaded downloaded, $skipped already existed"
    else
        log_info "Legacy Velociraptor (v${legacy_version}): all $skipped binaries already exist"
    fi
    return 0
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

    if docker pull anssi/dfir-o365rc:latest 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            log_success "DFIR-O365RC image pulled successfully"
        else
            log_warn "Failed to pull DFIR-O365RC image - Unified Audit Log collection will not be available"
            return 1
        fi
    else
        log_warn "Failed to pull DFIR-O365RC image - Unified Audit Log collection will not be available"
        return 1
    fi
}


pull_prowler_image() {
    # Pull Prowler image for AWS posture-scanning (used by
    # services/aws/prowler_runner.py). Mirrors pull_dfir_o365rc_image
    # so the install flow gates the pre-pull on the module being
    # enabled in config.yaml and reports the same way.
    #
    # The image is ~3.5 GB so it's worth front-loading at install time
    # — at runtime the first scan would otherwise stall for several
    # minutes waiting for the pull on a fresh customer machine.

    local aws_enabled=$(read_config "['modules']['aws']['enabled']")
    if ! is_enabled "$aws_enabled"; then
        log_info "AWS module disabled, skipping Prowler image"
        return 0
    fi

    log_info "Pulling Prowler image (AWS posture scans, ~3.5 GB)..."

    if docker image inspect toniblyx/prowler:latest > /dev/null 2>&1; then
        log_info "Prowler image already present"
        return 0
    fi

    if docker pull toniblyx/prowler:latest 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            log_success "Prowler image pulled successfully"
        else
            log_warn "Failed to pull Prowler image - AWS posture scans will fall back to fixture data"
            return 1
        fi
    else
        log_warn "Failed to pull Prowler image - AWS posture scans will fall back to fixture data"
        return 1
    fi
}


pull_velociraptor_base_image() {
    # Velociraptor's Dockerfile builds FROM ubuntu:22.04. Pre-pulling the base
    # image on the host with retry keeps a transient Docker Hub DNS hiccup at
    # "compose build" time from killing the whole module install.
    local velo_enabled
    velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if ! is_enabled "$velo_enabled"; then
        return 0
    fi

    local image="ubuntu:22.04"
    log_info "Pulling Ubuntu base image for Velociraptor build..."

    if docker image inspect "$image" > /dev/null 2>&1; then
        log_info "  $image already exists"
        return 0
    fi

    if _pull_image_with_retry "$image"; then
        log_success "  $image pulled successfully"
    else
        log_warn "  Failed to pull $image after retries — Velociraptor build will likely fail"
        return 1
    fi
}

pull_iris_images() {
    # Pre-pull every image IRIS needs at runtime (rabbitmq + dfir-iris stack)
    # so "compose up" doesn't have to talk to Docker Hub / GHCR. A single
    # registry blip in the middle of "compose up" otherwise interrupts the
    # whole stack — which is exactly what happened in install_20260428_072205.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        return 0
    fi

    local iris_version
    iris_version=$(read_config "['versions']['iris']")
    if [[ -z "$iris_version" || "$iris_version" == "None" ]]; then
        log_warn "  IRIS version missing from config.yaml; skipping IRIS image pre-pull"
        return 1
    fi

    log_info "Pre-pulling IRIS images..."

    local images=(
        "rabbitmq:3-management-alpine"
        "ghcr.io/dfir-iris/iriswebapp_db:${iris_version}"
        "ghcr.io/dfir-iris/iriswebapp_app:${iris_version}"
        "ghcr.io/dfir-iris/iriswebapp_nginx:${iris_version}"
    )

    local rc=0
    for image in "${images[@]}"; do
        if docker image inspect "$image" > /dev/null 2>&1; then
            log_info "  $image already exists"
            continue
        fi
        log_info "  Pulling $image..."
        if _pull_image_with_retry "$image"; then
            log_success "  Pulled $image"
        else
            log_warn "  Failed to pull $image after retries — IRIS deployment may fail"
            rc=1
        fi
    done
    return "$rc"
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
        -days 730 -nodes -subj "/CN=Intact.AI-Intact.AI-DFIR" 2>> "$LOG_FILE"

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
