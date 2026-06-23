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

    # Block on Ubuntu's unattended-upgrades daemon if it's holding the
    # dpkg lock (common on fresh-boot VMs). Without this, install.sh
    # races and aborts with "Could not get lock /var/lib/dpkg/lock-frontend"
    # — exactly what bit a 2026-06-16 install at 09:18.
    if ! wait_for_dpkg_lock; then
        log_error "Cannot install dependencies — dpkg lock not available"
        return 1
    fi

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
    # Same dpkg-lock guard as install_dependencies — unattended-upgrades
    # may still be holding the lock from the security-patch pass that
    # fires on first VM boot. The fresh install_dependencies above
    # already waited, but it's been a minute since then and apt-daily
    # cron could have re-grabbed the lock; re-check here.
    if ! wait_for_dpkg_lock; then
        log_error "Cannot install Docker — dpkg lock not available"
        return 1
    fi

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
        local pull_start=$SECONDS
        if docker pull "$image" 2>&1 | tee -a "$LOG_FILE"; then
            if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
                _log_pull_throughput "$image" "$pull_start"
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

# Log per-pull timing + effective throughput. Diagnostic for "is the customer
# network the bottleneck, or is the registry?" — without it, slow installs
# look like hangs and operators can't distinguish "200 kB/s uplink" from
# "buildkit stuck on resolve". `docker image inspect .Size` is total image
# size, so on cache-hit pulls (elapsed <5s) we skip the rate to avoid
# reporting fake-fast numbers like "5000 MB/s".
_log_pull_throughput() {
    local image="$1"
    local start_ts="$2"
    local elapsed=$(( SECONDS - start_ts ))
    local size_bytes
    size_bytes=$(docker image inspect --format '{{.Size}}' "$image" 2>/dev/null)
    if [[ -z "$size_bytes" || ! "$size_bytes" =~ ^[0-9]+$ ]]; then
        log_info "    ↳ $image: ${elapsed}s (size unknown)"
        return 0
    fi
    local size_mb=$(( size_bytes / 1048576 ))
    if (( elapsed < 5 )); then
        log_info "    ↳ $image: ${elapsed}s — ${size_mb} MB (cached / fast path)"
        return 0
    fi
    # kB/s as primary unit — fits the slow-uplink case from
    # install_20260610_070534.log where rates were ~120-250 kB/s. Add MB/s
    # only when fast enough that kB/s is unwieldy (>= 1 MB/s).
    local kbps=$(( size_bytes / 1024 / elapsed ))
    if (( kbps >= 1024 )); then
        local mbps_x10=$(( size_bytes * 10 / 1048576 / elapsed ))
        local mbps_int=$(( mbps_x10 / 10 ))
        local mbps_frac=$(( mbps_x10 % 10 ))
        log_info "    ↳ $image: ${size_mb} MB in ${elapsed}s = ${kbps} kB/s (~${mbps_int}.${mbps_frac} MB/s)"
    else
        log_info "    ↳ $image: ${size_mb} MB in ${elapsed}s = ${kbps} kB/s"
    fi
}

# Curl wrapper that logs bytes + wall-clock + computed kB/s using curl's
# own --write-out telemetry. Mirrors _log_pull_throughput so the log lines
# look the same whether the bottleneck was a docker pull or a host curl.
# Returns curl's exit code. Stdout of curl is not captured here — caller
# uses curl's own -o/-O to direct the body.
_curl_with_throughput() {
    local label="$1"
    local url="$2"
    local dest="$3"
    shift 3  # remaining args passed through to curl
    local stats
    stats=$(curl -fsSL "$@" \
        -w '%{size_download} %{time_total} %{speed_download}\n' \
        "$url" -o "$dest" 2>> "$LOG_FILE")
    local rc=$?
    if (( rc == 0 )) && [[ -n "$stats" ]]; then
        # curl prints size in bytes, time in seconds (float), speed in B/s
        local bytes seconds_f bps_f
        read -r bytes seconds_f bps_f <<< "$stats"
        local size_mb=$(( ${bytes:-0} / 1048576 ))
        local seconds_int=${seconds_f%.*}
        [[ -z "$seconds_int" ]] && seconds_int=0
        local kbps=$(( ${bps_f%.*} / 1024 ))
        if (( seconds_int < 2 )); then
            log_info "    ↳ $label: ${seconds_int}s — ${size_mb} MB (fast path)"
        elif (( kbps >= 1024 )); then
            local mbps_x10=$(( ${bps_f%.*} * 10 / 1048576 ))
            log_info "    ↳ $label: ${size_mb} MB in ${seconds_int}s = ${kbps} kB/s (~$(( mbps_x10 / 10 )).$(( mbps_x10 % 10 )) MB/s)"
        else
            log_info "    ↳ $label: ${size_mb} MB in ${seconds_int}s = ${kbps} kB/s"
        fi
    fi
    return $rc
}

pull_plaso_image() {
    local plaso_version=$(read_config "['versions']['plaso']")
    # Defensive: older configs shipped `plaso: 'plaso-20260119'` (with a
    # redundant `plaso-` prefix). Upstream's actual tags are bare dates
    # (`log2timeline/plaso:20260119`). Strip the legacy prefix so a
    # stale-config import doesn't re-trigger the 2026-06-14
    # `manifest unknown` install failure.
    plaso_version="${plaso_version#plaso-}"
    local plaso_image="log2timeline/plaso:${plaso_version:-20260119}"

    log_info "Pulling Plaso image for timeline processing..."

    if docker image inspect "$plaso_image" &> /dev/null; then
        log_info "Plaso image already exists: $plaso_image"
        return 0
    fi

    log_info "Downloading $plaso_image (this may take a few minutes)..."
    local pull_start=$SECONDS
    if docker pull "$plaso_image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            _log_pull_throughput "$plaso_image" "$pull_start"
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
    local pull_start=$SECONDS
    if docker pull "$image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            _log_pull_throughput "$image" "$pull_start"
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
    # GitHub tag resolution. Velocidex's tagging changed at v0.76.6: newer
    # patches get their OWN full-version tag (e.g. v0.77.1), while older 0.76.x
    # patches still live under the minor tag (v0.76). The naive major.minor
    # truncation 404s on v0.77+ — so probe the full-version tag first and only
    # fall back to the minor tag. (Matches resolve_velociraptor_release_tag in
    # the backend upgrade path.)
    local downloads_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local full_tag="v${velo_version}"
    local minor_tag="v$(echo "$velo_version" | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')"
    local velo_tag="$minor_tag"
    local _probe="velociraptor-v${velo_version}-windows-amd64.exe"
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' -IL \
            "https://github.com/Velocidex/velociraptor/releases/download/${full_tag}/${_probe}" 2>/dev/null)" == "200" ]]; then
        velo_tag="$full_tag"
    fi
    log_info "  Resolved Velociraptor release tag: ${velo_tag} (for v${velo_version})"
    local base_url="https://github.com/Velocidex/velociraptor/releases/download/${velo_tag}"

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

    # Clean up any prior-version MODERN binaries so the downloads dir reflects
    # the current pin. The glob `velociraptor-v*-` also matches the LEGACY
    # binaries (e.g. v0.7.1) the legacy downloader manages separately — those
    # MUST be preserved, so skip the legacy pin explicitly. (Previously this
    # wiped the legacy Windows/Linux installers on every install/upgrade.)
    local legacy_version
    legacy_version=$(read_config "['versions']['velociraptor_legacy']")
    local stale=0
    for old in "$downloads_dir"/velociraptor-v*-windows-amd64.exe \
               "$downloads_dir"/velociraptor-v*-linux-amd64 \
               "$downloads_dir"/velociraptor-v*-linux-amd64-musl \
               "$downloads_dir"/velociraptor-v*-darwin-amd64; do
        [[ -f "$old" ]] || continue
        # Keep the configured modern version.
        [[ "$old" == *"-v${velo_version}-"* ]] && continue
        # Keep the legacy pin (managed by download_legacy_velociraptor_binaries).
        if [[ -n "$legacy_version" && "$legacy_version" != "None" && "$old" == *"-v${legacy_version}-"* ]]; then
            continue
        fi
        log_info "  Removing stale binary: $(basename "$old")"
        rm -f "$old"
        ((stale++))
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
            if _curl_with_throughput "$binary" "${base_url}/${binary}" "$dest_path"; then
                chmod +x "$dest_path" 2>/dev/null || true
                log_success "  Downloaded: $binary"
                ((downloaded++))
            else
                rm -f "$dest_path"
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
            rm -f "$p"
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

stage_velociraptor_client_binaries() {
    # Stage the four binaries the Velociraptor Dockerfile COPYs at
    # build time. Without these, `docker compose build` fails because
    # the Dockerfile is pure COPY (intentionally — see Dockerfile
    # comments for why we moved off in-container curl).
    #
    # Args:
    #   $1 = full version, e.g. "0.75.6"
    #   $2 = velociraptor module dir (the docker build context)
    #
    # Side effects:
    #   Populates $module_dir/clients/{linux,mac,windows}/...
    #
    # Returns 0 on success, 1 if any required binary couldn't be
    # downloaded.

    local velo_version="$1"
    local module_dir="$2"

    if [[ -z "$velo_version" || -z "$module_dir" ]]; then
        log_error "stage_velociraptor_client_binaries: version + module_dir required"
        return 1
    fi

    local parts
    IFS='.' read -r -a parts <<< "$velo_version"
    if (( ${#parts[@]} < 2 )); then
        log_error "stage_velociraptor_client_binaries: malformed version '$velo_version' — need at least major.minor"
        return 1
    fi
    local release_tag="v${parts[0]}.${parts[1]}"
    local base_url="https://github.com/Velocidex/velociraptor/releases/download/${release_tag}"

    local linux_dir="${module_dir}/clients/linux"
    local mac_dir="${module_dir}/clients/mac"
    local win_dir="${module_dir}/clients/windows"
    mkdir -p "$linux_dir" "$mac_dir" "$win_dir"

    # Pairs of "dest_path|upstream_filename" — must mirror
    # services/upgrade/velociraptor.py:_velociraptor_binary_set.
    local items=(
        "${linux_dir}/velociraptor|velociraptor-v${velo_version}-linux-amd64"
        "${mac_dir}/velociraptor_client|velociraptor-v${velo_version}-darwin-amd64"
        "${win_dir}/velociraptor_client.exe|velociraptor-v${velo_version}-windows-amd64.exe"
        "${win_dir}/velociraptor_client.msi|velociraptor-v${velo_version}-windows-amd64.msi"
    )

    local min_size=$((1 * 1024 * 1024))  # 1 MB floor — under that = HTTP 404 / rate-limit / partial
    local required_dest="${linux_dir}/velociraptor"
    local required_ok=0
    local placeholders=0

    for item in "${items[@]}"; do
        local dest="${item%%|*}"
        local fname="${item##*|}"
        local is_required=0
        [[ "$dest" == "$required_dest" ]] && is_required=1

        if [[ -f "$dest" ]] && [[ $(stat -c%s "$dest" 2>/dev/null || echo 0) -ge $min_size ]]; then
            log_info "  Already staged: $(basename "$dest")"
            (( is_required )) && required_ok=1
            continue
        fi

        log_info "  Staging: $fname  (from ${base_url}/${fname})"
        local sz=0
        if curl -fsSL --retry 5 --retry-delay 5 --retry-max-time 120 \
                "${base_url}/${fname}" -o "$dest" 2>> "$LOG_FILE"; then
            sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
        else
            sz=0
            rm -f "$dest"
        fi

        if (( sz < min_size )); then
            if (( is_required )); then
                log_error "  REQUIRED binary unavailable upstream: $fname"
                return 1
            fi
            # Optional client binary missing (e.g. v0.75.6 has no
            # darwin-amd64). Drop a zero-byte placeholder so the
            # Dockerfile COPY still succeeds; entrypoint's repack
            # step silently no-ops on the empty file.
            log_warn "  $fname unavailable upstream — using empty placeholder (no pre-repacked client for this platform)"
            : > "$dest"
            ((placeholders++))
            continue
        fi

        if [[ "$dest" != *.msi ]]; then
            chmod +x "$dest" 2>/dev/null || true
        fi
        log_success "  Staged: $(basename "$dest") (${sz} bytes)"
        (( is_required )) && required_ok=1
    done

    if (( required_ok != 1 )); then
        log_error "stage_velociraptor_client_binaries: linux server binary not staged. Install/upgrade cannot continue."
        return 1
    fi

    if (( placeholders > 0 )); then
        log_warn "stage_velociraptor_client_binaries: ${placeholders} optional client binary placeholder(s) inserted — image build will succeed, those platforms just won't have a pre-repacked client."
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
            if _curl_with_throughput "$binary" "${base_url}/${binary}" "$dest_path"; then
                chmod +x "$dest_path" 2>/dev/null || true
                log_success "  Downloaded: $binary"
                ((downloaded++))
            else
                rm -f "$dest_path"
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
            rm -f "$p"
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
    # Download the special velociraptor-collector binary from GitHub.
    # This is a small (~80KB) template binary used by velociraptor's
    # server-side `client_repack` VQL function for Hunt-collector
    # generation. NOT the same as the regular velociraptor binary
    # (70+ MB). Placed in /data/tools/ where configure_inventory
    # registers it with Velociraptor as serve_locally=true.
    #
    # Version pin: read from config.yaml.versions.velociraptor so the
    # downloaded collector matches the velociraptor server version.
    # The old hardcoded v0.75 URL drifted from the installed velociraptor
    # version (which can be 0.76.x or newer), causing Hunt-collector
    # generation to fail with "lookup github.com" at runtime when
    # velociraptor server tried to fetch the version-matching binary
    # from upstream itself.

    local velo_version=$(read_config "['versions']['velociraptor']" 2>/dev/null)
    [[ -z "$velo_version" ]] && velo_version="0.76.6"   # safe fallback
    velo_version="${velo_version#v}"   # strip leading v if present

    local collector_url="https://github.com/Velocidex/velociraptor/releases/download/v${velo_version}/velociraptor-collector"
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
    if _curl_with_throughput "velociraptor-collector" "$collector_url" "$dest_path"; then
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
    local azure_enabled=$(read_config "['modules']['o365rc']['enabled']")
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

    local azure_enabled=$(read_config "['modules']['o365rc']['enabled']")
    if ! is_enabled "$azure_enabled"; then
        log_info "Azure module disabled, skipping DFIR-O365RC"
        return 0
    fi

    # Version pin from config.yaml (upstream only ships ':latest').
    local o365rc_version=$(read_config "['versions']['o365rc']")
    [[ -z "$o365rc_version" ]] && o365rc_version="latest"
    local o365rc_image="anssi/dfir-o365rc:${o365rc_version}"

    log_info "Pulling DFIR-O365RC image (${o365rc_image}, Unified Audit Log collection)..."

    if docker image inspect "$o365rc_image" > /dev/null 2>&1; then
        log_info "DFIR-O365RC image already present"
        return 0
    fi

    local pull_start=$SECONDS
    if docker pull "$o365rc_image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            _log_pull_throughput "$o365rc_image" "$pull_start"
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

    local aws_enabled=$(read_config "['modules']['prowler']['enabled']")
    if ! is_enabled "$aws_enabled"; then
        log_info "AWS module disabled, skipping Prowler image"
        return 0
    fi

    # Version pin from config.yaml for reproducible installs.
    local prowler_version=$(read_config "['versions']['prowler']")
    [[ -z "$prowler_version" ]] && prowler_version="5.28.1"
    local prowler_image="toniblyx/prowler:${prowler_version}"

    log_info "Pulling Prowler image (${prowler_image}, AWS posture scans, ~3.5 GB)..."

    if docker image inspect "$prowler_image" > /dev/null 2>&1; then
        log_info "Prowler image already present"
        return 0
    fi

    local pull_start=$SECONDS
    if docker pull "$prowler_image" 2>&1 | tee -a "$LOG_FILE"; then
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            _log_pull_throughput "$prowler_image" "$pull_start"
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

pull_backend_base_image() {
    # The Backend Dockerfile builds FROM python:3.11-slim. Pre-pulling on the
    # host means the ~46 MB base image doesn't count against `docker compose
    # build`'s wall-clock timeout — important on slow-uplink customer VMs
    # where install_20260610_070534.log showed ~120 kB/s sustained, putting
    # the base image alone at ~4 min of the build budget.
    local image="python:3.11-slim"
    log_info "Pulling Python base image for Backend build..."

    if docker image inspect "$image" > /dev/null 2>&1; then
        log_info "  $image already exists"
        return 0
    fi

    if _pull_image_with_retry "$image"; then
        log_success "  $image pulled successfully"
    else
        log_warn "  Failed to pull $image after retries — Backend build will likely fail"
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

    local azure_enabled=$(read_config "['modules']['o365rc']['enabled']")
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
