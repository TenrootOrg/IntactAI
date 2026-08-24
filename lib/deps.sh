#!/bin/bash
# Intact.AI Platform Installer - Host Dependencies
#
# Everything that gets Docker and the handful of apt packages the installer
# itself needs (curl, python3-yaml, ...) onto the box: the live-internet path
# (install_dependencies / install_docker_online, unchanged from before this
# file existed) and the release-bundle path added alongside it
# (install_dependencies_from_package / install_docker_from_package).
#
# Split out of lib/docker.sh so this half -- which touches apt and can be
# exercised with a stubbed apt-get -- is testable independent of the image
# pull / registry half that remains there.

# The probe is what actually decides — a package can be half-configured, and
# `dpkg -s` would call that installed. python3-pip is probed via `python3 -m
# pip` rather than `command -v pip3` because the two disagree on plenty of
# boxes (pip importable, no pip3 shim, and vice versa).
INTACT_HOST_DEPS=(
    "curl|command -v curl"
    "wget|command -v wget"
    "git|command -v git"
    "python3|command -v python3"
    "python3-pip|python3 -m pip --version"
    "python3-yaml|python3 -c 'import yaml'"
    "openssl|command -v openssl"
    "jq|command -v jq"
    "dnsutils|command -v dig"
    "lsb-release|command -v lsb_release"
)

# Which of INTACT_HOST_DEPS are missing right now. Echoes apt package names,
# space separated; empty output means everything is present.
_missing_host_deps() {
    local entry pkg probe out=()
    for entry in "${INTACT_HOST_DEPS[@]}"; do
        pkg="${entry%%|*}"; probe="${entry#*|}"
        eval "$probe" >/dev/null 2>&1 || out+=("$pkg")
    done
    echo "${out[*]}"
}

install_dependencies() {
    log_info "Checking system dependencies..."

    # PROBE BEFORE apt. This used to run `apt-get update` + a nine-package
    # `apt-get install` unconditionally, which cost ~2 minutes on every online
    # run of an already-provisioned box (measured 2026-08-04: 14:08:19 ->
    # 14:10:28) to install nothing. It is also mostly moot by the time it runs:
    # read_config() is `python3 -c "import yaml"` and download_release_assets()
    # needs curl + python3, and both run ~100 lines EARLIER in main(). So on a
    # box that got this far, these packages are present by definition.
    #
    # Nothing downstream needs fresh apt lists either — install_docker_online()
    # manages its own repo and runs its own `apt-get update`.
    local missing; missing="$(_missing_host_deps)"
    if [[ -z "$missing" && "${INTACT_FORCE_APT:-0}" != "1" ]]; then
        log_success "System dependencies already present — skipping apt"
        record_install_note "apt was skipped: every host dependency was already installed. Set INTACT_FORCE_APT=1 to force apt-get update + install."
        return 0
    fi

    if [[ -n "$missing" ]]; then
        log_info "  Missing: ${missing} — installing via apt"
    else
        log_info "  INTACT_FORCE_APT=1 — running apt even though nothing is missing"
        missing="$(printf '%s ' "${INTACT_HOST_DEPS[@]%%|*}")"
    fi

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

    # Install only what is actually missing, so a nearly-complete box does one
    # small transaction instead of nine.
    # Word splitting on $missing is the intent, not a bug.
    # shellcheck disable=SC2086
    if ! apt-get install -y -qq $missing 2>> "$LOG_FILE"; then
        log_error "Failed to install some dependencies"
        return 1
    fi

    # RE-PROBE. apt can exit 0 having installed something that still doesn't
    # satisfy us (held package, broken postinst, a python3-yaml that imports
    # against a different interpreter). Previously this function trusted apt's
    # exit code and logged "System dependencies installed" regardless, so a
    # genuinely missing python3-yaml surfaced ~100 lines later as read_config
    # silently returning empty strings.
    local still; still="$(_missing_host_deps)"
    if [[ -n "$still" ]]; then
        log_error "Still missing after apt: ${still}"
        log_error "  Install them by hand and re-run: sudo apt-get install ${still}"
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
# Install Docker + host dependencies from a bundled package
# ============================================================================
# A staged system-bundle directory (a real local apt repo: .deb files plus a
# CI-built Packages/Packages.gz -- see build-release-assets.yml's
# "system-bundle" step for how it's built) means
# this release never needs download.docker.com or a live apt mirror, online
# or air-gapped. THE PACKAGE IS THE ONLY SOURCE for anything in it -- no
# online fallback if something here fails. A release too old to carry a
# bundle simply never calls these; main() falls through to the pre-bundle
# behaviour (install_docker_online() / the air-gap presence-check) unchanged
# for exactly that case.
#
# The naive version of this (bare `apt-get install <bundle>/*.deb`) was
# tried and confirmed broken -- it does not reliably resolve dependencies
# even when every needed .deb is present. This is why the bundle ships a
# real repo index instead: point a `file://` source at it and let apt do
# its normal dependency resolution.

# Refuses to use a bundle built for a different Ubuntu release. A .deb built
# against 24.04's libc/systemd is not safely installable on 22.04 or a
# future 26.04 even though the package *names* match. Hard failure, not a
# fall-through -- per the "package is the only source" design, there is
# nowhere else to fall through to.
_verify_system_bundle_os_match() {
    local bundle_dir="$1"
    local bundle_version host_version
    bundle_version="$(cat "${bundle_dir}/ubuntu-version" 2>/dev/null || true)"
    if [[ -z "$bundle_version" ]]; then
        log_error "  System bundle at ${bundle_dir} has no ubuntu-version marker — refusing to use it"
        return 1
    fi
    host_version="$(. /etc/os-release && echo "$VERSION_ID")"
    if [[ "$bundle_version" != "$host_version" ]]; then
        log_error "=============================================="
        log_error "The release's dependency bundle was built for Ubuntu ${bundle_version},"
        log_error "but this host is running Ubuntu ${host_version}. A .deb set built"
        log_error "for one Ubuntu release is not safe to install on another."
        log_error "=============================================="
        return 1
    fi
    return 0
}

# Points apt at the bundle as a local, unsigned repo and installs the named
# packages from it. Shared by both install_docker_from_package() and
# install_dependencies_from_package() since the mechanism is identical --
# only the package list differs.
_INTACT_BUNDLE_APT_LIST="/etc/apt/sources.list.d/intact-system-bundle.list"
_apt_install_from_bundle() {
    local bundle_dir="$1"; shift
    local list_file="$_INTACT_BUNDLE_APT_LIST"

    # realpath, not the raw argument: bundle_dir can be whatever the operator
    # typed after --package ("./assets", "../usb/pkg", ...), and apt's
    # `file:` URI has no concept of a working directory to resolve a
    # relative path against -- `file:./assets/system-bundle` fails to
    # resolve on every apt version tested. A path containing whitespace
    # breaks sources.list's own parsing outright (it has no quoting), so
    # that is refused rather than silently mis-parsed.
    local resolved; resolved="$(realpath -- "$bundle_dir" 2>/dev/null)"
    if [[ -z "$resolved" || ! -d "$resolved" ]]; then
        log_error "  Bundle directory does not exist: ${bundle_dir}"
        return 1
    fi
    if [[ "$resolved" == *[[:space:]]* ]]; then
        log_error "  Bundle path contains whitespace, which apt's sources.list"
        log_error "  cannot express: ${resolved}"
        return 1
    fi

    # Remove any copy left over from an install that was interrupted between
    # this write and the cleanup at the end of this function -- otherwise it
    # keeps pointing apt at a data/tmp extraction dir a later run may have
    # already wiped, breaking the NEXT run's unrelated `apt-get update`.
    rm -f "$list_file"
    # Belt-and-suspenders against that same leftover: an EXIT trap fires even
    # if this function (or something it calls) exits non-zero or the script
    # is killed mid-install, which a plain cleanup-at-the-end block would not
    # cover.
    trap 'rm -f "$_INTACT_BUNDLE_APT_LIST"' EXIT

    # Same guard install_dependencies()/install_docker_online() already use
    # before touching apt -- missing here meant a freshly-booted VM (exactly
    # this feature's target scenario) could lose the race against
    # unattended-upgrades and die with "Could not get lock
    # /var/lib/dpkg/lock-frontend", the same failure that guard exists for.
    if ! wait_for_dpkg_lock; then
        log_error "  Cannot install from the bundled dependency repo — dpkg lock not available"
        return 1
    fi

    echo "deb [trusted=yes] file:${resolved} ./" > "$list_file"
    if ! apt-get update -qq -o Dir::Etc::sourcelist="sources.list.d/intact-system-bundle.list" \
            -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0" 2>> "$LOG_FILE"; then
        log_error "  Could not read the bundled dependency repo (${resolved})"
        rm -f "$list_file"
        return 1
    fi
    if ! apt-get install -y -qq "$@" 2>> "$LOG_FILE"; then
        log_error "  Failed installing from the bundled dependency repo — see $LOG_FILE"
        rm -f "$list_file"
        return 1
    fi
    rm -f "$list_file"
    return 0
}

install_docker_from_package() {
    local bundle_dir="$1"
    if command -v docker &> /dev/null; then
        # Same as install_docker(): an already-installed Docker, by any
        # method, is left alone -- this only ever fires on an empty box.
        install_docker
        return
    fi
    _verify_system_bundle_os_match "$bundle_dir" || return 1

    log_info "Installing Docker from the release's bundled dependency repo (no internet)..."
    if ! _apt_install_from_bundle "$bundle_dir" \
            docker-ce docker-ce-cli containerd.io docker-compose-plugin; then
        return 1
    fi

    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'EOF'
{
  "features": {
    "containerd-snapshotter": false
  }
}
EOF
    if ! systemctl start docker 2>> "$LOG_FILE"; then
        log_error "  Docker installed from the bundle but failed to start"
        return 1
    fi
    systemctl enable docker 2>> "$LOG_FILE" || log_warn "  Failed to enable Docker service on boot"
    if ! docker info &> /dev/null; then
        log_error "  Docker service started but not responding"
        return 1
    fi
    if [[ -n "$SUDO_USER" ]]; then
        usermod -aG docker "$SUDO_USER"
        log_success "  User $SUDO_USER added to docker group (logout/login required)"
    fi
    log_success "Docker installed from the bundled package"
}

install_dependencies_from_package() {
    local bundle_dir="$1"
    log_info "Checking system dependencies..."
    local missing; missing="$(_missing_host_deps)"
    if [[ -z "$missing" && "${INTACT_FORCE_APT:-0}" != "1" ]]; then
        log_success "System dependencies already present — skipping the bundle"
        return 0
    fi
    [[ -n "$missing" ]] || missing="$(printf '%s ' "${INTACT_HOST_DEPS[@]%%|*}")"
    _verify_system_bundle_os_match "$bundle_dir" || return 1

    log_info "  Installing from the release's bundled dependency repo: ${missing}"
    # Word splitting on $missing is the intent, not a bug.
    # shellcheck disable=SC2086
    if ! _apt_install_from_bundle "$bundle_dir" $missing; then
        return 1
    fi
    local still; still="$(_missing_host_deps)"
    if [[ -n "$still" ]]; then
        log_error "  Still missing after installing from the bundle: ${still}"
        return 1
    fi
    log_success "System dependencies installed from the bundled package"
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
# Core Dependencies Orchestration
# ============================================================================
# Everything main() needs to reach "docker is installed, verified, and the
# network is configured": the connectivity check, locating/staging this
# release's system bundle (if it carries one), and installing dependencies +
# Docker from it, from a live apt mirror, or (air-gapped, no bundle)
# verifying they're already present.
#
# Pulled out of main() into its own function so it can be driven by a test
# with stubbed collaborators (install_docker, apt-get, curl, ...) across
# every branch, rather than only ever having run for real on whatever boxes
# this shipped to.

# Global: the bundle directory ensure_core_dependencies() resolved and
# installed from, or empty if this release/args carry none. A global rather
# than a main()-local return value so a test can assert which path a given
# scenario took without scraping log output.
INTACT_BUNDLE_DIR=""

# Resolves INTACT_SYSTEM_BUNDLE_SRC (set by parse_install_args, lib/args.sh)
# to a ready-to-use bundle directory. $1 is either an already-extracted
# "system-bundle" directory (nothing to do) or a "*-system-bundle.tar" file
# (extract it). Echoes the final directory on success. Any failure here is
# fatal to the caller -- once a release advertises a bundle there is nowhere
# else to fall through to.
_stage_system_bundle_from_source() {
    local src="$1"
    if [[ -d "$src" ]]; then
        echo "$src"
        return 0
    fi
    local extract_dir="${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    if ! tar -xf "$src" -C "$extract_dir" 2>>"$LOG_FILE"; then
        log_error "  Could not extract the supplied dependency bundle (${src})"
        return 1
    fi
    echo "$extract_dir"
}

ensure_core_dependencies() {
    INTACT_BUNDLE_DIR=""

    # Network check runs BEFORE any image loading in the caller. This used to
    # run AFTER load_images_from_package() -- so on a genuinely fresh box
    # (docker never installed), the early DOCKER_BIN resolution in main()
    # found nothing, "docker load" failed with "docker: command not found",
    # and the code that would have INSTALLED docker never even ran yet.
    # Installing/verifying docker first means the loader always has a real
    # docker to call.
    if [[ "$INTACT_AIRGAP" == "1" ]]; then
        # No connectivity check: there is deliberately no route out. The
        # package replaces every registry fetch, so reachability is irrelevant
        # and the existing gate would abort a perfectly valid install.
        log_info "Air-gapped mode — skipping the internet connectivity check"
    elif ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    fi

    # -------------------------------------------------------------------------
    # Docker/dependency bundle — staged before Core Dependencies runs, so that
    # section installs from it instead of ever touching download.docker.com
    # or a live apt mirror. A release that predates this feature simply has
    # no bundle to find (INTACT_SYSTEM_BUNDLE_SRC empty, or
    # download_system_bundle returns 1) — that falls through to the exact
    # pre-bundle behaviour below, unchanged. A release that DOES advertise a
    # bundle but can't produce it working is a hard failure (return 2) — per
    # the "package is the only source" design, there is nowhere else to fall
    # through to once a release promises one.
    # -------------------------------------------------------------------------
    if [[ "$INTACT_AIRGAP" == "1" ]]; then
        if [[ -n "${INTACT_SYSTEM_BUNDLE_SRC:-}" ]]; then
            INTACT_BUNDLE_DIR="$(_stage_system_bundle_from_source "$INTACT_SYSTEM_BUNDLE_SRC")" || exit 1
        fi
    else
        local _bundle_tag; _bundle_tag="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || true)"
        if [[ -n "$_bundle_tag" ]]; then
            # download_system_bundle() needs curl, and this runs before
            # install_dependencies() -- which is what normally installs
            # curl (INTACT_HOST_DEPS) -- gets a chance to. Confirmed live on
            # a genuinely fresh box: without this, the GitHub API check
            # fails with "curl exit 127" and ensure_core_dependencies
            # (correctly, per the "package is the only source" design)
            # treats that as a fatal, unobtainable-bundle error rather than
            # falling through -- turning a perfectly good online install
            # into a hard failure before it even starts. Idempotent and
            # cheap: install_dependencies() below still runs its own full
            # pass; apt just finds curl already satisfied.
            if ! command -v curl &>/dev/null; then
                log_info "Bootstrapping curl (needed to check for a dependency bundle)..."
                wait_for_dpkg_lock || { log_error "Cannot bootstrap curl -- dpkg lock not available"; exit 1; }
                apt-get update -qq 2>>"$LOG_FILE" || true
                apt-get install -y -qq curl ca-certificates 2>>"$LOG_FILE" || true
            fi
            download_system_bundle "$_bundle_tag" "${SCRIPT_DIR}/data/tmp/system-bundle-pkg"
            case $? in
                0) INTACT_BUNDLE_DIR="${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle" ;;
                1) INTACT_BUNDLE_DIR="" ;;
                2) log_error "The release's dependency bundle could not be obtained — aborting installation"
                   exit 1 ;;
            esac
        fi
    fi

    # -------------------------------------------------------------------------
    # Core Dependencies
    # -------------------------------------------------------------------------
    # Air-gap, no bundle: apt and the docker repo are both internet-only, so
    # these have to be satisfied ALREADY. Check rather than attempt -- a
    # failed `apt-get update` on a box with no route produces a confusing
    # wall of DNS errors, where "docker is not installed and I cannot install
    # it here" is the actual problem and is worth saying in one line.
    if [[ -n "$INTACT_BUNDLE_DIR" ]]; then
        install_dependencies_from_package "$INTACT_BUNDLE_DIR" || exit 1
        prefer_ipv4_dns
    elif [[ "$INTACT_AIRGAP" == "1" ]]; then
        local _missing=()
        command -v docker >/dev/null 2>&1 || _missing+=("docker")
        docker compose version >/dev/null 2>&1 || _missing+=("docker-compose-plugin")
        command -v python3 >/dev/null 2>&1 || _missing+=("python3")
        python3 -c 'import yaml' >/dev/null 2>&1 || _missing+=("python3-yaml")
        command -v openssl >/dev/null 2>&1 || _missing+=("openssl")
        if (( ${#_missing[@]} > 0 )); then
            log_error "=============================================="
            log_error "Air-gapped install needs these already present: ${_missing[*]}"
            log_error ""
            log_error "They come from apt and the Docker repository, which this"
            log_error "install cannot reach by design. Install them on this host"
            log_error "first (or use an image that ships them), then re-run with"
            log_error "--package."
            log_error "=============================================="
            exit 1
        fi
        log_success "Host prerequisites present (docker, compose, python3, yaml, openssl)"
    else
        install_dependencies
        prefer_ipv4_dns
    fi
    if [[ -n "$INTACT_BUNDLE_DIR" ]]; then
        install_docker_from_package "$INTACT_BUNDLE_DIR" || {
            log_error "=============================================="
            log_error "Docker installation from the bundled package failed — aborting install."
            log_error "=============================================="
            exit 1
        }
    elif [[ "$INTACT_AIRGAP" != "1" ]] && ! install_docker; then
        log_error "=============================================="
        log_error "Docker installation failed — aborting install."
        log_error ""
        log_error "Fix the underlying issue (DNS, firewall, apt, etc.),"
        log_error "then re-run this script. Nothing below this point will"
        log_error "work without a functional docker daemon."
        log_error "=============================================="
        exit 1
    fi
    # Defensive: install_docker can log success for an unhealthy daemon if
    # something exotic happens mid-install. Gate the rest of the flow on a
    # real `docker version` call so we don't cascade through 'command not
    # found' errors for every module if Docker isn't actually usable.
    if ! command -v docker &>/dev/null || ! docker version &>/dev/null; then
        log_error "Docker reports installed but 'docker version' fails — aborting"
        exit 1
    fi
    # Re-resolve now that install_docker has had a chance to put it there for
    # a genuinely fresh box (the early resolution in main() can only have
    # found a pre-existing install). See that comment for why this exists.
    DOCKER_BIN="$(command -v docker 2>/dev/null || echo docker)"
    # Advisory: warn (never block) if the daemon is below the supported floor.
    # Matters mainly when Docker was pre-installed (a fresh install pulls the
    # current release from download.docker.com, which is always new enough).
    check_docker_min_version
    configure_docker_resolver
    create_network
}

