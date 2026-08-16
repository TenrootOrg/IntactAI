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
    elif [[ " $INTACT_SUPPORTED_UBUNTU " != *" ${VERSION_ID:-} "* ]]; then
        # Advisory only — non-LTS / untested Ubuntu releases usually work, but
        # the supported matrix is 20.04 / 22.04 / 24.04. Warn, don't block.
        log_warn "Ubuntu ${VERSION_ID:-?} is outside the tested matrix ($INTACT_SUPPORTED_UBUNTU)."
        log_warn "  Install will continue; see docs/SUPPORTED_PLATFORMS.md for supported releases."
    fi

    log_success "OS Check: $PRETTY_NAME"
}

# The host packages the installer itself needs, as "<apt package>|<probe>".
# INTACT_HOST_DEPS, _missing_host_deps, install_dependencies,
# install_docker_online, install_docker, and the *_from_package variants
# moved to lib/deps.sh.
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
# Already in the local store? Then there is nothing to fetch, and on an
# air-gapped box there is nowhere to fetch it FROM. install.sh --package loads
# every image out of a release package up front, so this one check is what makes
# every existing deploy_* path work offline without rewriting any of them.
#
# Deliberately not gated on --package: an image that is already present is never
# worth re-pulling, and skipping it makes an ONLINE reinstall faster too. The
# registry is only consulted for something the box genuinely does not have.
_image_present_locally() {
    docker image inspect "$1" >/dev/null 2>&1
}

_pull_image_with_retry() {
    local image="$1"
    if _image_present_locally "$image"; then
        log_info "  $image already present locally — not pulling"
        return 0
    fi
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_error "  $image is not in the local image store and this is an "
        log_error "  air-gapped install — the package did not contain it."
        return 1
    fi
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

    # Check FIRST, announce second. Saying "Pulling ..." before looking is how
    # a log ends up claiming a network fetch that never happened -- and the
    # inverse of that noise is what let the real nginx pull hide in plain sight
    # for as long as it did. Grepping an install log for pulls should return
    # pulls.
    if docker image inspect "$plaso_image" &> /dev/null; then
        log_info "Plaso image already present: $plaso_image"
        return 0
    fi

    # Unlike its siblings (pull_python_alpine_image, pull_iris_images, ...)
    # this had no air-gap check at all. Those siblings skip unconditionally
    # under INTACT_FROM_PACKAGE because they're pure build-time base images
    # never needed once a package supplies pre-built images -- but Plaso IS
    # one of the real, shipped module images, so a from-package install that
    # legitimately has it just hit the `docker image inspect` check above and
    # returned already. This only fires for the genuine gap: air-gapped AND
    # somehow still missing (a version-pin mismatch between config.yaml and
    # what the package actually shipped) -- fail fast with a clear reason
    # instead of sitting through a doomed pull attempt and timeout.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_warn "  Plaso image ($plaso_image) not in the local store and this is an air-gapped install — it cannot be pulled. Timeline processing (Plaso) will not work until this image is supplied."
        return 0
    fi

    log_info "Pulling Plaso image for timeline processing..."

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
    # Base images exist ONLY to feed `docker compose build`. When the release
    # package supplied the images there is no build (run_docker_compose skips
    # it), so pulling a base layer is pure waste online -- and offline it is a
    # guaranteed failure that logs an alarming error for something the install
    # does not need. Skip before either happens.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "  Base image not needed — images came from the release package"
        return 0
    fi

    # Python Alpine image is used by Plaso decompression (plaso_service.py)
    # Pre-pull to avoid network access at runtime in air-gap environments

    # Pinned (was floating python:3-alpine) so the pre-pull is reproducible.
    # Matches the currently-shipped Python 3.14 alpine line.
    local image="python:3.14-alpine"

    if docker image inspect "$image" &> /dev/null; then
        log_info "  Python Alpine image already exists"
        return 0
    fi

    log_info "Pulling Python Alpine image for Plaso decompression..."

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

# In air-gap mode there is no route to GitHub, so a download cannot be
# attempted -- but these assets are not all load-bearing, and failing the whole
# install over an optional one would be wrong. install.sh --package stages
# whatever the package carried; this reports precisely what is still missing and
# what the consequence is, then lets the install continue.
#
# Returns 0 = "handled, skip the download", 1 = "carry on and download".
_airgap_asset_check() {
    local what="$1" probe="$2" consequence="$3"
    [[ "${INTACT_AIRGAP:-0}" == "1" ]] || return 1
    if [[ -e "$probe" ]] || compgen -G "$probe" >/dev/null 2>&1; then
        log_info "  $what: already present (staged from the package) — not downloading"
    else
        log_warn "  $what: NOT in the package and cannot be downloaded offline."
        log_warn "    Consequence: $consequence"
        INSTALL_WARNINGS+=("  air-gap: $what unavailable — $consequence")
    fi
    return 0
}

download_offline_collector_binaries() {
    _airgap_asset_check "Velociraptor offline-collector binaries" \
        "${SCRIPT_DIR}/modules/nginx/html/downloads/velociraptor-*" \
        "offline collectors cannot be generated until these are supplied" \
        && return 0

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
    # Skip the probe entirely when air-gapped: there is no route to github.com,
    # so this only burns a connect timeout and then reports the WRONG tag (the
    # minor-tag fallback) as if it had been resolved. Nothing downstream can
    # use it offline anyway — every consumer below is gated on the same flag.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_info "  Air-gapped — not resolving the Velociraptor release tag from GitHub"
    elif [[ "$(curl -s -o /dev/null -w '%{http_code}' -IL \
            "https://github.com/Velocidex/velociraptor/releases/download/${full_tag}/${_probe}" 2>/dev/null)" == "200" ]]; then
        velo_tag="$full_tag"
    fi
    [[ "${INTACT_AIRGAP:-0}" == "1" ]] \
        || log_info "  Resolved Velociraptor release tag: ${velo_tag} (for v${velo_version})"
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
                chmod 755 "$dest_path" 2>/dev/null || true
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
            log_error "  Manual fix: curl -fsSL ${base_url}/${binary} -o $p && chmod 755 $p"
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
    # Velocidex tagging changed at v0.76.6: newer patches get their OWN full-
    # version tag (e.g. v0.77.1), while older 0.76.x patches still live under the
    # minor tag (v0.76). The naive major.minor truncation 404s on v0.77+ — so
    # probe the full-version tag first and only fall back to the minor tag.
    # (Mirrors the offline-collector staging above + resolve_velociraptor_release_tag
    # in the backend upgrade path.)
    local full_tag="v${velo_version}"
    local minor_tag="v${parts[0]}.${parts[1]}"
    local release_tag="$minor_tag"
    # Air-gapped: no route to github.com, so skip the probe (see the identical
    # guard in download_offline_collector_binaries above). Every download below
    # is refused in this mode too — the binaries must have come from the
    # package, which install.sh stages into clients/ with a .version sidecar.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_info "  Air-gapped — using only the binaries staged from the release package"
    elif [[ "$(curl -s -o /dev/null -w '%{http_code}' -IL \
            "https://github.com/Velocidex/velociraptor/releases/download/${full_tag}/velociraptor-v${velo_version}-windows-amd64.exe" 2>/dev/null)" == "200" ]]; then
        release_tag="$full_tag"
        log_info "  Resolved Velociraptor release tag: ${release_tag} (for v${velo_version})"
    else
        log_info "  Resolved Velociraptor release tag: ${release_tag} (for v${velo_version})"
    fi
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

        # Skip only when the staged file is BOTH credible AND the right version.
        #
        # The destinations are version-agnostic (velociraptor_client.exe) while
        # the sources carry the version (velociraptor-v0.77.1-windows-amd64.exe),
        # so a size-only check can never tell WHICH version is sitting there. It
        # answered "big enough, leave it" for any previously staged binary, and
        # every version change after the first silently kept the old one.
        #
        # Observed 2026-08-02: a box staged with 0.77.1 was reinstalled at
        # 0.76.1, the staged 0.77.1 binaries were "already staged", and the
        # image build then refused because the staged binary and the image tag
        # disagreed. Same shape in the other direction on an upgrade.
        #
        # A sidecar records what is actually staged. Absent (every box
        # installed before this change) means unknown, so we re-stage rather
        # than trust it -- but the download failure path below deliberately
        # keeps an existing usable file instead of deleting it, so an air-gapped
        # box that cannot re-download is no worse off than before.
        local ver_marker="${dest}.version"
        local staged_ver=""
        [[ -f "$ver_marker" ]] && staged_ver="$(cat "$ver_marker" 2>/dev/null)"
        if [[ -f "$dest" ]] && [[ $(stat -c%s "$dest" 2>/dev/null || echo 0) -ge $min_size ]] \
           && [[ "$staged_ver" == "$velo_version" ]]; then
            log_info "  Already staged: $(basename "$dest") (v${velo_version})"
            (( is_required )) && required_ok=1
            continue
        fi
        if [[ -f "$dest" ]] && [[ -n "$staged_ver" ]] && [[ "$staged_ver" != "$velo_version" ]]; then
            log_info "  Re-staging $(basename "$dest"): staged v${staged_ver}, need v${velo_version}"
        fi

        # Air-gapped and not already satisfied above: there is no route to
        # GitHub, so do not pretend. Say precisely which file is missing and
        # where it should have come from, and fail only for the one binary the
        # image build genuinely cannot do without.
        if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
            if (( is_required )); then
                log_error "  REQUIRED Velociraptor binary missing and cannot be downloaded (air-gapped):"
                log_error "    wanted: $(basename "$dest")  (v${velo_version})"
                log_error "    source: the release package should carry binaries/${fname}"
                return 1
            fi
            log_warn "  ${fname}: not in the release package and cannot be downloaded offline."
            log_warn "    Consequence: no pre-repacked client for that platform."
            INSTALL_WARNINGS+=("  air-gap: ${fname} unavailable — no pre-repacked client for that platform")
            # Same placeholder the upstream-missing branch below uses, so the
            # Dockerfile COPY still succeeds.
            : > "$dest"
            rm -f "$ver_marker"
            ((placeholders++))
            continue
        fi

        log_info "  Staging: $fname  (from ${base_url}/${fname})"
        local sz=0
        # Download to a temp path, not over $dest. Writing directly meant a
        # failed transfer destroyed a perfectly good previously-staged binary —
        # survivable when the network is up and fatal on an air-gapped box,
        # which is exactly where a re-stage is most likely to fail.
        local tmp_dest="${dest}.staging"
        rm -f "$tmp_dest"
        if curl -fsSL --retry 5 --retry-delay 5 --retry-max-time 120 \
                "${base_url}/${fname}" -o "$tmp_dest" 2>> "$LOG_FILE"; then
            sz=$(stat -c%s "$tmp_dest" 2>/dev/null || echo 0)
        else
            sz=0
            rm -f "$tmp_dest"
        fi
        if (( sz >= min_size )); then
            mv -f "$tmp_dest" "$dest"
            printf '%s\n' "$velo_version" > "$ver_marker"
        elif [[ -f "$dest" ]] && [[ $(stat -c%s "$dest" 2>/dev/null || echo 0) -ge $min_size ]]; then
            # Re-stage failed but a usable binary is already here. Keep it and
            # say so plainly: the version may be wrong, which is a real risk,
            # but deleting the only working binary is a worse one.
            rm -f "$tmp_dest"
            log_warn "  Could not re-stage $fname — keeping the existing $(basename "$dest") (version unverified${staged_ver:+, marker says v$staged_ver})"
            printf '%s\n' "${staged_ver:-unknown}" > "$ver_marker"
            (( is_required )) && required_ok=1
            continue
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
            # A placeholder is not a version. Leaving a stale marker here would
            # make the next run skip it as "already staged at the right version".
            rm -f "$ver_marker"
            ((placeholders++))
            continue
        fi

        if [[ "$dest" != *.msi ]]; then
            chmod 755 "$dest" 2>/dev/null || true
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

    publish_velociraptor_binaries_to_tools "$velo_version"
    return 0
}

publish_velociraptor_binaries_to_tools() {
    # Mirror the staged client binaries into data/tools under their UPSTREAM
    # versioned names.
    #
    # The two sides disagreed on both location and naming: staging writes
    # generic names (clients/windows/velociraptor_client.exe) under
    # modules/velociraptor, while velociraptor_inventory matches
    # `^velociraptor-v.*-windows-amd64.exe$` inside data/tools. So the agent
    # binaries were on the box yet permanently "File not found" in the
    # inventory — and Velociraptor then has no locally-served client to hand
    # out, sending client-package generation to the internet at hunt time.
    # That is the same air-gap failure mode as the image/tar bug.
    local velo_version="$1"
    [[ -z "$velo_version" ]] && return 0
    local module_dir="${SCRIPT_DIR}/modules/velociraptor"
    local tools_dir="${SCRIPT_DIR}/data/tools"
    mkdir -p "$tools_dir"

    local pairs=(
        "${module_dir}/clients/linux/velociraptor|velociraptor-v${velo_version}-linux-amd64"
        "${module_dir}/clients/mac/velociraptor_client|velociraptor-v${velo_version}-darwin-amd64"
        "${module_dir}/clients/windows/velociraptor_client.exe|velociraptor-v${velo_version}-windows-amd64.exe"
        "${module_dir}/clients/windows/velociraptor_client.msi|velociraptor-v${velo_version}-windows-amd64.msi"
    )
    local published=0
    for pair in "${pairs[@]}"; do
        local src="${pair%%|*}"
        local dest="${tools_dir}/${pair##*|}"
        # Skip the zero-byte placeholders the loop above may have written.
        [[ -s "$src" ]] || continue
        if [[ -f "$dest" ]] && [[ $(stat -c%s "$dest" 2>/dev/null || echo 0) -eq $(stat -c%s "$src" 2>/dev/null || echo 1) ]]; then
            continue
        fi
        cp -f "$src" "$dest" 2>/dev/null && ((published++))
    done

    # Drop stale copies from previous versions so the tools dir doesn't grow a
    # binary per upgrade (they are ~85 MB each).
    local keep="velociraptor-v${velo_version}-"
    for old in "$tools_dir"/velociraptor-v*-linux-amd64 \
               "$tools_dir"/velociraptor-v*-darwin-amd64 \
               "$tools_dir"/velociraptor-v*-windows-amd64.exe \
               "$tools_dir"/velociraptor-v*-windows-amd64.msi; do
        [[ -f "$old" ]] || continue
        [[ "$(basename "$old")" == ${keep}* ]] || rm -f "$old"
    done

    (( published > 0 )) && log_success "  Published ${published} Velociraptor client binaries to data/tools (inventory can now serve them locally)"
    return 0
}

download_legacy_velociraptor_binaries() {
    _airgap_asset_check "Legacy Velociraptor client (Win7 / 2008 R2)" \
        "${SCRIPT_DIR}/modules/nginx/html/downloads/velociraptor-v0.7.*" \
        "legacy Windows endpoints cannot be enrolled; current clients are unaffected" \
        && return 0

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
    # ONLY the two builds something actually serves. This used to also fetch
    # the plain linux-amd64 and darwin-amd64 legacy builds -- 113 MB, ~16 min
    # on the 120 kB/s uplinks this codebase elsewhere plans around -- and
    # nothing consumed either:
    #
    #   * darwin-amd64: no UI button, no route, no service path. The
    #     validation loop below already skips it as "a nice to have".
    #   * linux-amd64 (non-musl): referenced only as a FALLBACK in
    #     legacy_velociraptor_service.py (:292-294 and _TARGET_FALLBACK) for
    #     "installs that pre-date the musl download". That fallback cannot
    #     fire on a box this installer touched, because this very loop always
    #     fetches the musl build -- so the preferred tag is always cached and
    #     the except-branch is dead.
    #
    # The release package bundles exactly these two as well, which is what
    # made the mismatch visible: the packager shipped the served set, the
    # downloader fetched a superset.
    local binaries=(
        "velociraptor-v${legacy_version}-windows-amd64.exe"
        "velociraptor-v${legacy_version}-linux-amd64-musl"
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
                chmod 755 "$dest_path" 2>/dev/null || true
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

    mkdir -p "$tools_dir"

    # Check FIRST, announce second -- same rule pull_plaso_image follows. The
    # "Downloading..." line used to print before this check, so a run that
    # staged the collector from the release package still logged a download it
    # never performed. Reading the log, that is indistinguishable from the
    # package having been ignored.
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

    # Nothing staged it and there is no network: say so once, clearly, instead
    # of burning two curl timeouts (pinned URL, then the 'latest' fallback
    # below) to arrive at the same place. Parity with the _airgap_asset_check
    # its two sibling downloaders already use.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_warn "Velociraptor collector template is not in this package and this is an"
        log_warn "  offline install — Hunt-collector generation will be unavailable."
        return 1
    fi

    log_info "Downloading Velociraptor collector template..."

    # Download the collector template from GitHub.
    #
    # The version-pinned URL is a best-effort: Velocidex does NOT cut a GitHub
    # release for every version we pin. `versions.velociraptor: 0.76.1` has no
    # upstream release at all, so this 404'd on the 2026-07-22 install and the
    # box silently ended up with no collector — which per the rationale above
    # makes Hunt-collector generation fail at runtime with "lookup github.com".
    # Fall back to the latest release, which always exists and ships the asset.
    local latest_url="https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-collector"
    local url_label="v${velo_version}"

    log_info "  Downloading from: $collector_url"
    if ! _curl_with_throughput "velociraptor-collector" "$collector_url" "$dest_path"; then
        log_warn "  No collector published for v${velo_version} — falling back to latest release"
        rm -f "$dest_path"
        url_label="latest"
        if ! _curl_with_throughput "velociraptor-collector" "$latest_url" "$dest_path"; then
            log_warn "  Failed to download velociraptor-collector (pinned and latest)"
            return 1
        fi
    fi

    chmod 755 "$dest_path"
    local size=$(stat -c%s "$dest_path" 2>/dev/null || echo "0")
    if [[ "$size" -gt "$min_size" ]]; then
        log_success "  Downloaded: velociraptor-collector from ${url_label} ($(numfmt --to=iec $size))"
        return 0
    else
        log_warn "  Downloaded file too small: $size bytes"
        rm -f "$dest_path"
        return 1
    fi
}

# =============================================================================
# Azure Security Tools
# =============================================================================

download_sigma_rules() {
    # Download SIGMA detection rules for Azure security automation
    # Clones SigmaHQ rules repository for offline use

    # SIGMA rules power BOTH Azure (o365rc) and AWS (cloudtrail) detection.
    # Download when EITHER is enabled; skip only when both are off.
    local azure_enabled=$(read_config "['modules']['o365rc']['enabled']")
    local cloudtrail_enabled=$(read_config "['modules']['aws_sigma']['enabled']")
    if ! is_enabled "$azure_enabled" && ! is_enabled "$cloudtrail_enabled"; then
        log_info "Azure + CloudTrail modules disabled, skipping SIGMA rules download"
        return 0
    fi

    # AIR-GAP. This used to lead with a bare _airgap_asset_check whose
    # consequence line read "cloud detection packs (aws_sigma / o365rc) will
    # have no rules" -- fired BEFORE the enabled-checks above and with no
    # knowledge of the bundled rule pack, so it was wrong in both directions.
    # The 2026-08-16 install warned about o365rc, which is DISABLED, and about
    # aws_sigma, which logged "AWS SIGMA rule pack 2026.04 installed (57
    # rules)" a second later: install_bundled_rule_packs() feeds
    # /opt/sigma-rules/rules/cloud/aws straight from the package and never
    # needs the SigmaHQ clone at all.
    #
    # So name only the packs that will ACTUALLY end up ruleless: enabled, and
    # with no other source of rules. When that list is empty there is nothing
    # to warn about and the run should say so rather than manufacturing a
    # warning it will then have to explain away.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        if [[ -e /opt/sigma-rules/rules ]]; then
            log_info "  SIGMA detection rules: already present (staged from the package) — not downloading"
            return 0
        fi

        local -a stranded=()
        # o365rc has exactly one source: the SigmaHQ clone. Offline, an
        # enabled o365rc genuinely ends up with no Azure rules.
        is_enabled "$azure_enabled" && stranded+=("o365rc")
        # aws_sigma is fed by the bundled pack instead, staged into
        # data/tmp/rule-packs/ by the image loader and applied by
        # install_bundled_rule_packs(). Both spellings, same as there.
        if is_enabled "$cloudtrail_enabled" \
                && ! compgen -G "${SCRIPT_DIR}/data/tmp/rule-packs/aws_sigma-*.tar" >/dev/null 2>&1 \
                && ! compgen -G "${SCRIPT_DIR}/data/tmp/rule-packs/cloudtrail-*.tar" >/dev/null 2>&1; then
            stranded+=("aws_sigma")
        fi

        if (( ${#stranded[@]} > 0 )); then
            local names="${stranded[*]}"
            log_warn "  SIGMA detection rules: NOT in the package and cannot be downloaded offline."
            log_warn "    Consequence: ${names// /, } will have no detection rules"
            INSTALL_WARNINGS+=("  air-gap: SIGMA detection rules unavailable — ${names// /, } will have no detection rules")
        else
            log_info "  SIGMA detection rules: not in this package, and not needed — every enabled cloud pack gets its rules from elsewhere"
        fi
        return 0
    fi

    local sigma_dir="/opt/sigma-rules"

    # Pin the SIGMA clone to a specific SigmaHQ RELEASE TAG (versions.sigma_rules)
    # so AWS/Azure detection is reproducible — previously this cloned HEAD, so two
    # installs got different rules and the aws_sigma pin was cosmetic. SigmaHQ
    # publishes monthly tags (rYYYY-MM-01). Empty/missing pin -> default branch.
    local sigma_ref=$(read_config "['versions']['sigma_rules']")
    [[ "$sigma_ref" == "None" ]] && sigma_ref=""

    log_info "Setting up SIGMA detection rules for Azure automation..."
    [[ -n "$sigma_ref" ]] && log_info "  Pinned SIGMA release: $sigma_ref"

    # Stamp file records which ref is ACTUALLY checked out on disk — a shallow
    # `--branch <tag>` clone doesn't reliably leave a queryable local tag ref
    # to compare against later, so this is the source of truth for "is the
    # clone already at the currently-pinned version". Without this, bumping
    # `versions.sigma_rules` in config.yaml on an install/box that already had
    # SOME clone (from an earlier pin, or an earlier ad-hoc run) was silently
    # ignored forever — the old "already installed, rule_count > 10" check
    # short-circuited before ever looking at whether the pin had changed.
    local stamp_file="$sigma_dir/.sigma_pinned_ref"
    local current_stamp=""
    [[ -f "$stamp_file" ]] && current_stamp=$(cat "$stamp_file" 2>/dev/null)

    # Check if already exists, valid, AND at the currently-pinned ref
    if [[ -d "$sigma_dir/rules/cloud/azure" && "$current_stamp" == "$sigma_ref" ]]; then
        local rule_count=$(find "$sigma_dir/rules/cloud/azure" -name "*.yml" | wc -l)
        if [[ $rule_count -gt 10 ]]; then
            log_info "SIGMA rules already installed at pinned ref '$sigma_ref': $rule_count Azure rules found"
            return 0
        fi
    fi

    # Clone or update SIGMA rules
    if [[ -d "$sigma_dir/.git" ]]; then
        log_info "Updating existing SIGMA rules..."
        cd "$sigma_dir"
        if [[ -n "$sigma_ref" ]]; then
            # Fetch + checkout the pinned tag (shallow). Falls through to the
            # existing tree on failure so a bad pin never wipes working rules.
            if git fetch --depth 1 origin "refs/tags/${sigma_ref}:refs/tags/${sigma_ref}" 2>> "$LOG_FILE" \
                    && git checkout -f "$sigma_ref" 2>> "$LOG_FILE"; then
                echo "$sigma_ref" > "$stamp_file"
            else
                log_warn "  Pinned tag $sigma_ref unavailable — keeping existing checkout ($current_stamp)"
            fi
        else
            git pull --depth 1 2>> "$LOG_FILE" && rm -f "$stamp_file" || true
        fi
        cd - > /dev/null
    else
        log_info "Cloning SIGMA rules repository..."
        rm -rf "$sigma_dir" 2>/dev/null || true
        # --branch accepts a tag; pinned clone is shallow to that release. Fall
        # back to a default-branch clone if the pinned tag can't be fetched.
        if [[ -n "$sigma_ref" ]] && git clone --depth 1 --branch "$sigma_ref" \
                https://github.com/SigmaHQ/sigma.git "$sigma_dir" 2>> "$LOG_FILE"; then
            echo "$sigma_ref" > "$stamp_file"
            log_success "SIGMA rules cloned at pinned release $sigma_ref"
        elif git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$sigma_dir" 2>> "$LOG_FILE"; then
            [[ -n "$sigma_ref" ]] && log_warn "  Pinned tag $sigma_ref unavailable — cloned default branch instead"
            log_success "SIGMA rules cloned successfully"
        else
            log_warn "Failed to clone SIGMA rules - Azure/AWS detection will have limited rules"
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


# Apply the AWS SIGMA rule pack the release package carried.
#
# MUST RUN AFTER download_sigma_rules(). That function does `rm -rf
# /opt/sigma-rules` before cloning, so a pack written any earlier — e.g. during
# image loading, which is where it arrives — is silently destroyed. install.sh
# stages it aside into data/tmp/rule-packs/ precisely so it can be applied here
# instead.
#
# The rule pack is a plain data tar bundled under the package's images/ dir; it
# is NOT a docker image and must never be `docker load`ed (see
# _tar_is_docker_image in install.sh). Before this existed, install.sh had no
# route for it at all: an offline install with aws_sigma enabled came up with
# zero AWS detection rules, and the only symptom was a spurious
# "Could not load cloudtrail-<v>.tar" warning.
#
# Deliberately extracts on the HOST rather than through a one-shot container
# the way services/upgrade/aws.py:upgrade_aws_offline does. That indirection
# exists only because the backend runs INSIDE a container and cannot write the
# host's /opt/sigma-rules directly. install.sh is already root on the host, so
# the container round-trip would buy nothing. Do not "fix" this back.
install_bundled_rule_packs() {
    local staged_dir="${SCRIPT_DIR}/data/tmp/rule-packs"
    [[ -d "$staged_dir" ]] || return 0

    local pack applied=0 found=0
    # Both spellings: aws_sigma-<v>.tar is what the packager writes now,
    # cloudtrail-<v>.tar is what every package built before the rename carries.
    for pack in "$staged_dir"/aws_sigma-*.tar "$staged_dir"/cloudtrail-*.tar; do
        [[ -f "$pack" ]] || continue
        found=$((found + 1))
        local ver="$(basename "$pack")"
        ver="${ver#aws_sigma-}"; ver="${ver#cloudtrail-}"; ver="${ver%.tar}"

        local aws_enabled; aws_enabled=$(read_config "['modules']['aws_sigma']['enabled']")
        if ! is_enabled "$aws_enabled"; then
            log_info "  AWS SIGMA rule pack ${ver} is in the package but aws_sigma is disabled — not installed"
            record_install_note "Bundled AWS SIGMA rule pack ${ver} was not installed (modules.aws_sigma.enabled is false). Enable it and re-run install.sh to apply it — no internet needed."
            continue
        fi

        local pinned; pinned=$(read_config "['versions']['aws_sigma']")
        if [[ -n "$pinned" && "$pinned" != "None" && "$pinned" != "$ver" ]]; then
            log_warn "  Bundled AWS SIGMA rule pack is ${ver} but config.yaml pins ${pinned}"
        fi

        local dest="/opt/sigma-rules/rules/cloud/aws"
        mkdir -p "$dest"
        if tar xf "$pack" -C "$dest" 2>>"$LOG_FILE"; then
            local n; n=$(find "$dest" \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | wc -l)
            log_success "  AWS SIGMA rule pack ${ver} installed (${n} rules)"
            applied=$((applied + 1))
        else
            log_error "  Could not extract the bundled AWS SIGMA rule pack ($(basename "$pack"))"
            log_error "  AWS CloudTrail detection will run with no rules."
        fi
    done

    (( found == 0 )) && return 0
    (( applied > 0 )) && rm -rf "$staged_dir" 2>/dev/null || true
    return 0
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

    if docker image inspect "$o365rc_image" > /dev/null 2>&1; then
        log_info "DFIR-O365RC image already present"
        return 0
    fi

    # No release asset ships this image -- the index lists nine modules and
    # o365rc is not one of them -- so on an air-gapped box the pull below is a
    # guaranteed reach for Docker Hub. Every other pre-pull in this file guards
    # on INTACT_FROM_PACKAGE / INTACT_AIRGAP; this one did not, which made
    # "supported offline install" quietly untrue the moment an operator
    # enabled o365rc. Fail visibly and keep going: the module is optional and
    # the rest of the platform is unaffected.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_warn "DFIR-O365RC is enabled but its image is not in the release package,"
        log_warn "  and this is an offline install — skipping the registry pull."
        log_warn "  Unified Audit Log collection will be unavailable until this box can"
        log_warn "  reach a registry, or until ${o365rc_image} is loaded by hand:"
        log_warn "    docker load -i <o365rc-image>.tar"
        return 0
    fi

    log_info "Pulling DFIR-O365RC image (${o365rc_image}, Unified Audit Log collection)..."

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



pull_velociraptor_base_image() {
    # Base images exist ONLY to feed `docker compose build`. When the release
    # package supplied the images there is no build (run_docker_compose skips
    # it), so pulling a base layer is pure waste online -- and offline it is a
    # guaranteed failure that logs an alarming error for something the install
    # does not need. Skip before either happens.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "  Base image not needed — images came from the release package"
        return 0
    fi

    # Velociraptor's Dockerfile builds FROM ubuntu:22.04. Pre-pulling the base
    # image on the host with retry keeps a transient Docker Hub DNS hiccup at
    # "compose build" time from killing the whole module install.
    local velo_enabled
    velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if ! is_enabled "$velo_enabled"; then
        return 0
    fi

    local image="ubuntu:22.04"
    if docker image inspect "$image" > /dev/null 2>&1; then
        log_info "  $image already exists"
        return 0
    fi

    log_info "Pulling Ubuntu base image for Velociraptor build..."

    if _pull_image_with_retry "$image"; then
        log_success "  $image pulled successfully"
    else
        log_warn "  Failed to pull $image after retries — Velociraptor build will likely fail"
        return 1
    fi
}

pull_backend_base_image() {
    # Base images exist ONLY to feed `docker compose build`. When the release
    # package supplied the images there is no build (run_docker_compose skips
    # it), so pulling a base layer is pure waste online -- and offline it is a
    # guaranteed failure that logs an alarming error for something the install
    # does not need. Skip before either happens.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "  Base image not needed — images came from the release package"
        return 0
    fi

    # The Backend Dockerfile builds FROM python:3.11-slim. Pre-pulling on the
    # host means the ~46 MB base image doesn't count against `docker compose
    # build`'s wall-clock timeout — important on slow-uplink customer VMs
    # where install_20260610_070534.log showed ~120 kB/s sustained, putting
    # the base image alone at ~4 min of the build budget.
    local image="python:3.11-slim"
    if docker image inspect "$image" > /dev/null 2>&1; then
        log_info "  $image already exists"
        return 0
    fi

    log_info "Pulling Python base image for Backend build..."

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

    # The package already loaded all four IRIS images, so pre-pulling is at
    # best a no-op and at worst four registry round-trips on a box that may
    # have no registry. The per-image `docker image inspect` below short
    # -circuits in practice, but this is the only runtime-image pre-pull
    # without the early return its siblings (backend / velociraptor / python
    # -alpine base images) all have -- so make it consistent and cheap.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "IRIS images came from the release package — skipping pre-pull"
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
    local pfx_pass_path="${cert_dir}/azure_cert.pfx.pass"
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

    # Random per-install passphrase protecting the PKCS#12 private key.
    # An empty PFX passphrase (the previous behavior) provides no
    # confidentiality at all for the embedded private key (CWE-522).
    # Written via `-passout file:` (not `pass:`) so the plaintext never
    # appears in this process's argv/ps output either.
    openssl rand -hex 32 > "$pfx_pass_path"
    chmod 600 "$pfx_pass_path"

    # Create PFX, encrypted with the random passphrase above
    openssl pkcs12 -export -out "$pfx_path" \
        -inkey /tmp/azure_key.pem -in /tmp/azure_cert.pem \
        -passout file:"$pfx_pass_path" 2>> "$LOG_FILE"
    chmod 600 "$pfx_path"

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
