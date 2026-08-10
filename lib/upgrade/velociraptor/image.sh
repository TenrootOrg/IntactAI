#!/bin/bash
# Intact.AI upgrade — Velociraptor's env pin, client binaries, and the
# server image (present -> load the tar -> build).

# VELOCIRAPTOR_TAG is the major.minor the Dockerfile's download URL uses;
# VELOCIRAPTOR_VERSION is the full pin.
_velo_stamp_env() {
    local envf="$1" target="$2"
    local tag; tag="$(sed 's/^\([0-9]*\.[0-9]*\).*/\1/' <<< "$target")"
    _u_stamp "$envf" "VELOCIRAPTOR_VERSION=${target}" "VELOCIRAPTOR_TAG=${tag}" || return 1
    return 0
}

# The Dockerfile COPYs four client binaries unconditionally, so all four paths
# must exist or the build fails on a missing COPY source. Only linux is
# genuinely required -- it is the server binary too. mac and windows get
# zero-byte placeholders when unavailable, which is what the Python did and
# for the same reason.
_velo_stage_binaries() {
    local target="$1" dir; dir="$(_VELO_DIR)"
    local pkgbin="${UPKG_DIR}/binaries"
    mkdir -p "${dir}/clients/linux" "${dir}/clients/mac" "${dir}/clients/windows"

    local linux_dst="${dir}/clients/linux/velociraptor"
    if [[ -d "$pkgbin" ]]; then
        local f
        f="$(find "$pkgbin" -maxdepth 2 -name "*linux-amd64*" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && { cp -f "$f" "$linux_dst"; log_info "  staged the linux binary from the package"; }
        f="$(find "$pkgbin" -maxdepth 2 -name "*darwin*" -o -name "*mac*" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/mac/velociraptor_client"
        f="$(find "$pkgbin" -maxdepth 2 -name "*windows-amd64.exe" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/windows/velociraptor_client.exe"
        f="$(find "$pkgbin" -maxdepth 2 -name "*.msi" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/windows/velociraptor_client.msi"
    fi

    if [[ ! -s "$linux_dst" ]]; then
        # If the image already exists we never build, so a missing binary is
        # harmless; only fail when a build is actually going to happen.
        if _u_image_present "velociraptor-server:${target}"; then
            log_info "  no linux binary staged, but velociraptor-server:${target} already exists"
        else
            log_error "  no linux velociraptor binary in the package and no prebuilt image"
            return 1
        fi
    fi

    # chmod 755 explicitly, not chmod +x: umask can mask the group/other bits
    # and the container runs as a different uid than the one staging these.
    [[ -s "$linux_dst" ]] && chmod 755 "$linux_dst"
    local p
    for p in "${dir}/clients/mac/velociraptor_client" \
             "${dir}/clients/windows/velociraptor_client.exe" \
             "${dir}/clients/windows/velociraptor_client.msi"; do
        [[ -e "$p" ]] || { : > "$p"; log_info "  placeholder for $(basename "$p") (not in this package)"; }
    done
    return 0
}

# Present -> load the tar -> build. Building is last and loudly flagged: it
# runs apt-get and cannot work air-gapped.
_velo_resolve_image() {
    local target="$1" dir; dir="$(_VELO_DIR)"
    local ref="velociraptor-server:${target}"

    _u_image_present "$ref" && { log_info "  ${ref} already present"; return 0; }

    local tar="${UPKG_DIR}/images/velociraptor-${target}.tar"
    if [[ -f "$tar" ]]; then
        log_info "  loading ${ref} from the package"
        "${DOCKER_BIN:-docker}" load -i "$tar" >>"${LOG_FILE:-/dev/null}" 2>&1 \
            && _u_image_present "$ref" && return 0
        log_warn "  the bundled tar did not yield ${ref}"
    fi

    if [[ "${INTACT_UPGRADE_OFFLINE:-0}" == "1" ]]; then
        log_error "  ${ref} is absent and building it needs network access"
        return 1
    fi
    log_warn "  ${ref} is not present and the package does not carry it — building."
    log_warn "  This runs apt-get and WILL fail on an air-gapped host."
    ( cd "$dir" && "${DOCKER_BIN:-docker}" compose build >>"${LOG_FILE:-/dev/null}" 2>&1 ) || {
        log_error "  velociraptor image build failed"; return 1; }
    _u_image_present "$ref"
}
