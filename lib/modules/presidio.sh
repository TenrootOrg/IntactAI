#!/usr/bin/env bash
# lib/modules/presidio.sh — deploy the optional PII NER sidecar (modules/presidio).
#
# Like the backend, the image is BUILT AND TESTED by CI and shipped in the release
# package, so an air-gapped install LOADS it and never rebuilds (a rebuild would
# need PyPI + the spaCy model download — impossible offline, and it would replace
# a tested artifact with an untested one). A from-source install builds it.
#
# The sidecar is internal-only (no host port); the backend reaches it at
# http://intact_presidio:3000. It is OFF unless modules.presidio.enabled is true.

deploy_presidio() {
    local enabled
    enabled=$(read_config "['modules']['presidio']['enabled']")
    if ! is_enabled "$enabled"; then
        log_info "Presidio (PII NER sidecar): SKIPPED (presidio disabled in config)"
        return 0
    fi

    if is_module_installed intact_presidio; then
        log_info "Presidio: already installed + running (skipping)"
        return 0
    fi

    log_info "Starting Presidio (PII NER sidecar)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/presidio"
    cd "${SCRIPT_DIR}/modules/presidio" || { track_module_failure "Presidio"; return 1; }

    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        # Package install: the image must already be loaded. Read the tag from
        # the .env docker compose will interpolate, config.yaml as fallback.
        local env_file="${SCRIPT_DIR}/modules/presidio/.env"
        local tag
        tag="$(grep -E '^PRESIDIO_VERSION=' "$env_file" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
        [[ -z "$tag" ]] && tag="$(read_config "['versions']['presidio']")"
        local want="intact-presidio:${tag}"
        if docker image inspect "$want" >/dev/null 2>&1; then
            log_success "  Presidio image ${want} present (shipped by the release package) — not building"
        else
            local found=()
            mapfile -t found < <(docker images --format '{{.Repository}}:{{.Tag}}' \
                                 --filter reference='intact-presidio:*' 2>/dev/null | grep -v '<none>')
            if (( ${#found[@]} == 1 )); then
                log_warn "  ${want} not in the image store, but ${found[0]} is — retagging."
                docker tag "${found[0]}" "$want"
            else
                # The sidecar is OPTIONAL: a missing image should not fail the whole
                # install. Warn, skip, and leave masking.ner as a no-op in the backend.
                log_warn "  ${want} was not shipped by this release package; presidio images present: ${found[*]:-none}"
                log_warn "  Skipping the PII NER sidecar (backend masking.ner stays a no-op)."
                return 0
            fi
        fi
    else
        log_info "  Building Presidio Docker image (downloads the spaCy model — needs internet)..."
        if ! run_docker_compose "build" "Presidio"; then
            log_error "  Failed to build Presidio image"
            track_module_failure "Presidio"
            return 1
        fi
        log_success "  Presidio image built successfully"
    fi

    if ! run_compose_up_with_retry "Presidio"; then
        log_error "  Failed to start Presidio container"
        track_module_failure "Presidio"
        return 1
    fi
    log_success "  Presidio (PII NER sidecar) started"
    return 0
}
