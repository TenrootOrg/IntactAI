#!/bin/bash
# Intact.AI Platform Installer — Backend API module.

# ============================================================================
# Backend API Module
# ============================================================================

deploy_backend() {
    log_info "[7/8] Starting Backend API..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/backend"
    cd "${SCRIPT_DIR}/modules/backend"

    # Installing from a package means the backend image was BUILT AND TESTED
    # by CI and shipped in the asset. Rebuilding it here would need PyPI + apt
    # (impossible air-gapped) and would replace a tested artifact with an
    # untested local build under the same tag, so a missing image is a hard
    # failure rather than a silent rebuild.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        # Read the tag from modules/backend/.env — that is the file docker
        # compose itself interpolates ${BACKEND_VERSION} from, so this checks
        # for exactly the image compose is about to demand. (It is not a shell
        # variable here: update_env_files writes it to .env, it is never
        # exported.) config.yaml is the fallback for a pre-Wave-F .env.
        local be_env="${SCRIPT_DIR}/modules/backend/.env"
        local be_tag
        be_tag="$(grep -E '^BACKEND_VERSION=' "$be_env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
        [[ -z "$be_tag" ]] && be_tag="$(read_config "['versions']['backend']")"
        local want="intact-backend:${be_tag}"
        if docker image inspect "$want" >/dev/null 2>&1; then
            log_success "  Backend image ${want} present (shipped by the release package) — not building"
        else
            # The package's filename tag and config.yaml can legitimately
            # disagree; when exactly one backend image is present, that is
            # unambiguously the one the package shipped. Mirrors the retag
            # branch in services/upgrade/intact.py:ensure_backend_runtime_image.
            local found=()
            mapfile -t found < <(docker images --format '{{.Repository}}:{{.Tag}}' \
                                 --filter reference='intact-backend:*' 2>/dev/null | grep -v '<none>')
            if (( ${#found[@]} == 1 )); then
                log_warn "  ${want} is not in the image store, but ${found[0]} is — retagging."
                log_warn "  (config.yaml versions.backend and the shipped package disagree.)"
                docker tag "${found[0]}" "$want"
            else
                log_error "  ${want} was not shipped by the release package."
                log_error "  intact-backend images present: ${found[*]:-none}"
                log_error "  Refusing to rebuild the backend from source: that needs PyPI + apt"
                log_error "  (impossible air-gapped) and would replace the tested image with an"
                log_error "  untested local build under the same tag."
                track_module_failure "Backend API"
                return 1
            fi
        fi
    else
        log_info "  Building Backend Docker image..."
        if ! run_docker_compose "build" "Backend"; then
            log_error "  Failed to build Backend image"
            track_module_failure "Backend API"
            return 1
        fi
        log_success "  Backend image built successfully"
    fi

    # Start
    log_info "  Starting Backend container..."
    if ! run_compose_up_with_retry "Backend"; then
        log_error "  Failed to start Backend containers"
        track_module_failure "Backend API"
        return 1
    fi

    # Show container status
    show_container_status "intact_backend"

    # Wait for backend health endpoint
    log_info "  Waiting for Backend API health check (http://localhost:5001/api/health)..."
    local be_wait=0
    local be_max_wait=60
    local be_healthy=false
    while [[ $be_wait -lt $be_max_wait ]]; do
        if curl -sf --max-time 5 "http://localhost:5001/api/health" > /dev/null 2>&1; then
            log_success "  Backend API is healthy! (${be_wait}s)"
            be_healthy=true
            break
        fi
        sleep 5
        ((be_wait+=5))
        log_info "  Waiting for Backend API... (${be_wait}/${be_max_wait}s)"
    done

    if [[ "$be_healthy" != "true" ]]; then
        # Honest failure: the backend container started but its
        # /api/health endpoint never responded within 60s. Previously
        # this called `track_module_success "Backend API"` — a literal
        # falsehood that masked the failure and let install.sh print
        # "Installation Complete!" with exit 0 (see install_20260607
        # log). Switching to `track_module_failure` populates
        # FAILED_MODULES so the end-of-run summary in install.sh can
        # honestly report the install as failed and exit non-zero.
        log_error "  Backend API never responded to /api/health after 60s"
        capture_diagnostic_logs "Backend API (post-deploy timeout)" intact_backend
        track_module_failure "Backend API"
        return 1
    fi

    # ---- Bootstrap LLM model catalogs ----------------------------------
    # Persists each provider's model catalog to /app/data/<provider>_models.json
    # so the dashboard's model selector has results immediately on first
    # open. Best-effort: if a provider's API is unreachable (or the
    # operator hasn't configured an API key for that provider yet) the
    # bootstrap simply skips it and the on-demand fetch in the API
    # endpoint retries the next time Settings is opened. The maintenance
    # workflow refreshes all four catalogs later.
    #
    # Order matters: OpenRouter goes first because the three direct-
    # provider refreshes enrich their entries from the OpenRouter catalog.
    log_info "  Bootstrapping LLM model catalogs (best-effort)..."

    # IN-CONTAINER, not over HTTP.
    #
    # This used to POST to http://localhost:5001/api/maintenance/refresh-<x>-models
    # and every install reported:
    #
    #     [WARN] OpenRouter: deferred (no API key, network issue, or provider
    #                                  unreachable)
    #
    # All three of those are wrong. The catalog endpoint is public (no key), the
    # network is fine, and the provider is reachable. The call was simply
    # getting a 401.
    #
    # WHY: the API auth gate exempts loopback (services/auth_service.py,
    # LOOPBACK_ADDRS = {127.0.0.1, ::1}) on the reasoning that a request from
    # the box itself is trusted. But the backend port is published as
    # `127.0.0.1:5001:5001`, and Docker's proxy rewrites the source address, so
    # what actually arrives inside the container is the bridge gateway:
    #
    #     172.18.0.1 - - "POST /api/maintenance/refresh-openrouter-models" 401
    #
    # remote_addr is never 127.0.0.1 for a host-originated call, so that
    # exemption cannot fire and the route is unreachable from install.sh. The
    # bootstrap then read any non-success as "no models" and warned about an API
    # key that this catalog does not even use.
    #
    # Calling the underlying function inside the container sidesteps HTTP
    # entirely -- same approach as every other install-time backend operation
    # here (see the `docker exec intact_backend python3` calls above, and
    # scripts/run_maintenance.py). Deliberately NOT fixed by adding the route to
    # EXEMPT_PATHS: that would make it callable unauthenticated through nginx
    # from off-box too, which is a real widening of the auth surface to work
    # around a local plumbing detail.
    _bootstrap_one_catalog() {
        local label="$1"
        local module="$2"
        local count
        count=$(docker exec intact_backend python3 -c "
import json, sys, io, contextlib
buf = io.StringIO()
try:
    # The catalog modules log to stdout on import + refresh; capture it so only
    # the count reaches the shell.
    with contextlib.redirect_stdout(buf):
        from services.llm_catalogs import ${module} as catalog
        result = catalog.refresh_catalog()
    print(result.get('model_count', 0) if result.get('success') else 0)
except Exception:
    print(0)
" 2>/dev/null | tail -1)
        if [[ "${count:-0}" -gt 0 ]]; then
            log_success "    ${label}: ${count} models cached"
        else
            # Genuinely could not fetch: no network from the container, upstream
            # down, or a provider that does need a key and has none configured.
            # A note, not a warning -- the catalog refreshes on demand the first
            # time Settings is opened, and the maintenance workflow retries it.
            log_info "    ${label}: not cached yet (will fetch on demand)"
            record_install_note "${label} model catalog was not seeded at install. It refreshes automatically the first time Settings → LLM is opened, or via System Maintenance."
        fi
    }

    # OpenRouter is the only catalog seeded at install — direct-provider
    # paths (Anthropic / OpenAI / Gemini) are gated behind the UI and
    # remain unused by default. Bootstrapping them produced "deferred"
    # warnings on every install since no API keys were configured.
    _bootstrap_one_catalog "OpenRouter" "openrouter"

    track_module_success "Backend API"
}
