#!/bin/bash
# Intact.AI Platform Installer - Module Deployment Functions
# Service startup and module management

# ============================================================================
# Security Credentials Generation
# ============================================================================

generate_iris_secrets() {
    log_info "Generating IRIS secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/iris/secrets"
    mkdir -p "$secrets_dir"

    local secrets_created=false

    # IRIS_ADM_PASSWORD should come from config.yaml, not be random
    if [[ ! -f "$secrets_dir/IRIS_ADM_PASSWORD" ]] || [[ ! -s "$secrets_dir/IRIS_ADM_PASSWORD" ]]; then
        local iris_password=$(read_config "['modules']['iris']['password']")
        if [[ -n "$iris_password" && "$iris_password" != "None" ]]; then
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_info "  Created IRIS_ADM_PASSWORD from config.yaml"
        else
            # Fallback to default if not in config
            echo -n "123123" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_warn "  Created IRIS_ADM_PASSWORD with default (set in config.yaml)"
        fi
        secrets_created=true
    else
        log_info "  IRIS_ADM_PASSWORD exists, skipping"
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

    # Ensure all secrets are flushed to disk before containers try to read them
    if [[ "$secrets_created" == "true" ]]; then
        sync
        sleep 1
    fi

    # Verify all secrets exist and have content
    local all_ok=true
    for secret in IRIS_ADM_PASSWORD IRIS_SECRET_KEY IRIS_SECURITY_PASSWORD_SALT POSTGRES_ADMIN_PASSWORD POSTGRES_PASSWORD; do
        if [[ ! -s "$secrets_dir/$secret" ]]; then
            log_error "  Secret file missing or empty: $secret"
            all_ok=false
        fi
    done

    if [[ "$all_ok" == "true" ]]; then
        log_success "IRIS secrets ready"
    else
        log_error "IRIS secrets generation failed!"
        return 1
    fi
}

generate_portainer_secrets() {
    # Portainer CE locks itself after a 5-minute "initial setup" window if no
    # admin account is created. Seed the admin account via --admin-password-file
    # so the very first container boot skips the interactive setup entirely
    # and the install works unattended.
    log_info "Generating Portainer secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/portainer/secrets"
    mkdir -p "$secrets_dir"

    if [[ ! -s "$secrets_dir/admin_password" ]]; then
        local portainer_password
        portainer_password=$(read_config "['modules']['portainer']['password']")
        # Portainer enforces a 12-character minimum even when the password is
        # seeded via --admin-password-file. Short values silently cause the
        # admin user to never be created and the UI falls back to the
        # timed-out "initial setup" state — exactly what we're trying to avoid.
        if [[ -z "$portainer_password" || "$portainer_password" == "None" || ${#portainer_password} -lt 12 ]]; then
            log_warn "  Portainer password missing or < 12 chars in config.yaml; using built-in default '1234qwer!@#\$'"
            log_warn "  Change it from the Portainer UI after first login (Settings -> Users)"
            portainer_password='1234qwer!@#$'
        fi
        printf '%s' "$portainer_password" > "$secrets_dir/admin_password"
        chmod 600 "$secrets_dir/admin_password"
        sync
        log_info "  Created Portainer admin password file"
    else
        log_info "  Portainer admin password file exists, skipping"
    fi

    log_success "Portainer secrets ready"
}

generate_certificates() {
    log_info "Generating SSL certificates..."
    local domain="${DOMAIN:-localhost}"

    # Nginx SSL
    local nginx_ssl="${SCRIPT_DIR}/modules/nginx/ssl"
    mkdir -p "$nginx_ssl"
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" ]]; then
        log_info "  Generating Nginx SSL certificate for domain: $domain"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$nginx_ssl/nginx-cert.key" \
            -out "$nginx_ssl/nginx-cert.crt" \
            -subj "/CN=$domain/O=Intact.AI/C=US" 2>/dev/null
        log_success "  Generated Nginx SSL certificate"
    else
        log_info "  Nginx SSL certificate exists, skipping"
    fi

    # IRIS Root CA
    local iris_ca="${SCRIPT_DIR}/modules/iris/config/certificates/rootCA"
    mkdir -p "$iris_ca"
    if [[ ! -f "$iris_ca/irisRootCACert.pem" ]]; then
        log_info "  Generating IRIS Root CA..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$iris_ca/irisRootCAKey.pem" \
            -out "$iris_ca/irisRootCACert.pem" \
            -subj "/CN=IRIS Root CA/O=Intact.AI/C=US" 2>/dev/null
        log_success "  Generated IRIS Root CA"
    else
        log_info "  IRIS Root CA exists, skipping"
    fi

    # IRIS Web Cert — shared with Nginx (same cert, copied to IRIS path)
    local iris_web="${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates"
    mkdir -p "$iris_web"
    if [[ -f "$nginx_ssl/nginx-cert.crt" ]]; then
        log_info "  Copying shared TLS certificate to IRIS..."
        cp "$nginx_ssl/nginx-cert.crt" "$iris_web/iris_dev_cert.pem"
        cp "$nginx_ssl/nginx-cert.key" "$iris_web/iris_dev_key.pem"
        chmod 644 "$iris_web"/*.pem
        log_success "  IRIS web certificate synced with Nginx certificate"
    fi

    # Ensure IRIS certificates are readable (fix permissions if needed)
    if [[ -d "$iris_web" ]]; then
        chmod 644 "$iris_web"/*.pem 2>/dev/null || true
    fi
}

# ============================================================================
# Helper: Show docker compose output with logging
# ============================================================================

run_docker_compose() {
    local action="$1"
    local module_name="$2"
    # Allow callers to override the build timeout per module (Backend ships
    # with 900s default; Velociraptor's smaller surface gets 600s passed in).
    local build_timeout="${3:-900}"

    log_info "  Running: docker compose $action"

    # Run docker compose with cleaner output (filter out noisy progress)
    if [[ "$action" == "build" ]]; then
        # Wrap with heartbeat + hard timeout. Catches the silent-stop failure
        # mode where a build hangs with no log output and the operator can't
        # tell whether the script froze or is making progress.
        local cwd="$PWD"
        run_with_heartbeat "${module_name} image build" "$build_timeout" \
            bash -c '
                cd "$1" || exit 2
                docker compose build 2>&1 | tee -a "$2" | while IFS= read -r line; do
                    if echo "$line" | grep -qE "^(Step [0-9]+|Successfully|Building|CACHED|\[.*/.*\])"; then
                        echo "    $line"
                    fi
                done
                exit "${PIPESTATUS[0]}"
            ' _ "$cwd" "$LOG_FILE"
        return $?
    else
        # For 'up -d': Filter repetitive download/extract progress, show key events
        # Keep: Image pulling, Container creating/starting, errors/warnings
        # Filter: "abc123 Downloading 4.194MB", "abc123 Extracting", "Download complete", etc.
        # Wrap in heartbeat too — Velociraptor's `up -d` triggers a local
        # build (image not on registry), and IRIS first-time DB init can
        # take 5+ min. Without heartbeat, those minutes look like a hang.
        local up_cwd="$PWD"
        run_with_heartbeat "${module_name} compose up" "$build_timeout" \
            bash -c '
                cd "$1" || exit 2
                docker compose up -d 2>&1 | tee -a "$2" | \
                    grep -vE "^\s*[0-9a-f]{12} (Downloading|Extracting|Waiting|Download complete|Pull complete|Pulling fs layer) " | \
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            echo "    $line"
                        fi
                    done
                exit "${PIPESTATUS[0]}"
            ' _ "$up_cwd" "$LOG_FILE"
        return $?
    fi
}

# Pull a module's compose images with retry/backoff, separated from `up -d`.
# Pulls are by far the most common transient-failure point on real networks
# (registry rate-limits, IPv6 race on IPv4-only hosts, brief CDN hiccups).
# Doing the pull as a discrete, retryable step means a single bad DNS roll or
# 503 doesn't doom the whole module deploy. Subsequent `up -d` runs from
# run_docker_compose() find images locally and don't repeat the network risk.
# Same exponential-backoff cadence as _pull_image_with_retry() in docker.sh.
pull_compose_with_retry() {
    local module_name="$1"
    local max_attempts=3
    local delays=(5 15 45)
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        log_info "  Pulling images for ${module_name} (attempt ${attempt}/${max_attempts})..."
        if docker compose pull 2>&1 | tee -a "$LOG_FILE" | \
                grep -vE "^\s*[0-9a-f]{12} (Downloading|Extracting|Waiting|Download complete|Pull complete|Pulling fs layer) " >/dev/null; then
            # PIPESTATUS[0] is docker compose pull's exit code
            if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
                return 0
            fi
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            local delay=${delays[$((attempt - 1))]}
            log_warn "  ${module_name} pull attempt ${attempt} failed; retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done

    log_error "  ${module_name} pull failed after ${max_attempts} attempts"
    return 1
}

# ============================================================================
# Helper: Show container status
# ============================================================================

show_container_status() {
    local container_name="$1"
    local status=$(docker ps --filter "name=$container_name" --format "{{.Status}}" 2>/dev/null | head -1)
    if [[ -n "$status" ]]; then
        log_info "  Container $container_name: $status"
    else
        log_warn "  Container $container_name: Not found"
    fi
}

# ============================================================================
# ELK Stack Module
# ============================================================================

deploy_elk() {
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if ! is_enabled "$elk_enabled"; then
        log_info "[1/7] ELK Stack: SKIPPED (disabled in config)"
        return
    fi

    log_info "[1/7] Starting ELK Stack..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/elk"
    cd "${SCRIPT_DIR}/modules/elk"

    # Show what images will be used
    local elk_version=$(read_config "['versions']['elk']")
    log_info "  Elasticsearch version: ${elk_version:-8.x}"

    if ! pull_compose_with_retry "ELK Stack"; then
        track_module_failure "ELK Stack"
        return 1
    fi
    if ! run_docker_compose "up -d" "ELK"; then
        log_error "  Docker compose failed!"
        track_module_failure "ELK Stack"
        return 1
    fi

    # Show container status
    show_container_status "intact_elasticsearch"
    show_container_status "intact_kibana"

    # Wait for Elasticsearch to be ready
    log_info "  Waiting for Elasticsearch API (http://localhost:9200)..."
    local es_wait=0
    local es_max_wait=90
    while [[ $es_wait -lt $es_max_wait ]]; do
        if curl -sf --max-time 5 "http://localhost:9200/_cluster/health" > /dev/null 2>&1; then
            log_success "  Elasticsearch is ready! (${es_wait}s)"
            track_module_success "ELK Stack"
            return 0
        fi
        sleep 5
        ((es_wait+=5))
        log_info "  Waiting for Elasticsearch... (${es_wait}/${es_max_wait}s)"
    done

    log_error "  Elasticsearch failed to become ready after ${es_max_wait}s"
    track_module_failure "ELK Stack"
    return 1
}

# ============================================================================
# TimeSketch Module
# ============================================================================

deploy_timesketch() {
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if ! is_enabled "$ts_enabled"; then
        log_info "[2/7] TimeSketch: SKIPPED (disabled in config)"
        return
    fi

    log_info "[2/7] Starting TimeSketch..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/timesketch"
    cd "${SCRIPT_DIR}/modules/timesketch"

    local ts_version=$(read_config "['versions']['timesketch']")
    log_info "  TimeSketch version: ${ts_version:-latest}"

    if ! pull_compose_with_retry "TimeSketch"; then
        track_module_failure "TimeSketch"
        return 1
    fi
    if ! run_docker_compose "up -d" "TimeSketch"; then
        log_error "  Docker compose failed!"
        track_module_failure "TimeSketch"
        return 1
    fi

    # Show container status
    show_container_status "intact_timesketch_web"
    show_container_status "intact_timesketch_worker"
    show_container_status "intact_timesketch_postgres"
    show_container_status "intact_timesketch_redis"
    show_container_status "intact_timesketch_opensearch"

    # Wait for TimeSketch web container to be ready
    log_info "  Waiting for TimeSketch container..."
    if ! wait_for_container "intact_timesketch_web" 60; then
        log_error "  TimeSketch web container failed to start"
        track_module_failure "TimeSketch"
        return 1
    fi

    # Wait for TimeSketch API to be ready (check from host, not container - no curl in container)
    log_info "  Waiting for TimeSketch API (http://localhost:5000)..."
    local ts_ready=false
    local ts_wait=0
    local ts_max_wait=90

    while [[ $ts_wait -lt $ts_max_wait ]]; do
        local http_code=$(curl -s --max-time 5 "http://localhost:5000/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            ts_ready=true
            log_success "  TimeSketch API is ready! (HTTP $http_code, ${ts_wait}s)"
            break
        fi
        sleep 5
        ((ts_wait+=5))
        log_info "  Waiting for TimeSketch API... (${ts_wait}/${ts_max_wait}s)"
    done

    if [[ "$ts_ready" != "true" ]]; then
        log_warn "  TimeSketch API not responding after ${ts_max_wait}s"
        log_info "  Check logs: docker logs intact_timesketch_web"
    fi

    # Create user
    local ts_user=$(read_config "['modules']['timesketch']['id']")
    local ts_pass=$(read_config "['modules']['timesketch']['password']")

    log_info "  Creating TimeSketch user: ${ts_user}"

    # Try user creation with retries
    local ts_user_created=false
    local ts_retry=0
    local ts_max_retry=5

    while [[ $ts_retry -lt $ts_max_retry ]]; do
        local ts_error=$(docker exec intact_timesketch_web tsctl create-user "${ts_user}" --password "${ts_pass}" 2>&1)
        local ts_exit_code=$?

        if [[ $ts_exit_code -eq 0 ]]; then
            ts_user_created=true
            break
        fi

        if echo "$ts_error" | grep -qi "already exists"; then
            log_info "  TimeSketch user '${ts_user}' already exists"
            # Enable user in case it was disabled
            docker exec intact_timesketch_web tsctl enable-user "${ts_user}" >/dev/null 2>&1 || true
            ts_user_created=true
            break
        fi

        ((ts_retry++))
        if [[ $ts_retry -lt $ts_max_retry ]]; then
            log_info "  Retrying user creation... (attempt ${ts_retry}/${ts_max_retry})"
            sleep 10
        fi
    done

    if [[ "$ts_user_created" == "true" ]]; then
        # Ensure user is enabled
        docker exec intact_timesketch_web tsctl enable-user "${ts_user}" >/dev/null 2>&1 || true
        log_success "  TimeSketch user '${ts_user}' ready"

        # Enable DFIQ after successful deployment (requires db migration for schema)
        log_info "  Enabling DFIQ..."
        docker exec intact_timesketch_web tsctl db upgrade 2>/dev/null || true
        sed -i 's/DFIQ_ENABLED = False/DFIQ_ENABLED = True/' "${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        log_success "  DFIQ enabled"

        # Raise OpenSearch / import timeouts so large .plaso imports don't false-fail
        # (upstream defaults are 10s and 180s — too aggressive under disk/memory pressure)
        log_info "  Raising Timesketch OpenSearch/import timeouts..."
        local ts_conf="${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        sed -i 's/^OPENSEARCH_TIMEOUT = 10$/OPENSEARCH_TIMEOUT = 300/'                    "$ts_conf"
        sed -i 's/^OPENSEARCH_FLUSH_INTERVAL = 5000$/OPENSEARCH_FLUSH_INTERVAL = 10000/'  "$ts_conf"
        sed -i 's/^OPENSEARCH_INDEX_WAIT_TIMEOUT = 10$/OPENSEARCH_INDEX_WAIT_TIMEOUT = 300/' "$ts_conf"
        sed -i 's/^TIMEOUT_FOR_EVENT_IMPORT = 180$/TIMEOUT_FOR_EVENT_IMPORT = 600/'       "$ts_conf"
        log_success "  Timeouts raised (OpenSearch 10->300s, event import 180->600s)"

        # NL2Q defaults to vertexai with an empty project_id, which makes the
        # "AI generated queries" toggle in the sketch settings sit greyed-out
        # as "requires LLM provider". Swap it to aistudio and reuse the Gemini
        # api_key already wired into the llm_summarize block so it works on a
        # fresh install without manual editing. Idempotent — re-running on an
        # already-converted block is a no-op.
        log_info "  Wiring Timesketch nl2q to Gemini AI Studio..."
        local gemini_key
        gemini_key=$(awk "/'llm_summarize':/,/},/" "$ts_conf" \
            | grep -oE "'api_key': '[^']+'" \
            | head -1 \
            | sed -E "s/'api_key': '([^']+)'/\1/")
        if [[ -n "$gemini_key" ]]; then
            sed -i "/    'nl2q': {/,/    },/ {
                s/'vertexai':/'aistudio':/
                s|'project_id': ''|'api_key': '$gemini_key'|
            }" "$ts_conf"
            log_success "  nl2q wired to aistudio"
        else
            log_warning "  Could not read Gemini api_key from llm_summarize; nl2q left as-is"
        fi

        # Restart the Timesketch containers that bind-mount timesketch.conf so both
        # DFIQ and the timeout bumps take effect. Worker + web_legacy matter too —
        # without this, indexing runs with the old timeouts until next reboot.
        docker restart intact_timesketch_web intact_timesketch_worker intact_timesketch_web_legacy >/dev/null 2>&1

        track_module_success "TimeSketch"
    else
        log_error "  TimeSketch user creation failed: ${ts_error}"
        track_module_failure "TimeSketch"
        return 1
    fi
}

# ============================================================================
# Velociraptor Module
# ============================================================================

deploy_velociraptor() {
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if ! is_enabled "$velo_enabled"; then
        log_info "[3/7] Velociraptor: SKIPPED (disabled in config)"
        return
    fi

    log_info "[3/7] Starting Velociraptor..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/velociraptor"
    cd "${SCRIPT_DIR}/modules/velociraptor"

    local velo_version=$(read_config "['versions']['velociraptor']")
    log_info "  Velociraptor version: ${velo_version:-latest}"

    if ! run_docker_compose "up -d" "Velociraptor"; then
        log_error "  Docker compose failed!"
        track_module_failure "Velociraptor"
        return 1
    fi

    # Show container status
    show_container_status "intact_velociraptor"

    # Wait for container to be ready
    log_info "  Waiting for Velociraptor container..."
    if ! wait_for_container "intact_velociraptor" 60; then
        log_warn "  Velociraptor container may not be fully ready"
    fi

    # Wait for Velociraptor configuration to be generated
    log_info "  Waiting for Velociraptor configuration..."
    local velo_config_wait=0
    while [[ $velo_config_wait -lt 90 ]]; do
        if docker exec intact_velociraptor test -f /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  Velociraptor configuration ready (${velo_config_wait}s)"
            break
        fi
        sleep 5
        ((velo_config_wait+=5))
    done
    if [[ $velo_config_wait -ge 90 ]]; then
        log_warn "  Velociraptor configuration not ready after 90s"
    fi

    # Generate client installers
    log_info "  Generating pre-configured client installers..."
    if [[ -f "${SCRIPT_DIR}/scripts/generate_clients.sh" ]]; then
        bash "${SCRIPT_DIR}/scripts/generate_clients.sh" 2>&1 | tee -a "$LOG_FILE"
        if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
            log_warn "  Client installer generation had issues"
        fi
    else
        log_warn "  Client installer script not found, skipping"
    fi

    track_module_success "Velociraptor"
}

# ============================================================================
# IRIS Module
# ============================================================================

deploy_iris() {
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "[4/7] IRIS: SKIPPED (disabled in config)"
        return
    fi

    log_info "[4/7] Starting IRIS (Incident Response Platform)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/iris"
    cd "${SCRIPT_DIR}/modules/iris"

    local iris_version=$(read_config "['versions']['iris']")
    log_info "  IRIS version: ${iris_version:-latest}"

    # Check if this is a fresh install (no existing database volume)
    local is_fresh_install=false
    if ! docker volume inspect modules_iris_db_data > /dev/null 2>&1 && \
       ! docker volume inspect iris_iris_db_data > /dev/null 2>&1; then
        is_fresh_install=true
        log_info "  Fresh IRIS installation detected (first-time setup will take longer)"
    fi

    if ! pull_compose_with_retry "IRIS"; then
        track_module_failure "IRIS"
        return 1
    fi
    if ! run_docker_compose "up -d" "IRIS"; then
        log_error "  Docker compose failed!"
        track_module_failure "IRIS"
        return 1
    fi

    # Show container status (including nginx which serves port 8443)
    show_container_status "intact_iris_db"
    show_container_status "intact_iris_rabbitmq"
    show_container_status "intact_iris_app"
    show_container_status "intact_iris_worker"
    show_container_status "intact_iris_nginx"

    # Wait for database first
    log_info "  Waiting for IRIS database (PostgreSQL)..."
    local db_wait=0
    local db_max_wait=90
    while [[ $db_wait -lt $db_max_wait ]]; do
        if docker exec intact_iris_db pg_isready -U postgres > /dev/null 2>&1; then
            log_success "  IRIS database is ready (${db_wait}s)"
            break
        fi
        sleep 5
        ((db_wait+=5))
        log_info "  Waiting for database... (${db_wait}/${db_max_wait}s)"
    done

    # Wait for RabbitMQ
    log_info "  Waiting for IRIS message queue (RabbitMQ)..."
    local mq_wait=0
    local mq_max_wait=60
    while [[ $mq_wait -lt $mq_max_wait ]]; do
        if docker exec intact_iris_rabbitmq rabbitmqctl status > /dev/null 2>&1; then
            log_success "  RabbitMQ is ready (${mq_wait}s)"
            break
        fi
        sleep 5
        ((mq_wait+=5))
        log_info "  Waiting for RabbitMQ... (${mq_wait}/${mq_max_wait}s)"
    done

    # Wait for IRIS app container
    log_info "  Waiting for IRIS app container..."
    if ! wait_for_container "intact_iris_app" 90; then
        log_warn "  IRIS app container not ready after 90s"
    fi

    # Wait for IRIS API to be accessible (HTTPS on port 8443)
    # Fresh installs need more time for database schema creation and seeding
    local iris_max_wait=180
    if [[ "$is_fresh_install" == "true" ]]; then
        iris_max_wait=300
        log_info "  Waiting for IRIS web interface (fresh install, up to 5 minutes)..."
    else
        log_info "  Waiting for IRIS web interface (https://localhost:8443)..."
    fi

    local iris_wait=0
    local iris_ready=false
    local last_status=""

    while [[ $iris_wait -lt $iris_max_wait ]]; do
        # Check for any HTTP response (IRIS returns 302 redirect when ready)
        local http_code=$(curl -sk --max-time 5 "https://localhost:8443/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            iris_ready=true
            log_success "  IRIS web interface is responding! (HTTP $http_code, ${iris_wait}s)"
            break
        fi

        # Show initialization progress by checking app logs
        local current_status=$(docker logs intact_iris_app 2>&1 | tail -1 | grep -oP '(?<=:: )[^:]+(?= ::)' | tail -1)
        if [[ -n "$current_status" && "$current_status" != "$last_status" ]]; then
            log_info "  IRIS status: $current_status"
            last_status="$current_status"
        fi

        sleep 5
        ((iris_wait+=5))
        # Only show periodic updates every 15 seconds to reduce noise
        if (( iris_wait % 15 == 0 )); then
            log_info "  Waiting for IRIS... (${iris_wait}/${iris_max_wait}s)"
        fi
    done

    if [[ "$iris_ready" == "true" ]]; then
        track_module_success "IRIS"
    else
        log_warn "  IRIS web interface not responding after ${iris_max_wait}s"
        log_info "  This may be normal for first-time installation"
        log_info "  Check logs: docker logs intact_iris_app"
        log_info "  IRIS should be accessible at https://localhost:8443 once ready"
        track_module_success "IRIS"
    fi

    # Persist the IRIS administrator's API key into the backend's secrets
    # table so IRIS automation doesn't have to docker-exec into iris-db
    # at runtime (which fails when the container name drifts, docker.sock
    # isn't mounted, or the iris-db is briefly unhealthy). The key is
    # never written to config.yaml or any export — it lives only in the
    # backend's SQLite secrets table.
    bootstrap_iris_api_key
}

bootstrap_iris_api_key() {
    # Idempotent: skip if the secret is already in the backend DB. Doing
    # the check via the backend container guarantees we use the same
    # storage layer the runtime uses. If intact_backend isn't up yet we
    # fall through to the bootstrap (the secret simply doesn't exist).
    local existing
    existing=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
v = get_secret('iris.administrator.api_key')
sys.stdout.write(v or '')
" 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        log_info "  IRIS API key already in backend secrets DB — skipping bootstrap"
        return 0
    fi

    log_info "  Bootstrapping IRIS API key into backend secrets DB..."

    # Wait for IRIS first-init to create the administrator row with a
    # non-NULL api_key. Up to 5 minutes; the DB itself comes up in
    # seconds but the IRIS web app populates the user table only after
    # alembic migrations + seed data finish.
    local api_key=""
    local attempts=0
    while (( attempts < 60 )); do
        api_key=$(docker exec intact_iris_db psql -U iris -d iris_db -tAc \
            "SELECT api_key FROM \"user\" WHERE name='administrator' AND api_key IS NOT NULL;" \
            2>/dev/null | tr -d '[:space:]')
        if [[ -n "$api_key" ]]; then
            break
        fi
        sleep 5
        ((attempts++))
        if (( attempts % 6 == 0 )); then
            log_info "  Still waiting for IRIS to create administrator key... ($((attempts * 5))s)"
        fi
    done

    if [[ -z "$api_key" ]]; then
        log_warn "  Could not retrieve IRIS API key from intact_iris_db after 5 minutes"
        log_warn "  Backend will fall back to the runtime docker-exec lookup."
        log_warn "  If that also fails, run this manually after IRIS is up:"
        log_warn "    docker exec intact_iris_db psql -U iris -d iris_db -tAc \\"
        log_warn "      \"SELECT api_key FROM \\\"user\\\" WHERE name='administrator';\""
        log_warn "  then store it via:"
        log_warn "    docker exec intact_backend python3 -c \"from services.storage.secret_store import set_secret; set_secret('iris.administrator.api_key', '<key>')\""
        return 0
    fi

    # Write to the backend's secrets table. The backend doesn't need to be
    # restarted — config.py reads on startup, but iris_service does its own
    # secret lookup on each call too. Worst case: a backend that started
    # before this writes will pick up the secret on the next IRIS request.
    if ! docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import set_secret
ok = set_secret('iris.administrator.api_key', '$api_key')
sys.exit(0 if ok else 1)
" 2>/dev/null
    then
        log_warn "  Failed to write IRIS api_key into backend secrets DB"
        log_warn "  Backend will fall back to the runtime docker-exec lookup."
        return 0
    fi

    log_success "  IRIS API key persisted to backend secrets table (iris.administrator.api_key)"
}

# ============================================================================
# Portainer Module
# ============================================================================

deploy_portainer() {
    local portainer_enabled=$(read_config "['modules']['portainer']['enabled']")
    if ! is_enabled "$portainer_enabled"; then
        log_info "[5/7] Portainer: SKIPPED (disabled in config)"
        return
    fi

    log_info "[5/7] Starting Portainer (Container Management)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/portainer"
    cd "${SCRIPT_DIR}/modules/portainer"

    # Portainer mounts the shared Nginx TLS cert via --tlscert/--tlskey so the
    # UI on :9443 presents the same certificate as the rest of the stack.
    # generate_certificates() runs before this step, so the cert should exist —
    # but bail out loud if it doesn't rather than letting Docker create empty
    # bind-mount dirs and Portainer fail to start with an unhelpful error.
    local nginx_ssl="${SCRIPT_DIR}/modules/nginx/ssl"
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" ]] || [[ ! -f "$nginx_ssl/nginx-cert.key" ]]; then
        log_error "  Shared Nginx TLS cert not found at $nginx_ssl/"
        log_error "  Expected generate_certificates() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    # Admin password file must exist; without it the first boot falls into the
    # 5-minute initial-setup window and times out before anyone can click.
    local portainer_secret="${SCRIPT_DIR}/modules/portainer/secrets/admin_password"
    if [[ ! -s "$portainer_secret" ]]; then
        log_error "  Portainer admin password file missing at $portainer_secret"
        log_error "  Expected generate_portainer_secrets() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    local portainer_version=$(read_config "['versions']['portainer']")
    log_info "  Portainer version: ${portainer_version:-latest}"

    if ! pull_compose_with_retry "Portainer"; then
        track_module_failure "Portainer"
        return 1
    fi
    if ! run_docker_compose "up -d" "Portainer"; then
        log_error "  Docker compose failed!"
        track_module_failure "Portainer"
        return 1
    fi

    # Show container status
    show_container_status "intact_portainer"

    # Wait for Portainer container
    log_info "  Waiting for Portainer container..."
    if wait_for_container "intact_portainer" 30; then
        log_success "  Portainer is ready"
        track_module_success "Portainer"
    else
        log_warn "  Portainer may not be fully ready"
        track_module_success "Portainer"
    fi
}

# ============================================================================
# Backend API Module
# ============================================================================

deploy_backend() {
    log_info "[6/7] Starting Backend API..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/backend"
    cd "${SCRIPT_DIR}/modules/backend"

    # Build
    log_info "  Building Backend Docker image..."
    if ! run_docker_compose "build" "Backend"; then
        log_error "  Failed to build Backend image"
        track_module_failure "Backend API"
        return 1
    fi
    log_success "  Backend image built successfully"

    # Start
    log_info "  Starting Backend container..."
    if ! run_docker_compose "up -d" "Backend"; then
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
    while [[ $be_wait -lt $be_max_wait ]]; do
        if curl -sf --max-time 5 "http://localhost:5001/api/health" > /dev/null 2>&1; then
            log_success "  Backend API is healthy! (${be_wait}s)"
            track_module_success "Backend API"
            return 0
        fi
        sleep 5
        ((be_wait+=5))
        log_info "  Waiting for Backend API... (${be_wait}/${be_max_wait}s)"
    done

    log_warn "  Backend API started but health check not responding yet"
    track_module_success "Backend API"
}

# ============================================================================
# Nginx Module
# ============================================================================

deploy_nginx() {
    log_info "[7/7] Starting Nginx (Web Server & Reverse Proxy)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/nginx"
    cd "${SCRIPT_DIR}/modules/nginx"

    if ! pull_compose_with_retry "Nginx"; then
        track_module_failure "Nginx"
        return 1
    fi
    if ! run_docker_compose "up -d" "Nginx"; then
        log_error "  Docker compose failed!"
        track_module_failure "Nginx"
        return 1
    fi

    # Show container status
    show_container_status "intact_nginx"

    # Wait for Nginx
    log_info "  Waiting for Nginx container..."
    if wait_for_container "intact_nginx" 30; then
        log_success "  Nginx is ready"
        track_module_success "Nginx"
    else
        log_warn "  Nginx may not be fully ready"
        track_module_success "Nginx"
    fi
}

# ============================================================================
# Main Service Deployment Orchestration
# ============================================================================

start_services() {
    log_info "=========================================="
    log_info "Starting Intact.AI Services"
    log_info "=========================================="
    echo ""

    cd "${SCRIPT_DIR}"

    # Generate secrets and certificates before starting services
    generate_iris_secrets
    echo ""
    generate_portainer_secrets
    echo ""
    generate_certificates
    echo ""

    # Deploy modules in order (7 modules now, not 8)
    deploy_elk
    echo ""
    deploy_timesketch
    echo ""
    deploy_velociraptor
    echo ""
    deploy_iris
    echo ""
    deploy_portainer
    echo ""
    deploy_backend
    echo ""
    deploy_nginx
    echo ""

    # Summary
    log_info "=========================================="
    log_info "Service deployment completed"
    log_info "=========================================="

    # Show all running containers
    echo ""
    log_info "Running Intact.AI containers:"
    docker ps --filter "name=intact_" --format "  {{.Names}}: {{.Status}}" 2>/dev/null

    cd "${SCRIPT_DIR}"
}
