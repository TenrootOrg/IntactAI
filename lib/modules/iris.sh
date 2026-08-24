#!/bin/bash
# Intact.AI Platform Installer — IRIS module.

generate_iris_secrets() {
    # IRIS-disabled guard — without this, fresh installs with
    # `modules.iris.enabled: false` still write 5 secret files into
    # `modules/iris/secrets/` and pull config values for a module the
    # operator turned off. Same `is_enabled` pattern as the rest.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "Generating IRIS secrets: SKIPPED (disabled in config)"
        return 0
    fi
    log_info "Generating IRIS secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/iris/secrets"
    mkdir -p "$secrets_dir"

    local secrets_created=false

    # IRIS_ADM_PASSWORD comes from config.yaml when the operator set one;
    # otherwise generate a random per-install password instead of shipping
    # the same fixed, publicly-documented string to every default install
    # (the same pattern used for the Portainer admin password below).
    if [[ ! -f "$secrets_dir/IRIS_ADM_PASSWORD" ]] || [[ ! -s "$secrets_dir/IRIS_ADM_PASSWORD" ]]; then
        local iris_password=$(read_config "['modules']['iris']['password']")
        if [[ -n "$iris_password" && "$iris_password" != "None" ]]; then
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_info "  Created IRIS_ADM_PASSWORD from config.yaml"
        else
            iris_password=$(openssl rand -hex 16)
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_warn "  No IRIS password set in config.yaml; generated a random one instead"
            log_warn "  Retrieve it with: cat ${secrets_dir}/IRIS_ADM_PASSWORD"
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

# ============================================================================
# IRIS Module
# ============================================================================

deploy_iris() {
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "[4/8] IRIS: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_iris_app; then
        log_info "[4/8] IRIS: already installed + running (skipping)"
        return 0
    fi

    log_info "[4/8] Starting IRIS (Incident Response Platform)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/iris"
    cd "${SCRIPT_DIR}/modules/iris"

    if ! preflight_host_check "IRIS"; then
        log_error "IRIS: host pre-flight FAILED — see warnings above"
        track_module_failure "IRIS"
        return 1
    fi

    local iris_version=$(read_config "['versions']['iris']")
    log_info "  IRIS version: ${iris_version:-latest}"

    # Stamp transitive container pins from config.yaml. iris's compose
    # uses `${RABBITMQ_VERSION:?...}`; loud failure here is preferable
    # to a silent stale literal.
    _stamp_transitive_env_from_config "iris" \
        "RABBITMQ_VERSION:iris_rabbitmq"

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
    if ! run_compose_up_with_retry "IRIS"; then
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
    local db_ready=false
    while [[ $db_wait -lt $db_max_wait ]]; do
        if docker exec intact_iris_db pg_isready -U postgres > /dev/null 2>&1; then
            log_success "  IRIS database is ready (${db_wait}s)"
            db_ready=true
            break
        fi
        sleep 5
        ((db_wait+=5))
        log_info "  Waiting for database... (${db_wait}/${db_max_wait}s)"
    done
    if [[ "$db_ready" != "true" ]]; then
        log_warn "  IRIS database did not become ready in ${db_max_wait}s"
        capture_diagnostic_logs "IRIS database (timeout)" intact_iris_db
    fi

    # Wait for RabbitMQ
    log_info "  Waiting for IRIS message queue (RabbitMQ)..."
    local mq_wait=0
    local mq_max_wait=60
    local mq_ready=false
    while [[ $mq_wait -lt $mq_max_wait ]]; do
        if docker exec intact_iris_rabbitmq rabbitmqctl status > /dev/null 2>&1; then
            log_success "  RabbitMQ is ready (${mq_wait}s)"
            mq_ready=true
            break
        fi
        sleep 5
        ((mq_wait+=5))
        log_info "  Waiting for RabbitMQ... (${mq_wait}/${mq_max_wait}s)"
    done
    if [[ "$mq_ready" != "true" ]]; then
        log_warn "  IRIS RabbitMQ did not become ready in ${mq_max_wait}s"
        capture_diagnostic_logs "IRIS RabbitMQ (timeout)" intact_iris_rabbitmq
    fi

    # Wait for IRIS app container
    log_info "  Waiting for IRIS app container..."
    if ! wait_for_container "intact_iris_app" 90; then
        log_warn "  IRIS app container not ready after 90s"
        capture_diagnostic_logs "IRIS app (container timeout)" intact_iris_app intact_iris_db intact_iris_rabbitmq
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
        capture_diagnostic_logs "IRIS web (post-deploy timeout)" \
            intact_iris_nginx intact_iris_app intact_iris_db intact_iris_rabbitmq
        track_module_success "IRIS"
    fi

    # bootstrap_iris_api_key is intentionally NOT called here — it writes
    # via `docker exec intact_backend …`, but Backend is deployed AFTER
    # IRIS in start_services. Calling it here meant set_secret failed
    # 100% of the time on fresh installs ("no such container") and the
    # backend silently fell back to the slow runtime docker-exec lookup.
    # The bootstrap now runs from start_services, after deploy_backend.
}

bootstrap_iris_api_key() {
    # IRIS-disabled guard — added in the install-hardening pass after
    # the June 7 log showed 5 minutes of dead-wait polling for an
    # `intact_iris_db` container that never started because IRIS was
    # off. Mirrors the same pattern `deploy_iris` already uses.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "  IRIS disabled — skipping API key bootstrap"
        return 0
    fi
    # Idempotent: skip if the secret is already in the backend DB. Doing
    # the check via the backend container guarantees we use the same
    # storage layer the runtime uses. If intact_backend isn't up yet we
    # fall through to the bootstrap (the secret simply doesn't exist).
    #
    # SENTINEL, not a bare capture. Importing services.storage prints three
    # banner lines to STDOUT ("[STORAGE] Initializing SQLite storage...",
    # "[STORAGE] SQLite storage initialized: ...", "[WORKFLOW] Using SQLite +
    # Elasticsearch storage for workflows"), and a plain $(...) swallows all
    # of it. With `sys.stdout.write(v or '')` writing NOTHING when there is no
    # key, `existing` was therefore the banner text -- always non-empty -- so
    # this guard fired on every box and bootstrap_iris_api_key never ran at
    # all. Measured on a clean 2026-08-24 install: zero iris rows in the
    # secrets table and "IRIS API key already in backend secrets DB" in the
    # same log. Same hazard, same fix, as lib/modules/shared.sh's has_cred
    # probe, which documents it and already uses this pattern.
    local existing
    existing=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
print('INTACT_IRISKEY:' + (get_secret('iris.administrator.api_key') or ''))
" 2>/dev/null | grep -o 'INTACT_IRISKEY:.*' | tail -1 || true)
    existing="${existing#INTACT_IRISKEY:}"
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

    # Read-back verification — set_secret() can return 0 even when the
    # write is rolled back (locked SQLite, transient I/O). Re-query
    # via get_secret to confirm the value actually persisted, so a
    # silent failure here doesn't surface as a runtime IRIS-API error
    # weeks later.
    # Same sentinel as the guard above, and for the same reason: a bare
    # capture returns the storage banner glued to the key, so this comparison
    # could never match even on a perfectly successful write. It was masked
    # only because the (also unprotected) guard above returned early on every
    # box, so this line had never once been reached with a real key.
    local persisted
    persisted=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
print('INTACT_IRISKEY:' + (get_secret('iris.administrator.api_key') or ''))
" 2>/dev/null | grep -o 'INTACT_IRISKEY:.*' | tail -1)
    persisted="${persisted#INTACT_IRISKEY:}"

    if [[ "$persisted" == "$api_key" ]]; then
        log_success "  IRIS API key persisted to backend secrets table (iris.administrator.api_key) — verified"
    else
        log_error "  IRIS api_key set_secret() returned OK but the read-back didn't match"
        log_error "  Manual fix: docker exec intact_backend python3 -c \"from services.storage.secret_store import set_secret; set_secret('iris.administrator.api_key', '<key>')\""
        capture_diagnostic_logs "Backend secret write" intact_backend
    fi
}

enforce_iris_admin_password() {
    # Make config.yaml the source of truth for the IRIS administrator password.
    # IRIS only honours IRIS_ADM_PASSWORD at FIRST init (post_init.py); on later
    # boots an existing admin keeps whatever it had. So if the secret wasn't
    # applied at first-init (e.g. an unreadable secret file -> IRIS fell back to
    # a RANDOM password), the documented config.yaml creds never work. Re-assert
    # them here using IRIS's own bcrypt hashing (flask-bcrypt), idempotently.

    # IRIS-disabled guard — mirrors bootstrap_iris_api_key. Without this, a
    # deselected IRIS still reached the app/db running-check below and logged a
    # misleading "IRIS app/db not running" WARNING on every install where IRIS
    # is off. Nothing to enforce when the module isn't installed.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "  IRIS disabled — skipping admin-password enforcement"
        return 0
    fi

    local iris_user iris_pass
    iris_user=$(read_config "['modules']['iris']['id']"); [[ -z "$iris_user" ]] && iris_user="administrator"
    iris_pass=$(read_config "['modules']['iris']['password']")
    if [[ -z "$iris_pass" ]]; then
        log_warn "  IRIS password not set in config.yaml — skipping admin-password enforcement"
        return 0
    fi
    if ! docker ps --filter 'name=^intact_iris_app$' --format '{{.Names}}' 2>/dev/null | grep -q . \
       || ! docker ps --filter 'name=^intact_iris_db$' --format '{{.Names}}' 2>/dev/null | grep -q .; then
        log_warn "  IRIS app/db not running — skipping IRIS admin-password enforcement"
        return 0
    fi

    log_info "  Enforcing IRIS administrator password from config.yaml..."
    # Step 1: hash with IRIS's own flask-bcrypt, standalone (NO db access — a
    # fresh `docker exec` lacks the DB secret the entrypoint exports, so importing
    # `app` can't connect). Password comes from the container env, never the body.
    local hash
    hash=$(docker exec -e IRIS_RESET_PW="$iris_pass" intact_iris_app python3 -c \
        'import os;from flask_bcrypt import Bcrypt;print(Bcrypt().generate_password_hash(os.environ["IRIS_RESET_PW"].encode()).decode())' \
        2>/dev/null | tail -1)
    if [[ "$hash" != \$2* ]]; then
        log_warn "  Could not compute IRIS password hash — skipping"
        return 0
    fi
    # Step 2: write it straight into iris_db (psql authenticates locally). bcrypt
    # has no single quotes so the SQL literal is safe.
    local res
    res=$(docker exec intact_iris_db psql -U iris -d iris_db \
        -c "UPDATE \"user\" SET password='$hash' WHERE \"user\"='$iris_user';" 2>&1 | tail -1)
    if [[ "$res" == *"UPDATE 1"* ]]; then
        log_success "  IRIS administrator password set from config.yaml"
    elif [[ "$res" == *"UPDATE 0"* ]]; then
        log_warn "  IRIS administrator row not found — password not set"
    else
        log_warn "  Could not enforce IRIS admin password: $res"
    fi
    return 0
}
