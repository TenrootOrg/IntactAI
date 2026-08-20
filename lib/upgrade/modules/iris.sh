#!/bin/bash
# Intact.AI upgrade — IRIS.
#
# Docs: pg_dump -> stop -> remove app/worker -> new version -> up. "Iris
# handles upgrades of the database automatically when a new version is
# started", so there is no migration step to run: post_init.py runs Alembic at
# boot. The dump is NEW here -- the Python upgrader took none, the docs ask
# for one, and it costs seconds.

upgrade_module_iris() {
    local target="$1"
    local dir; dir="$(_u_module_dir iris)"
    local envf; envf="$(_u_env_file iris)"
    local bak="" dump

    u_begin iris
    dump="$(_u_backup_dir iris)/iris_${U_FROM// /_}_to_${target}_$(date +%Y%m%d_%H%M%S).sql"

    # Not fatal: IRIS's volumes are never touched by this upgrade, so the dump
    # is insurance against the app's own boot-time Alembic migration, not
    # against us. Role and database read from .env for the same reason as
    # VolWeb below, though IRIS does use 'postgres'/'iris_db'.
    if _u_container_state intact_iris_db | grep -q running; then
        local ir_user ir_db
        ir_user="$(read_env_var "$envf" POSTGRES_USER 2>/dev/null || echo postgres)"
        ir_db="$(read_env_var "$envf" POSTGRES_DB 2>/dev/null || echo iris_db)"
        _u_pg_dump intact_iris_db "$ir_user" "$ir_db" "$dump" \
            || log_warn "  continuing without a database backup"
    fi

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old iris"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 900 "load iris images" -- _u_load_module_images iris "iris-"
    u_do "ensure iriswebapp_app:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_app:${target}" "iris-app-${target}.tar"
    u_do "ensure iriswebapp_db:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_db:${target}" "iris-db-${target}.tar"
    u_do "ensure iriswebapp_nginx:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_nginx:${target}" "iris-nginx-${target}.tar"

    u_do --timeout 300 "stop iris" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp iris pin" -- _u_stamp "$envf" "IRIS_VERSION=${target}"
    # config.yaml too, not just the .env. `--only elk` is supported and skips
    # the intact module that would normally merge the package pins in, so
    # config.yaml keeps the OLD version while the module moves. That is not
    # cosmetic: update_env_files (install.sh, change_ip.sh) re-derives every
    # module .env FROM config.yaml, so the next repair silently REGRESSES the
    # pin -- and for Elasticsearch a regressed pin means the node refuses to
    # start at all against a data directory a newer version wrote. Observed on
    # this box 2026-08-13. plaso and aws_sigma already did this.
    u_undo_pin iris
    u_do "pin iris in config.yaml" -- _pin_module_version iris "$target"
    u_do "stamp iris sidecar pins" -- _u_stamp_transitive iris
    u_do "iris web certificate" -- ensure_iris_web_cert
    # The 5 files under modules/iris/secrets/ are gitignored Docker Compose
    # file-secrets (docker-compose.yaml's `secrets: … file:` entries) --
    # compose refuses to start IRIS at all without them. Only ever written by
    # install.sh's generate_iris_secrets today; a module enabled but never
    # deployed (turned on in config.yaml, then upgraded rather than
    # installed) has none of them. Idempotent -- only fills in what is
    # missing/empty, never rotates an existing secret -- so this is a no-op
    # on every normal upgrade, where they already exist.
    u_do "generate IRIS secrets" -- generate_iris_secrets
    u_do --timeout 900 "start iris" -- _u_compose "$dir" up -d --no-build --pull never

    u_end iris rollback 240
    local rc=$?
    if (( rc == 0 )); then
        # IRIS only honours IRIS_ADM_PASSWORD at first init, so config.yaml's
        # documented credentials silently stop working on any box where the DB
        # already existed. Re-asserting is what makes them true again.
        if declare -F enforce_iris_admin_password >/dev/null; then
            enforce_iris_admin_password || log_warn "  could not re-assert the IRIS admin password"
        fi
        # The backend's IRIS api_key, which ONLY the installer used to write.
        # bootstrap_iris_api_key was reachable from lib/modules/orchestrator.sh
        # and from nowhere under lib/upgrade/, so IRIS installed BY AN UPGRADE
        # -- an operator enabling it in config.yaml and upgrading rather than
        # re-running install.sh -- came up healthy, passed every container
        # probe, and left the backend unable to call its API. Measured on a
        # backend-only box that adopted all nine modules through the dashboard:
        # every container up, secrets table empty.
        #
        # Same shape as the line above it, and for the same reason: idempotent,
        # writes only what is missing, so it is a no-op on the normal upgrade
        # where the key already exists.
        if declare -F bootstrap_iris_api_key >/dev/null; then
            bootstrap_iris_api_key || log_warn "  could not bootstrap the IRIS api key"
        fi
        discard_backup "$bak"
    fi
    return $rc
}

# Missing-only, never clobbering. modules/iris/config/certificates/... is
# gitignored and only ever created by lib/modules/shared.sh:generate_certificates,
# which is gated on iris.enabled -- so enabling IRIS later leaves nginx
# crash-looping on "cannot load certificate". Ported from iris.py:17-84.
ensure_iris_web_cert() {
    local certdir="${SCRIPT_DIR}/modules/iris/config/certificates"
    local webdir="${certdir}/web_certificates"
    local src="${SCRIPT_DIR}/modules/nginx/ssl"

    mkdir -p "$webdir" "${certdir}/rootCA" 2>/dev/null

    if [[ ! -f "${webdir}/iris_dev_cert.pem" || ! -f "${webdir}/iris_dev_key.pem" ]]; then
        if [[ -f "${src}/nginx-cert.crt" && -f "${src}/nginx-cert.key" ]]; then
            cp -p "${src}/nginx-cert.crt" "${webdir}/iris_dev_cert.pem" || return 1
            cp -p "${src}/nginx-cert.key" "${webdir}/iris_dev_key.pem" || return 1
            chmod 0644 "${webdir}/iris_dev_cert.pem"
            # iris-nginx runs as www-data (uid/gid 33) and must be able to read
            # the key; 0640 root:33 is the narrowest thing that works.
            chown 0:33 "${webdir}/iris_dev_key.pem" 2>/dev/null
            chmod 0640 "${webdir}/iris_dev_key.pem"
            log_info "  synced the IRIS web certificate from modules/nginx/ssl"
        else
            log_warn "  no nginx certificate to sync; IRIS nginx may not start"
        fi
    fi

    if [[ ! -f "${certdir}/rootCA/irisRootCACert.pem" ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "${certdir}/rootCA/irisRootCAKey.pem" \
            -out "${certdir}/rootCA/irisRootCACert.pem" \
            -subj '/CN=IRIS Root CA/O=Intact.AI/C=US' >>"${LOG_FILE:-/dev/null}" 2>&1 \
            || { log_warn "  could not generate the IRIS root CA"; return 0; }
        log_info "  generated the IRIS root CA"
    fi
    return 0
}
