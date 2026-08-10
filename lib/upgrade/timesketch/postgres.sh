#!/bin/bash
# Intact.AI upgrade — Timesketch's Postgres: credential migration and the
# major-version wipe/restore path.

# ---------------------------------------------------------------------------
# Credentials
#
# Migrates off the shipped timesketch/timesketch default. THE ORDER MATTERS:
#   1. write secrets/postgres.env  (compose reads it via env_file, and the
#      CLI must be able to read it before anything restarts)
#   2. ALTER USER, while the OLD credential still works
#   3. rewrite the conf URIs
# Doing 2 before 1, or 3 before 2, locks the platform out of its own database.
# Idempotent: once postgres.env exists this is a no-op.
# ---------------------------------------------------------------------------
_ts_ensure_postgres_password() {
    local dir; dir="$(_TS_DIR)"
    local pgenv="${dir}/secrets/postgres.env"

    if [[ -s "$pgenv" ]] && grep -q '^POSTGRES_PASSWORD=..' "$pgenv"; then
        log_info "  postgres credentials already migrated"
        return 0
    fi

    # A fresh install has no container to ALTER, and the file must be KEPT
    # rather than rolled back -- postgres will initdb with it.
    local fresh=0
    "${DOCKER_BIN:-docker}" inspect intact_timesketch_postgres >/dev/null 2>&1 || fresh=1

    local newpw; newpw="$(openssl rand -hex 32)"
    mkdir -p "${dir}/secrets" 2>/dev/null
    printf 'POSTGRES_USER=timesketch\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=timesketch\n' "$newpw" > "$pgenv" || return 1
    chmod 600 "$pgenv"
    chown --reference="$dir" "$pgenv" 2>/dev/null
    sync

    if (( ! fresh )); then
        # NOT a plain >> redirect: on a syntax/permission error postgres
        # commonly echoes the failed statement back (`LINE 1: ALTER USER
        # timesketch WITH PASSWORD '<newpw>'`), and $LOG_FILE is exactly the
        # artifact operators download and paste into support tickets.
        # redact_secrets (lib/common.sh) masks the quoted literal before it
        # ever reaches disk.
        if ! "${DOCKER_BIN:-docker}" exec -e PGPASSWORD=timesketch intact_timesketch_postgres \
                psql -U timesketch -d timesketch \
                -c "ALTER USER timesketch WITH PASSWORD '${newpw}'" 2>&1 \
                | redact_secrets >>"${LOG_FILE:-/dev/null}"; then
            log_error "  could not rotate the Timesketch postgres password"
            rm -f "$pgenv"
            return 1
        fi
    fi

    local conf
    for conf in "${dir}/config/timesketch.conf" "${dir}/config/timesketch_legacy.conf"; do
        [[ -f "$conf" ]] || continue
        sed -i -E "s|postgresql://timesketch:[^@]*@|postgresql://timesketch:${newpw}@|g" "$conf"
    done
    log_info "  migrated the Timesketch postgres password off the shipped default"
    return 0
}

# ---------------------------------------------------------------------------
# Postgres major detection
# ---------------------------------------------------------------------------
_TS_PG_MIGRATE=0; _TS_PG_FROM=""; _TS_PG_TO=""; _TS_PG_VOLUME=""

_ts_detect_pg_major_change() {
    local envf="$1"
    _TS_PG_MIGRATE=0; _TS_PG_FROM=""; _TS_PG_TO=""; _TS_PG_VOLUME=""

    _TS_PG_FROM="$("${DOCKER_BIN:-docker}" exec intact_timesketch_postgres \
        cat /var/lib/postgresql/data/PG_VERSION 2>/dev/null | tr -d '[:space:]')"
    local pinned; pinned="$(read_env_var "$envf" POSTGRES_VERSION 2>/dev/null || echo '')"
    _TS_PG_TO="${pinned%%.*}"

    if [[ -z "$_TS_PG_FROM" || -z "$_TS_PG_TO" ]]; then
        log_info "  Postgres major: could not determine (running='${_TS_PG_FROM:-?}' pinned='${pinned:-?}'); assuming unchanged"
        return 0
    fi
    if [[ "$_TS_PG_FROM" == "$_TS_PG_TO" ]]; then
        log_info "  Postgres major ${_TS_PG_FROM} unchanged"
        return 0
    fi

    _TS_PG_VOLUME="$("${DOCKER_BIN:-docker}" inspect intact_timesketch_postgres \
        --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' 2>/dev/null)"
    _TS_PG_MIGRATE=1
    log_warn "  Postgres major changes ${_TS_PG_FROM} -> ${_TS_PG_TO}"
    log_warn "  The data directory format differs between majors, so the volume"
    log_warn "  (${_TS_PG_VOLUME:-unknown}) must be wiped and restored from the dump."
    return 0
}

# Wipe and restore. Only ever reached when a dump exists -- the caller refuses
# otherwise, and that refusal is the guarantee.
_ts_migrate_pg_major() {
    local dir="$1" dump="$2"
    [[ -s "$dump" ]] || { log_error "  refusing to wipe the volume without a dump"; return 1; }
    [[ -n "$_TS_PG_VOLUME" ]] || { log_error "  could not identify the postgres data volume"; return 1; }

    log_info "  removing volume ${_TS_PG_VOLUME}"
    "${DOCKER_BIN:-docker}" volume rm "$_TS_PG_VOLUME" >>"${LOG_FILE:-/dev/null}" 2>&1 || {
        log_error "  could not remove ${_TS_PG_VOLUME}"; return 1; }

    # Postgres ALONE first: bringing the whole stack up would let web and
    # worker connect to a database that has not been restored yet.
    _u_compose "$dir" up -d --no-build --pull never timesketch-postgres || return 1
    _ts_wait_postgres || return 1
    _ts_restore_db "$dump" || return 1
    log_success "  Postgres migrated to major ${_TS_PG_TO} and restored"
    return 0
}

_ts_wait_postgres() {
    local i
    for i in $(seq 1 40); do
        if "${DOCKER_BIN:-docker}" exec intact_timesketch_postgres \
             pg_isready -U timesketch >/dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    log_error "  postgres did not become ready"
    return 1
}

# Terminate, drop, create, restore. Used by the major migration and by the
# rollback.
_ts_restore_db() {
    local dump="$1"
    [[ -s "$dump" ]] || { log_error "  no dump to restore from"; return 1; }
    _ts_wait_postgres || return 1
    local d="${DOCKER_BIN:-docker}"
    $d exec intact_timesketch_postgres psql -U timesketch -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='timesketch' AND pid<>pg_backend_pid()" \
        >>"${LOG_FILE:-/dev/null}" 2>&1
    $d exec intact_timesketch_postgres dropdb --if-exists -U timesketch timesketch >>"${LOG_FILE:-/dev/null}" 2>&1
    $d exec intact_timesketch_postgres createdb -U timesketch timesketch >>"${LOG_FILE:-/dev/null}" 2>&1 || return 1
    $d exec -i intact_timesketch_postgres psql -U timesketch -d timesketch < "$dump" >>"${LOG_FILE:-/dev/null}" 2>&1 || return 1
    log_info "  restored the Timesketch database from ${dump}"
    return 0
}

_ts_bring_back_up() {
    local dir; dir="$(_TS_DIR)"
    _u_compose "$dir" down --remove-orphans
    _u_compose "$dir" up -d --no-build --pull never
}
