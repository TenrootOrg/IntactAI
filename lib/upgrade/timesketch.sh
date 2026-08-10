#!/bin/bash
# Intact.AI upgrade — Timesketch.
#
# The only module with a real database migration, and the only one that can
# destroy evidence if it goes wrong. Follows timesketch.org's documented
# procedure:
#
#     pg_dump / pg_dumpall
#     tsctl db current -> db history -> db stamp <REVISION> -> db upgrade
#     bump TIMESKETCH_VERSION
#     docker compose pull -> down -> up -d
#
# Two deliberate differences from the docs, both because the docs describe a
# hand-driven upgrade and this one has to run unattended:
#
#   * The docs `git clone` the Timesketch repo INSIDE the web container to get
#     migrations/, because the installed wheel does not ship it (confirmed on
#     this box: there is no /migrations and the package lives in
#     /opt/venv/.../timesketch). We `docker cp` the same directory in from the
#     package instead -- identical content, and it works air-gapped.
#
#   * The docs stamp a revision the operator reads off `db history`. Unattended
#     that becomes "stamp head", which is a lie whenever the database is
#     actually behind head: alembic then skips every migration between and the
#     schema silently never changes. So the stamp only ever happens when
#     alembic_version is EMPTY (a database that predates alembic tracking),
#     and `db upgrade` refuses to run against an empty table.
#
# WHAT IS NOT PROTECTED, said out loud because the log should not imply
# otherwise: pg_dump covers Postgres, which holds sketches, timelines, users
# and ACLs. It does NOT cover OpenSearch, which holds the actual timeline
# EVENTS. A lost OpenSearch index is detectable here (the doc count drops) but
# not recoverable from anything this script takes.

_TS_DIR() { echo "${SCRIPT_DIR}/modules/timesketch"; }

upgrade_module_timesketch() {
    local target="$1"
    local dir; dir="$(_TS_DIR)"
    local envf="${dir}/.env"
    local backend_env="${SCRIPT_DIR}/modules/backend/.env"
    local bak="" dump="" pg_migrate=0

    u_begin timesketch

    dump="$(_u_backup_dir timesketch)/timesketch_${U_FROM// /_}_to_${target}_$(date +%Y%m%d_%H%M%S).sql"

    # 1. Credential migration off the shipped default. ORDER IS LOAD-BEARING;
    #    see the function.
    u_do "postgres credentials" -- _ts_ensure_postgres_password

    # 2. The dump, while everything is still up and consistent.
    local have_dump=0
    if _u_pg_dump intact_timesketch_postgres timesketch timesketch "$dump"; then
        have_dump=1
    fi

    # 3. Back up .env BEFORE the first thing that writes to it. The sidecar
    #    stamp below is a mutation, so taking the backup after it would
    #    snapshot an already-modified file and a rollback would "restore" the
    #    new POSTGRES_VERSION -- leaving the pin pointing at a major the
    #    rolled-back stack was never running.
    bak="$(backup_file_for_rollback "$envf")" || bak=""

    # 4. Sidecar pins, before the Postgres-major check below reads
    #    POSTGRES_VERSION out of .env -- stamping after it would compare the
    #    running major against the OLD pin and miss the migration entirely.
    u_do "stamp timesketch sidecar pins" -- _u_stamp_transitive timesketch

    # 5. Would this upgrade change the Postgres MAJOR? If so the data volume
    #    has to be wiped and restored, and that is only safe with a dump.
    u_do "check for a Postgres major change" -- _ts_detect_pg_major_change "$envf"
    pg_migrate="${_TS_PG_MIGRATE:-0}"
    if (( pg_migrate )) && (( ! have_dump )); then
        # The refusal IS the data-safety guarantee. Everything else here is
        # convenience; this is the line that stops an upgrade deleting a
        # volume it cannot put back.
        log_error "  Postgres would go from major ${_TS_PG_FROM} to ${_TS_PG_TO},"
        log_error "  which requires wiping and restoring the data volume — but the"
        log_error "  pg_dump above FAILED. Refusing to continue."
        U_FAILED=1; U_LABEL="pg_dump failed before a required Postgres major migration"; U_RC=1
    fi

    # 6. Cheap sanity snapshot. Four numbers in two round-trips, not the 18
    #    tables the Python counted -- the point is to notice evidence
    #    disappearing, and a sketch or timeline vanishing is what that looks
    #    like.
    local before_counts=""
    if (( ! U_FAILED )); then
        before_counts="$(_ts_counts)"
        log_info "  before: ${before_counts}"
    fi

    # 7. Alembic bootstrap MUST happen against the still-running OLD container.
    u_do --timeout 600 "bootstrap alembic if untracked" -- _ts_bootstrap_alembic "$U_FROM"

    u_undo "_ts_bring_back_up"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"
    (( have_dump )) && u_undo "_ts_restore_db '${dump}'"

    u_do --timeout 900 "load timesketch images" -- _u_load_tars_matching "timesketch-"
    u_do --timeout 1800 "ensure timesketch:${target}" -- \
        _u_ensure_image "us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:${target}" \
        "timesketch-${target}.tar"

    u_do --timeout 600 "stop timesketch" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp TIMESKETCH_VERSION" -- _u_stamp "$envf" "TIMESKETCH_VERSION=${target}"

    if (( pg_migrate )); then
        u_do --timeout 1800 "migrate Postgres ${_TS_PG_FROM} -> ${_TS_PG_TO}" -- \
            _ts_migrate_pg_major "$dir" "$dump"
    fi

    u_do --timeout 900 "start timesketch" -- _u_compose "$dir" up -d --no-build --pull never
    u_do --timeout 600 "wait for gunicorn" -- _ts_wait_gunicorn

    # 8. A Postgres-major migration restores the dump taken at step 2 -- which
    #    was taken BEFORE step 7 stamped alembic_version, so the restored
    #    database has no alembic table at all and the schema upgrade below
    #    would (correctly) refuse to run against it. Re-stamp against the OLD
    #    version, which is what the restored schema actually is.
    #
    #    Found by running a real 13 -> 15 migration: the data restored fine and
    #    then the run rolled itself back on "alembic_version is empty".
    if (( pg_migrate )); then
        u_do --timeout 600 "re-stamp alembic after the Postgres migration" -- \
            _ts_bootstrap_alembic "$U_FROM"
    fi

    # 9. Schema migration, on the NEW image, against a database whose alembic
    #    state is known.
    u_do --timeout 900 "apply database migrations" -- _ts_db_upgrade "$target"

    # 7. Did anything disappear?
    if (( ! U_FAILED )); then
        local after_counts; after_counts="$(_ts_counts)"
        log_info "  after:  ${after_counts}"
        if ! _ts_counts_not_lower "$before_counts" "$after_counts"; then
            U_FAILED=1; U_LABEL="row/doc counts dropped across the upgrade"; U_RC=1
            log_error "  DATA LOSS DETECTED. The Postgres dump is at:"
            log_error "    ${dump}"
        fi
    fi

    u_end timesketch rollback 300
    local rc=$?
    if (( rc == 0 )); then
        discard_backup "$bak"
        # The DB dump is deliberately KEPT. It is the only copy of the
        # pre-upgrade schema+data, it is small next to the evidence it
        # protects, and an operator who needs it needs it days later.
        [[ -n "$dump" && -f "$dump" ]] && log_info "  database backup kept at ${dump}"
    fi
    return $rc
}

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
        if ! "${DOCKER_BIN:-docker}" exec -e PGPASSWORD=timesketch intact_timesketch_postgres \
                psql -U timesketch -d timesketch \
                -c "ALTER USER timesketch WITH PASSWORD '${newpw}'" >>"${LOG_FILE:-/dev/null}" 2>&1; then
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

# ---------------------------------------------------------------------------
# Alembic
# ---------------------------------------------------------------------------

# Get migrations/ onto the web container. Offline reads only what the package
# carries and NEVER falls back to GitHub -- a silent network fetch during an
# air-gapped upgrade is either a hang or a lie about what was applied.
_ts_stage_migrations() {
    local version="$1"
    local bundled="${UPKG_DIR}/migrations/timesketch"
    local src=""

    if [[ -d "$bundled" ]]; then
        src="$bundled"
        log_info "  using the migrations bundled in the package"
    elif [[ "${INTACT_UPGRADE_OFFLINE:-0}" == "1" ]]; then
        log_error "  no migrations/timesketch in the package and offline; cannot migrate the schema"
        return 1
    else
        local cache="${SCRIPT_DIR}/backups/timesketch/migrations_cache/${version}"
        if [[ ! -d "${cache}/migrations" ]]; then
            mkdir -p "$cache" || return 1
            local url="https://github.com/google/timesketch/archive/refs/tags/${version}.tar.gz"
            log_info "  fetching migrations for ${version} from GitHub"
            if ! curl -fLsS --retry 3 --max-time 300 -o "${cache}/src.tar.gz" "$url" 2>>"${LOG_FILE:-/dev/null}"; then
                log_warn "  no tag ${version} upstream; trying master"
                curl -fLsS --retry 3 --max-time 300 -o "${cache}/src.tar.gz" \
                    "https://github.com/google/timesketch/archive/refs/heads/master.tar.gz" \
                    2>>"${LOG_FILE:-/dev/null}" || { log_error "  could not fetch migrations"; return 1; }
            fi
            tar -xzf "${cache}/src.tar.gz" -C "$cache" --strip-components=2 \
                --wildcards '*/timesketch/migrations' 2>>"${LOG_FILE:-/dev/null}" \
                || { log_error "  could not extract migrations"; return 1; }
            rm -f "${cache}/src.tar.gz"
        fi
        src="${cache}/migrations"
        [[ -d "$src" ]] || { log_error "  migrations directory not found after extraction"; return 1; }
    fi

    "${DOCKER_BIN:-docker}" exec intact_timesketch_web rm -rf /migrations >>"${LOG_FILE:-/dev/null}" 2>&1
    "${DOCKER_BIN:-docker}" cp "${src}/." intact_timesketch_web:/migrations >>"${LOG_FILE:-/dev/null}" 2>&1 \
        || { log_error "  could not copy migrations into the container"; return 1; }
    return 0
}

_ts_alembic_revision() {
    "${DOCKER_BIN:-docker}" exec intact_timesketch_postgres \
        psql -U timesketch -d timesketch -tAc \
        "SELECT version_num FROM alembic_version LIMIT 1" 2>/dev/null | tr -d '[:space:]'
}

# A database that predates alembic tracking has no alembic_version table at
# all -- which is the state this very appliance is in. `db upgrade` against
# that would try to replay EVERY migration from the beginning against a schema
# that already exists, and fail on the first CREATE TABLE. Stamping first tells
# alembic "you are already here".
#
# Runs against the OLD, still-running container on purpose: the stamp has to
# record the revision matching the schema that is actually in the database
# right now, which is the old version's head, not the new one's.
_ts_bootstrap_alembic() {
    local current_version="$1"
    local d="${DOCKER_BIN:-docker}"

    if ! $d inspect intact_timesketch_web >/dev/null 2>&1; then
        log_info "  no timesketch-web container yet; nothing to bootstrap"
        return 0
    fi
    # Compose may leave it Created rather than running.
    if [[ "$(_u_container_state intact_timesketch_web)" != "running" ]]; then
        $d start intact_timesketch_web >>"${LOG_FILE:-/dev/null}" 2>&1
        local i; for i in $(seq 1 20); do
            [[ "$(_u_container_state intact_timesketch_web)" == "running" ]] && break
            sleep 3
        done
    fi

    local have_table rev
    have_table="$($d exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
        "SELECT to_regclass('alembic_version')" 2>/dev/null | tr -d '[:space:]')"
    rev="$(_ts_alembic_revision)"

    if [[ -n "$rev" ]]; then
        log_info "  alembic already tracking at revision ${rev}"
        return 0
    fi

    log_info "  alembic is untracked (table: ${have_table:-absent}); stamping the current schema"
    _ts_stage_migrations "$current_version" || return 1

    if ! $d exec intact_timesketch_web tsctl db stamp -d /migrations head >>"${LOG_FILE:-/dev/null}" 2>&1; then
        log_error "  tsctl db stamp failed"
        return 1
    fi
    rev="$(_ts_alembic_revision)"
    if [[ -z "$rev" ]]; then
        log_error "  stamp reported success but alembic_version is still empty"
        return 1
    fi
    log_success "  alembic bootstrapped at ${rev}"
    return 0
}

# REFUSES TO BLIND-STAMP HEAD. If alembic_version is empty at this point the
# bootstrap above did not happen or did not work, and running `db upgrade`
# would either fail loudly or -- worse -- a stamp-then-upgrade would mark the
# schema as migrated without touching it.
_ts_db_upgrade() {
    local target="$1"
    local d="${DOCKER_BIN:-docker}"

    _ts_stage_migrations "$target" || return 1

    local before after
    before="$(_ts_alembic_revision)"
    if [[ -z "$before" ]]; then
        log_error "  alembic_version is empty; refusing to upgrade the schema."
        log_error "  Stamping head here would mark the database as migrated without"
        log_error "  migrating it, and the mismatch would only surface much later."
        return 1
    fi

    if ! $d exec intact_timesketch_web tsctl db upgrade -d /migrations >>"${LOG_FILE:-/dev/null}" 2>&1; then
        log_error "  tsctl db upgrade failed"
        return 1
    fi
    after="$(_ts_alembic_revision)"
    if [[ "$before" == "$after" ]]; then
        log_info "  schema already current at ${after}"
    else
        log_success "  schema migrated ${before} -> ${after}"
    fi
    return 0
}

_ts_wait_gunicorn() {
    local i
    for i in $(seq 1 60); do
        if "${DOCKER_BIN:-docker}" exec intact_timesketch_web pgrep -f gunicorn >/dev/null 2>&1; then
            return 0
        fi
        # A crash-looping stack will not settle; stop waiting the full ten
        # minutes for it.
        case "$(_u_container_state intact_timesketch_web)" in
            restarting|exited) log_error "  timesketch-web is ${_LAST:-not running}"; return 1 ;;
        esac
        sleep 5
    done
    log_error "  gunicorn did not appear in timesketch-web"
    return 1
}

# ---------------------------------------------------------------------------
# The cheap sanity check.
#
# Four numbers: users, sketches, timelines (Postgres) and total OpenSearch
# documents. The Python counted 18 tables in 19 separate psql round-trips; the
# question being answered is "did evidence disappear", and a vanished sketch or
# timeline is what that looks like. Two round-trips instead of nineteen.
# ---------------------------------------------------------------------------
_ts_counts() {
    local d="${DOCKER_BIN:-docker}" pg os
    pg="$($d exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
        'SELECT (SELECT count(*) FROM "user"),(SELECT count(*) FROM sketch),(SELECT count(*) FROM timeline)' \
        2>/dev/null | tr -d '[:space:]')"
    # Non-system indices only: the leading-dot ones are OpenSearch's own.
    os="$($d exec intact_timesketch_opensearch \
        curl -s --max-time 10 'localhost:9200/_cat/indices?h=index,docs.count' 2>/dev/null \
        | awk '$1 !~ /^\./ {s += $2} END {print s + 0}')"
    echo "users/sketches/timelines=${pg:-?} opensearch_docs=${os:-?}"
}

# Not-lower rather than equal: an upgrade may legitimately add rows (a
# migration backfilling a table, the app writing a login record), but nothing
# should ever DISAPPEAR.
_ts_counts_not_lower() {
    local before="$1" after="$2"
    local b_pg a_pg b_os a_os
    b_pg="${before#*=}"; b_pg="${b_pg%% *}"
    a_pg="${after#*=}";  a_pg="${a_pg%% *}"
    b_os="${before##*=}"; a_os="${after##*=}"

    if [[ "$b_pg" == "?" || "$a_pg" == "?" ]]; then
        log_warn "  could not compare Postgres counts (before='${b_pg}' after='${a_pg}')"
    else
        local i
        local -a bs as
        IFS='|' read -ra bs <<< "$b_pg"
        IFS='|' read -ra as <<< "$a_pg"
        local names=(users sketches timelines)
        for i in 0 1 2; do
            if [[ -n "${bs[i]:-}" && -n "${as[i]:-}" ]] && (( ${as[i]} < ${bs[i]} )); then
                log_error "  ${names[i]}: ${bs[i]} -> ${as[i]} (LOST ROWS)"
                return 1
            fi
        done
    fi

    if [[ "$b_os" =~ ^[0-9]+$ && "$a_os" =~ ^[0-9]+$ ]] && (( a_os < b_os )); then
        log_error "  OpenSearch documents: ${b_os} -> ${a_os} (LOST EVENTS)"
        # Worth stating rather than implying: the dump does not cover this.
        log_error "  NOTE: OpenSearch is not dumped by this upgrade. The Postgres backup"
        log_error "  cannot restore timeline events — this is detectable, not recoverable."
        return 1
    fi
    return 0
}
