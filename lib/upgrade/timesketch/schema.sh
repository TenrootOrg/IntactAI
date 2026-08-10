#!/bin/bash
# Intact.AI upgrade — Timesketch's Alembic schema migration.

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
