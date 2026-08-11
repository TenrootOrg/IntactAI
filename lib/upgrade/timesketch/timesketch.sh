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
#
# Sibling files: postgres.sh (credentials + the major-version wipe/restore),
# schema.sh (Alembic bootstrap + upgrade), health.sh (readiness wait + the
# data-loss sanity check this module's own steps below call into).

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

    # timesketch.conf / timesketch_legacy.conf are gitignored and
    # bind-mounted into the containers -- a module enabled but never before
    # deployed (turned on in config.yaml, then upgraded rather than
    # installed) has neither file, and "start timesketch" would hit the
    # same Docker-fabricates-an-empty-directory failure the intact module's
    # own mount-asset delivery guards against for other files. Idempotent
    # (skips a conf that already exists), so unconditional here costs
    # nothing on every normal upgrade.
    u_do "render timesketch conf templates" -- render_timesketch_conf_templates

    # Same idempotent-so-unconditional reasoning as the conf-template render
    # above: modules/timesketch/config/dfiq/ is gitignored, and a module
    # enabled but never before deployed has none of it. Staging from the
    # package here means deploy_timesketch's own presence check short-
    # circuits and the live google/dfiq clone is never attempted on an
    # air-gapped upgrade target.
    stage_dfiq_from_package "$UPKG_DIR"

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

    u_do --timeout 900 "load timesketch images" -- _u_load_module_images timesketch "timesketch-"
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
        # A module enabled but never before deployed has no admin user --
        # nothing else in this path ever creates one. Gated on U_FROM
        # (nothing installed before this run) rather than running
        # unconditionally: tsctl's own polling (up to 60s for the schema,
        # 5 retries at 10s for the create) is real latency an ALREADY
        # -established install has no reason to pay on every upgrade.
        if [[ "$U_FROM" == "not installed" ]] && declare -F create_timesketch_admin_user >/dev/null; then
            create_timesketch_admin_user || log_warn "  could not create the TimeSketch admin user"
        fi
        discard_backup "$bak"
        # The DB dump is deliberately KEPT. It is the only copy of the
        # pre-upgrade schema+data, it is small next to the evidence it
        # protects, and an operator who needs it needs it days later.
        [[ -n "$dump" && -f "$dump" ]] && log_info "  database backup kept at ${dump}"
    fi
    return $rc
}
