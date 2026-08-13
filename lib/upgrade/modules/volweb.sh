#!/bin/bash
# Intact.AI upgrade — VolWeb.
#
# No formal upstream upgrade doc beyond pull-and-restart. Postgres and media
# are named volumes and are never touched. The pg_dump is new: Django runs its
# migrations at boot, so the volume IS modified by an upgrade even though we
# do not touch it ourselves.

upgrade_module_volweb() {
    local target="$1"
    local dir; dir="$(_u_module_dir volweb)"
    local envf; envf="$(_u_env_file volweb)"
    local bak="" dump

    u_begin volweb
    dump="$(_u_backup_dir volweb)/volweb_${U_FROM// /_}_to_${target}_$(date +%Y%m%d_%H%M%S).sql"
    if _u_container_state intact_volweb_postgresdb | grep -q running; then
        # Read the role from .env rather than assuming 'postgres': VolWeb's
        # compose creates the database owned by VOLWEB_POSTGRES_USER (volweb),
        # and there is no 'postgres' role at all, so a hardcoded -U postgres
        # fails with "role does not exist" and silently skips the backup.
        local vw_user vw_db
        vw_user="$(read_env_var "$envf" VOLWEB_POSTGRES_USER 2>/dev/null || echo volweb)"
        vw_db="$(read_env_var "$envf" VOLWEB_POSTGRES_DB 2>/dev/null || echo volweb)"
        _u_pg_dump intact_volweb_postgresdb "$vw_user" "$vw_db" "$dump" \
            || log_warn "  continuing without a database backup"
    fi

    # modules/volweb/.env is gitignored -- a module enabled but never
    # actually deployed before (the operator turns it on in config.yaml
    # then runs an upgrade rather than install.sh) has NO .env file at all,
    # and "stamp volweb pins" below would fail immediately with nothing to
    # stamp into. render_volweb_env_template (lib/modules/volweb.sh, shared with
    # deploy_volweb) is idempotent -- a no-op past this point on every
    # normal upgrade, where the file already exists.
    u_do "render volweb .env template" -- render_volweb_env_template

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old volweb"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 900 "load volweb images" -- _u_load_module_images volweb "volweb-"
    u_do "ensure volweb-backend:${target}" -- \
        _u_ensure_image "forensicxlab/volweb-backend:${target}" "volweb-backend-${target}.tar"
    u_do "ensure volweb-frontend:${target}" -- \
        _u_ensure_image "forensicxlab/volweb-frontend:${target}" "volweb-frontend-${target}.tar"

    # One config.yaml pin drives both images.
    u_do "stamp volweb pins" -- _u_stamp "$envf" \
        "VOLWEB_BACKEND_VERSION=${target}" "VOLWEB_FRONTEND_VERSION=${target}"
    # config.yaml too, not just the .env. `--only elk` is supported and skips
    # the intact module that would normally merge the package pins in, so
    # config.yaml keeps the OLD version while the module moves. That is not
    # cosmetic: update_env_files (install.sh, change_ip.sh) re-derives every
    # module .env FROM config.yaml, so the next repair silently REGRESSES the
    # pin -- and for Elasticsearch a regressed pin means the node refuses to
    # start at all against a data directory a newer version wrote. Observed on
    # this box 2026-08-13. plaso and aws_sigma already did this.
    u_do "pin volweb in config.yaml" -- _pin_module_version volweb "$target"
    u_do "stamp volweb sidecar pins" -- _u_stamp_transitive volweb
    u_do --timeout 900 "start volweb" -- _u_volweb_compose_up "$dir"

    # Policy 'report', matching the Python: a DOWN VolWeb is named loudly but
    # not reverted. Worth revisiting once the .env rollback here is
    # field-proven, but changing it in the same release that introduces the
    # rollback would be testing two things at once.
    u_end volweb report 180
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

# Four to six containers mount the shared volweb_media volume at once and race
# its initialisation. These four messages are that race and nothing else, so
# they are the only ones retried. Ported from volweb.py:110-183.
_u_volweb_compose_up() {
    local dir="$1" attempt
    for attempt in 1 2 3; do
        if _u_compose "$dir" up -d --no-build --pull never; then
            return 0
        fi
        local tail_out
        tail_out="$(tail -40 "${LOG_FILE:-/dev/null}" 2>/dev/null)"
        if grep -qiE 'file exists|failed to mkdir|device or resource busy|error while creating mount source path' <<< "$tail_out"; then
            log_warn "  volweb_media volume-init race on attempt ${attempt}; retrying"
            sleep $((attempt * 5))
            continue
        fi
        return 1
    done
    return 1
}
