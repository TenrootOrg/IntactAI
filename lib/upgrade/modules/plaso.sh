#!/bin/bash
# Intact.AI upgrade — Plaso. No container of its own; the job runner shells
# out to the pinned image per-job.

upgrade_module_plaso() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin plaso
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 1800 "ensure plaso:${target}" -- \
        _u_ensure_image "log2timeline/plaso:${target}" "plaso-${target}.tar"
    u_do "stamp PLASO_VERSION" -- _u_stamp "$envf" "PLASO_VERSION=${target}"
    # plaso is not in the install-function table, so it is always dispatched as
    # an UPGRADE and the generic enable-on-install writeback never fires --
    # leaving modules.plaso.enabled false forever. plaso.py:23-31.
    u_undo_pin plaso
    u_do "enable plaso in config.yaml" -- _pin_module_version plaso "$target"

    # Nothing runs, so there is nothing to probe. The job runner reads the pin
    # fresh per job; no restart is needed.
    u_end plaso none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}
