#!/bin/bash
# Intact.AI upgrade — DFIR-O365RC. No container of its own.

upgrade_module_o365rc() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin o365rc
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 1800 "ensure dfir-o365rc:${target}" -- \
        _u_ensure_image "anssi/dfir-o365rc:${target}" "o365rc-${target}.tar"
    u_do "stamp DFIR_O365RC_VERSION" -- _u_stamp "$envf" "DFIR_O365RC_VERSION=${target}"

    u_end o365rc none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}
