#!/bin/bash
# Intact.AI upgrade — Presidio (PII NER for report masking). No container of its
# own between uses: the backend `docker run`s the pinned image on demand and it
# stops itself when idle, like plaso. Always installed -- there is no
# modules.presidio flag -- so a box upgrading from a release that predates it is
# planned as an INSTALL and lands here the same way.

upgrade_module_presidio() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin presidio
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 1800 "ensure intact-presidio:${target}" -- \
        _u_ensure_image "intact-presidio:${target}" "intact-presidio-${target}.tar"
    # The backend reads the pin fresh per masking call (config.get_presidio_image),
    # so no restart is needed. config.yaml gets it too, so the next install or
    # env regeneration keeps the same version.
    u_do "stamp PRESIDIO_VERSION" -- _u_stamp "$envf" "PRESIDIO_VERSION=${target}"
    u_undo_pin presidio
    u_do "pin versions.presidio in config.yaml" -- _pin_module_version presidio "$target"

    u_end presidio none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}
