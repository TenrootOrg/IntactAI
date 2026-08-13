#!/bin/bash
# Intact.AI upgrade — the final report + the single exit decision.
#
# Exit codes:
#   0  everything committed, every gate 'up'
#   1  at least one module rolled back or failed
#   2  refused before touching anything (set by the caller, not here)
#   3  everything committed but at least one module degraded

print_upgrade_report() {
    local item
    log_info ""
    log_info "=================================================================="
    log_info "Upgrade report"
    log_info "=================================================================="

    if (( ${#UPGRADE_OK[@]} )); then
        log_success "Upgraded (${#UPGRADE_OK[@]}):"
        for item in "${UPGRADE_OK[@]}"; do log_success "  ✔ ${item}"; done
    fi
    if (( ${#UPGRADE_SKIPPED[@]} )); then
        log_info "Skipped (${#UPGRADE_SKIPPED[@]}):"
        for item in "${UPGRADE_SKIPPED[@]}"; do log_info "  · ${item}"; done
    fi
    if (( ${#UPGRADE_DEGRADED[@]} )); then
        log_warn "Applied but degraded (${#UPGRADE_DEGRADED[@]}):"
        for item in "${UPGRADE_DEGRADED[@]}"; do log_warn "  ! ${item}"; done
    fi
    if (( ${#UPGRADE_ROLLED_BACK[@]} )); then
        # "back on their previous version" is only true for an upgrade. A
        # failed INSTALL has no previous version and is undone, not restored --
        # each entry says which, so the heading stays neutral rather than
        # contradicting the line beneath it.
        log_warn "Rolled back (${#UPGRADE_ROLLED_BACK[@]}) — undone, the box is as it was:"
        for item in "${UPGRADE_ROLLED_BACK[@]}"; do log_warn "  ↩ ${item}"; done
    fi
    if (( ${#UPGRADE_FAILED[@]} )); then
        log_error "NEEDS MANUAL REPAIR (${#UPGRADE_FAILED[@]}):"
        for item in "${UPGRADE_FAILED[@]}"; do log_error "  ✘ ${item}"; done
    fi

    # Make the freeing visible. Silent reclamation is indistinguishable from
    # no reclamation in a support bundle, and this number is the whole point of
    # upkg_release_loaded_tar -- if it ever reads 0B on a real package, the
    # scratch guard is refusing every path and nobody would otherwise notice.
    if (( ${U_TARS_FREED:-0} > 0 )); then
        log_info "Reclaimed $(_human_size "${U_TARS_FREED}") of image tars as they loaded"
    fi

    if (( ${#UPGRADE_OK[@]} == 0 && ${#UPGRADE_DEGRADED[@]} == 0 \
          && ${#UPGRADE_ROLLED_BACK[@]} == 0 && ${#UPGRADE_FAILED[@]} == 0 )); then
        log_info "Nothing to do — every module was already at its target version."
    fi
    [[ -n "${LOG_FILE:-}" ]] && log_info "Full log: ${LOG_FILE}"
    return 0
}

upgrade_exit_code() {
    if (( ${#UPGRADE_FAILED[@]} || ${#UPGRADE_ROLLED_BACK[@]} )); then
        echo 1
    elif (( ${#UPGRADE_DEGRADED[@]} )); then
        echo 3
    else
        echo 0
    fi
}
