#!/bin/bash
# Intact.AI upgrade — Ctrl-C / SIGTERM mid-run.
#
# Sibling of core.sh: built entirely on _u_unwind_current and _U_RUNNING_PID,
# both defined there. Split out because signal handling is a distinct
# concern from the four primitives themselves -- core.sh is "what a module
# transaction is", this is "what happens when one gets interrupted".
#
# Call u_install_interrupt_trap once, from scripts/upgrade.sh's main(), after
# the bootstrap and before the module loop.
#
# Without this, Ctrl-C (or a systemd stop, or a killed SSH session) mid-run:
#   1. never unwinds U_UNDO -- whatever the interrupted module had already
#      done (a `compose down`, a stamped .env, a `docker volume rm`) stays
#      exactly where it was, since only u_end's normal failure path ever
#      called the unwind;
#   2. orphans whatever step was running under a `u_do --timeout` deadline --
#      that subshell IS the process this script's own trap-free exit leaves
#      behind, since a plain `exit` does not propagate to background jobs.
#
# A second signal while cleanup is already running is let through to the
# shell default (SIGTERM/SIGINT terminates immediately) rather than trying to
# be clever about an interrupt during an interrupt.
# ---------------------------------------------------------------------------
_U_INTERRUPTED=0
_u_handle_interrupt() {
    (( _U_INTERRUPTED )) && return
    _U_INTERRUPTED=1
    trap - INT TERM

    log_warn ""
    log_warn "Interrupted — cleaning up before exiting."

    if [[ -n "$_U_RUNNING_PID" ]]; then
        log_warn "  stopping the in-flight step (pid ${_U_RUNNING_PID})..."
        kill -TERM "-${_U_RUNNING_PID}" 2>/dev/null
        sleep 2
        kill -KILL "-${_U_RUNNING_PID}" 2>/dev/null
        wait "$_U_RUNNING_PID" 2>/dev/null
        _U_RUNNING_PID=""
    fi

    if [[ -n "$U_MODULE" ]]; then
        U_FAILED=1
        [[ -z "$U_LABEL" ]] && { U_LABEL="interrupted"; U_RC=130; }
        _u_unwind_current
    fi

    print_upgrade_report

    # Reclaim the extraction scratch. Every other exit path in
    # scripts/upgrade.sh calls upkg_cleanup; this one did not, so an
    # interrupted run left its extracted package behind until
    # upkg_sweep_stale_scratch's 48-hour pass -- and a full release extracts to
    # about 15 GB. Two cancelled upgrades were enough to take a 148 GB
    # appliance from 68 GB free to 4 GB and make the NEXT upgrade fail its own
    # disk precheck with "Not enough disk", which is a confusing way to
    # discover that Stop leaks. Observed exactly that way.
    #
    # After the unwind, deliberately: the rollback steps above may still need
    # what was extracted. Guarded because this file is sourced on its own in
    # tests, where package.sh's functions are not present.
    if declare -F upkg_cleanup >/dev/null 2>&1; then
        upkg_cleanup
    fi

    log_error "Upgrade interrupted (exit 130)."
    exit 130
}

u_install_interrupt_trap() {
    trap _u_handle_interrupt INT TERM
}

# ---------------------------------------------------------------------------
# _u_exit_cleanup — the other half of the leak the comment above describes.
#
# INT and TERM were covered; a plain `return 2` was not. Three refusals sit
# between extraction and the module loop -- plan_reject_downgrades,
# plan_check_disk and _u_preflight_images -- and each returned straight out
# without calling upkg_cleanup. The disk one is the perverse case: it refuses
# for want of space and then leaves ~15 GB of extraction on the very
# filesystem it just measured, so the next attempt is refused harder.
#
# Registered as an EXIT trap rather than fixing three call sites, so a fourth
# refusal added later cannot reintroduce the leak. Safe to register after the
# stage-0 hop because `exec` does not run EXIT traps -- the handing-over
# process must not clean up scratch the new one is about to read.
#
# U_KEEP_SCRATCH is set by any failed image load. Then the extraction is
# EVIDENCE and a retry input, not garbage: the images already loaded are in
# the docker store, their tars are gone, and re-running against the surviving
# tree skips both the download and the checksum pass.
# ---------------------------------------------------------------------------
_u_exit_cleanup() {
    local rc=$?
    trap - EXIT
    if [[ "${U_KEEP_SCRATCH:-0}" == "1" ]]; then
        log_warn "  an image failed to load — keeping the extracted package for a retry:"
        log_warn "    ${UPKG_DIR:-?}"
        log_warn "    sudo bash ${SCRIPT_DIR}/scripts/upgrade.sh --package-dir ${UPKG_DIR:-?} --root ${SCRIPT_DIR}"
        log_warn "    (swept automatically after 48h)"
    elif declare -F upkg_cleanup >/dev/null 2>&1; then
        upkg_cleanup
    fi
    return $rc
}

u_install_exit_cleanup_trap() {
    trap _u_exit_cleanup EXIT
}
