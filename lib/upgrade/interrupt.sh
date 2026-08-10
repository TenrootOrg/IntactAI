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
    log_error "Upgrade interrupted (exit 130)."
    exit 130
}

u_install_interrupt_trap() {
    trap _u_handle_interrupt INT TERM
}
