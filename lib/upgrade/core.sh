#!/bin/bash
# Intact.AI upgrade — the four primitives.
#
# Every module upgrade in lib/upgrade/*.sh is written as a flat list of
# u_do calls bracketed by u_begin/u_end. Nothing else in the upgrade path
# implements retry, rollback, health-checking or failure accounting; if you
# find yourself writing an `if ! ...; then rollback; fi` inside a module,
# that is the signal something belongs here instead.
#
#   u_begin <module>                       open a transaction
#   u_do [--timeout N] <label> -- <cmd...> a guarded step
#   u_undo <command string>                push onto the LIFO rollback stack
#   u_end <module> [policy] [timeout]      health gate, then commit or unwind
#
# WHY THIS SHAPE. The Python engine hand-rolled the same try/except/rollback
# body in ten places, averaging ~130 lines each, and they drifted: elk and
# iris restore .env, velociraptor restores .env and the binary but silently
# not the configs, volweb never rolls back at all, portainer has no health
# policy so it can never roll back even when it should. Centralising the
# shape is the point -- a module author cannot forget to restore something,
# because restoring is a stack they push onto rather than a block they
# remember to write.
#
# ERROR MODEL. Inherited verbatim from install.sh: `set -o pipefail`, no
# `set -e`, no `set -u` at the top level. Failures accumulate into arrays and
# there is exactly ONE exit decision, at the very end of upgrade.sh. A step
# failing never aborts the run; it aborts its own module and the loop moves
# on, so one broken module cannot strand the other nine half-upgraded.

# ---------------------------------------------------------------------------
# Per-transaction state. Reset by u_begin, consumed by u_end.
# ---------------------------------------------------------------------------
U_MODULE=""      # module id whose transaction is currently open
U_FAILED=0       # 1 once ANY u_do in this transaction has failed
U_LABEL=""       # label of the FIRST failure; later ones never overwrite it
U_RC=0           # that first failure's exit code
U_DETAIL=""      # what it appended to $LOG_FILE, trimmed to 5 lines
U_UNDO=()        # LIFO stack of rollback command strings
U_FROM=""        # version we are coming from (banner + rollback message)
U_TO=""          # version we are going to
U_STEP_N=0       # position in the module loop, for the banner
U_STEP_TOTAL=0

# ---------------------------------------------------------------------------
# Process-wide accumulators. Never reset; the exit code is derived from them.
# ---------------------------------------------------------------------------
UPGRADE_OK=()            # committed cleanly, health verdict 'up'
UPGRADE_DEGRADED=()      # committed, but health was 'degraded' (or 'down' under
                         # a 'report' policy) — the box works, something is off
UPGRADE_ROLLED_BACK=()   # failed, unwind SUCCEEDED, box is back on the old version
UPGRADE_FAILED=()        # failed AND the unwind also failed — needs a human
UPGRADE_SKIPPED=()       # disabled, already at target, or excluded by --only/--skip

# ---------------------------------------------------------------------------
# u_begin <module>
# ---------------------------------------------------------------------------
u_begin() {
    U_MODULE="$1"
    U_FAILED=0
    U_LABEL=""
    U_RC=0
    U_DETAIL=""
    U_UNDO=()

    local from="${U_FROM:-unknown}" to="${U_TO:-unknown}"
    local pos=""
    [[ "${U_STEP_TOTAL:-0}" -gt 0 ]] && pos="[${U_STEP_N}/${U_STEP_TOTAL}] "

    log_info ""
    log_info "=================================================================="
    log_info "${pos}$(printf '%s' "$U_MODULE" | tr '[:lower:]' '[:upper:]'): ${from} -> ${to}"
    log_info "=================================================================="
    return 0
}

# ---------------------------------------------------------------------------
# u_do [--timeout N] <label> -- <cmd> [args...]
#
# Returns 0 on success, 1 on failure or short-circuit. NEVER exits.
#
# The short-circuit is what makes module bodies flat. Once the transaction
# has failed, every subsequent u_do is a no-op returning 1, so a module can
# be a bare list of steps with no `if`, no `&&` chaining and no early return
# -- and, crucially, no path by which step 7 runs after step 3 blew up.
# ---------------------------------------------------------------------------
u_do() {
    local timeout=""
    if [[ "${1:-}" == "--timeout" ]]; then
        timeout="$2"
        shift 2
    fi
    local label="$1"; shift
    [[ "${1:-}" == "--" ]] && shift

    if (( U_FAILED )); then
        log_info "  skipped (transaction already failed): ${label}"
        return 1
    fi

    # Byte offset into the log BEFORE the step runs, so failure detail is
    # exactly what this step emitted rather than a blind `tail`. Same trick
    # run_compose_up_with_retry uses to classify compose failures
    # (lib/modules.sh:699) -- with concurrent heartbeat writes to the same
    # file, an offset is the only way to attribute output to a step.
    local marker=0
    [[ -n "${LOG_FILE:-}" && -f "${LOG_FILE}" ]] && marker="$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)"

    local rc=0
    if [[ -n "$timeout" ]]; then
        RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "$label" "$timeout" "$@"
        rc=$?
    else
        "$@"
        rc=$?
    fi

    if (( rc == 0 )); then
        if [[ -n "$timeout" && -n "${RUN_HEARTBEAT_ELAPSED:-}" ]]; then
            log_info "  ok: ${label} (${RUN_HEARTBEAT_ELAPSED}s)"
        else
            log_info "  ok: ${label}"
        fi
        return 0
    fi

    U_FAILED=1
    U_LABEL="$label"
    U_RC=$rc

    if [[ -n "${LOG_FILE:-}" && -f "${LOG_FILE}" ]]; then
        U_DETAIL="$(tail -c "+$((marker + 1))" "$LOG_FILE" 2>/dev/null \
                    | grep -v '^[[:space:]]*$' | tail -5)"
    fi

    if (( rc == 124 )); then
        log_error "${U_MODULE}: step '${label}' TIMED OUT after ${timeout}s"
    else
        log_error "${U_MODULE}: step '${label}' failed (rc=${rc})"
    fi
    if [[ -n "$U_DETAIL" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_error "    | ${line}"
        done <<< "$U_DETAIL"
    fi
    return 1
}

# ---------------------------------------------------------------------------
# u_undo <command string...>
#
# THE ONE DISCIPLINE RULE: the stack unwinds LIFO, so register the coarsest,
# last-resort action FIRST (it runs last), and register a fine-grained undo
# only AFTER the forward action that made the change has succeeded.
#
# In practice every module opens with:
#     u_undo "_compose_up_old <module>"          # runs LAST
#     u_undo "restore_file_from_backup <env> <bak>"
# because the bring-up has to happen after the files are back, and it has to
# be registered before the first `compose down` so that a failure during the
# down is still recoverable.
#
# The command is stored as a string and later `eval`ed. Callers must quote
# any path that could contain spaces at registration time.
# ---------------------------------------------------------------------------
u_undo() {
    U_UNDO+=("$*")
    log_info "  rollback registered: $*"
    return 0
}

# ---------------------------------------------------------------------------
# u_end <module> [policy] [timeout]
#
# policy: rollback (default) | report | none
#   rollback  a 'down' verdict fails the transaction and unwinds
#   report    a 'down' verdict is recorded loudly but the module stays applied
#   none      no health probe at all (plaso, aws_sigma, o365rc — nothing runs)
#
# THE HONESTY INVARIANT: this function is the only thing that may append to
# UPGRADE_OK, and it never does so on a timeout or an unreachable probe.
#
# That is a deliberate break from the install path, where the pattern is
# `wait_for_condition` returns 1, the caller log_warns, and then calls
# track_module_success anyway (lib/modules.sh:1318-1322, lib/health.sh:161-175)
# -- so a module that never came up is reported as installed. The upgrade path
# never calls track_module_success at all, which makes that outcome structurally
# unreachable rather than merely discouraged.
# ---------------------------------------------------------------------------
u_end() {
    local module="$1"
    local policy="${2:-rollback}"
    local timeout="${3:-150}"

    # 'up' is the default so that policy=none (plaso, aws_sigma, o365rc — no
    # service to probe) commits cleanly rather than being reported as an
    # unverified module.
    local verdict="up"

    # ---- health gate ------------------------------------------------------
    if (( ! U_FAILED )) && [[ "$policy" != "none" ]]; then
        local detail probe_out
        probe_out="$(u_probe_module "$module" "$timeout")"
        verdict="${probe_out%% *}"
        detail="${probe_out#* }"
        [[ "$detail" == "$verdict" ]] && detail=""

        case "$verdict" in
            up)
                log_success "  health: ${module} is UP${detail:+ (${detail})}"
                ;;
            degraded)
                log_warn "  health: ${module} is DEGRADED${detail:+ (${detail})} — not rolling back"
                UPGRADE_DEGRADED+=("${module} — degraded${detail:+: ${detail}}")
                ;;
            down|*)
                if [[ "$policy" == "rollback" ]]; then
                    U_FAILED=1
                    U_LABEL="health gate"
                    U_RC=1
                    U_DETAIL="$detail"
                    log_error "  health: ${module} is DOWN${detail:+ (${detail})} — rolling back"
                else
                    log_error "  health: ${module} is DOWN${detail:+ (${detail})} — policy is 'report', NOT rolling back"
                    UPGRADE_DEGRADED+=("${module} — DOWN${detail:+: ${detail}}")
                fi
                ;;
        esac

        if [[ "$verdict" != "up" ]]; then
            # shellcheck disable=SC2046
            capture_diagnostic_logs "${module} health gate" $(u_containers_of "$module")
        fi
    fi

    # ---- commit -----------------------------------------------------------
    if (( ! U_FAILED )); then
        # A degraded module is committed but is NOT a clean success. It has
        # already been recorded in UPGRADE_DEGRADED above; adding it to
        # UPGRADE_OK as well would list it twice in the report -- once as
        # "✔ upgraded" and once as "! degraded" -- which is exactly the
        # mixed signal the three-verdict gate exists to avoid.
        if [[ "$verdict" == "up" ]]; then
            UPGRADE_OK+=("${module} ${U_FROM:-?} -> ${U_TO:-?}")
            log_success "${module}: upgraded to ${U_TO:-?}"
        else
            log_warn "${module}: applied ${U_FROM:-?} -> ${U_TO:-?}, but the health gate said ${verdict}"
        fi
        U_UNDO=()
        U_MODULE=""
        return 0
    fi

    # ---- unwind -----------------------------------------------------------
    log_warn "${module}: rolling back (${U_LABEL}, rc=${U_RC})"
    local i undo_failed=0
    for (( i = ${#U_UNDO[@]} - 1; i >= 0; i-- )); do
        log_info "  undo: ${U_UNDO[$i]}"
        if ! eval "${U_UNDO[$i]}" >>"${LOG_FILE:-/dev/null}" 2>&1; then
            log_error "  undo FAILED: ${U_UNDO[$i]}"
            undo_failed=1
        fi
    done

    if (( undo_failed )); then
        # The distinction between these two arrays is the whole point of
        # tracking the unwind result: "we put it back" and "we could not put
        # it back" are different operator situations, and collapsing them
        # into one FAILED list is how a half-rolled-back module gets missed.
        UPGRADE_FAILED+=("${module} — ${U_LABEL} (rc=${U_RC}) AND ROLLBACK FAILED; needs manual repair")
        log_error "${module}: ROLLBACK FAILED — this module needs manual repair"
    else
        UPGRADE_ROLLED_BACK+=("${module} — ${U_LABEL} (rc=${U_RC}); restored to ${U_FROM:-previous version}")
        log_warn "${module}: rolled back to ${U_FROM:-the previous version}"
    fi

    U_UNDO=()
    U_MODULE=""
    return 1
}

# ---------------------------------------------------------------------------
# u_skip <module> <reason>
# ---------------------------------------------------------------------------
u_skip() {
    UPGRADE_SKIPPED+=("$1 — $2")
    log_info "$1: SKIPPED ($2)"
    return 0
}

# ---------------------------------------------------------------------------
# Small shared helpers the module files lean on.
# ---------------------------------------------------------------------------

# Snapshot a file so an undo can put it back. Echoes the backup path; echoes
# nothing and returns 1 if the source does not exist, so a caller can tell
# "backed up" from "there was nothing to back up" without a stat of its own.
backup_file_for_rollback() {
    local src="$1"
    [[ -f "$src" ]] || return 1
    local bak="${src}.upgrade-bak-$(date +%Y%m%d_%H%M%S)"
    if cp -p "$src" "$bak" 2>/dev/null; then
        echo "$bak"
        return 0
    fi
    log_warn "could not back up ${src}"
    return 1
}

# Restore, preserving the destination inode. `cp` onto the existing path
# rather than `mv` for the same reason _pin_module_version truncates in
# place: .env files are bind-mount and env_file sources, and swapping the
# inode under a running container is a change that appears to work.
restore_file_from_backup() {
    local dst="$1" bak="$2"
    [[ -f "$bak" ]] || { log_warn "no backup at ${bak} to restore"; return 1; }
    cp -p --no-preserve=mode "$bak" "$dst" 2>/dev/null || cp "$bak" "$dst" || return 1
    return 0
}

# Drop a backup once the transaction has committed. Best-effort by design:
# a leftover .upgrade-bak-* is harmless clutter, and failing an otherwise
# successful upgrade over an unlink error would be absurd.
discard_backup() {
    [[ -n "${1:-}" && -f "$1" ]] && rm -f "$1"
    return 0
}

sha256_of() {
    [[ -f "${1:-}" ]] || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# Read one KEY from a .env-style file. Returns 1 (and echoes nothing) when the
# key is absent, so callers can distinguish "unset" from "set to empty".
read_env_var() {
    local file="$1" key="$2" line
    [[ -f "$file" ]] || return 1
    line="$(grep -m1 -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null)" || return 1
    [[ -n "$line" ]] || return 1
    line="${line#*=}"
    # strip one layer of surrounding quotes, if present
    line="${line%\"}"; line="${line#\"}"
    line="${line%\'}"; line="${line#\'}"
    echo "$line"
    return 0
}

# ---------------------------------------------------------------------------
# The final report + the single exit decision.
#
# Exit codes:
#   0  everything committed, every gate 'up'
#   1  at least one module rolled back or failed
#   2  refused before touching anything (set by the caller, not here)
#   3  everything committed but at least one module degraded
# ---------------------------------------------------------------------------
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
        log_warn "Rolled back (${#UPGRADE_ROLLED_BACK[@]}) — these are back on their previous version:"
        for item in "${UPGRADE_ROLLED_BACK[@]}"; do log_warn "  ↩ ${item}"; done
    fi
    if (( ${#UPGRADE_FAILED[@]} )); then
        log_error "NEEDS MANUAL REPAIR (${#UPGRADE_FAILED[@]}):"
        for item in "${UPGRADE_FAILED[@]}"; do log_error "  ✘ ${item}"; done
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
