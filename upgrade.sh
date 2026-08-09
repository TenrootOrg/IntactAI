#!/bin/bash
# Intact.AI — module upgrade, run on the host.
#
#   sudo bash upgrade.sh <tag>
#   sudo bash upgrade.sh --package <file|dir>...
#   sudo bash upgrade.sh --list
#
# THE POINT OF RUNNING ON THE HOST. The previous upgrade engine lived inside
# the backend container and spent most of its 23,000 lines coping with the
# fact that it had to replace the container it was executing in: a two-phase
# handoff, an upgrade_state table that had to survive a restart, a detached
# helper container spawned from the outgoing image, a watchdog, a boot-time
# self-heal, resume counters. None of that protected any data; all of it
# protected the upgrader. Here the backend is just another container, and
# swapping it is `docker compose up -d backend`.
#
# ERROR MODEL. `set -o pipefail`, deliberately NO `set -e` -- the same model
# install.sh uses. A failing step aborts its own module and the loop moves on,
# so one broken module cannot strand the other nine half-upgraded. Failures
# accumulate and there is exactly one exit decision, at the bottom.

set -o pipefail

# Before $LOG_FILE is created, so the log is not world-writable.
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/upgrade_$(date +%Y%m%d_%H%M%S).log"
_ORIG_ARGS=("$@")

# Same root-escalation guard install.sh:56-73 uses: this runs as root and
# sources these files, so a group-writable lib/ is a privilege-escalation
# path. Fix what we can, warn about what we cannot (vboxsf/9p shares ignore
# chmod entirely).
chmod go-w "${BASH_SOURCE[0]}" 2>/dev/null
chmod go-w "${SCRIPT_DIR}/lib/"*.sh "${SCRIPT_DIR}/lib/upgrade/"*.sh 2>/dev/null
for _f in "${SCRIPT_DIR}/lib/"*.sh "${SCRIPT_DIR}/lib/upgrade/"*.sh; do
    [[ -f "$_f" ]] || continue
    if [[ -w "$_f" && "$(stat -c '%a' "$_f" 2>/dev/null)" =~ [2367][0-9]$|[0-9][2367]$ ]]; then
        echo "WARNING: $_f is group- or world-writable and is sourced as root." >&2
    fi
done
unset _f

for _lib in common config docker modules health package release permissions; do
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/${_lib}.sh" || { echo "Cannot source lib/${_lib}.sh" >&2; exit 2; }
done
for _lib in core health plan package args refs modules; do
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/upgrade/${_lib}.sh" || { echo "Cannot source lib/upgrade/${_lib}.sh" >&2; exit 2; }
done
unset _lib

# lib/upgrade/health.sh defines u_probe_module etc.; lib/health.sh defines the
# install-side verify_installation. Both are wanted, and the upgrade one is
# sourced second so its definitions win where the names collide.

main() {
    parse_upgrade_args "${_ORIG_ARGS[@]}"

    touch "$LOG_FILE" 2>/dev/null
    log_info "Intact.AI upgrade — $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Log: ${LOG_FILE}"

    # --------------------------------------------------------------- list ---
    if (( UPGRADE_LIST )); then
        upgrade_list_releases
        return $?
    fi

    # ------------------------------------------------------------ preflight -
    check_root
    check_config

    DOCKER_BIN="$(command -v docker 2>/dev/null)"
    if [[ -z "$DOCKER_BIN" ]]; then
        log_error "docker is not installed. Run install.sh first."
        return 2
    fi
    export DOCKER_BIN
    if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
        log_error "Cannot talk to the Docker daemon."
        return 2
    fi
    if ! "$DOCKER_BIN" compose version >/dev/null 2>&1; then
        log_error "Docker Compose v2 is required (docker compose, not docker-compose)."
        return 2
    fi
    if [[ ! -w "$SCRIPT_DIR" ]]; then
        log_error "${SCRIPT_DIR} is not writable."
        return 2
    fi

    # ------------------------------------------------------- velo-refresh ---
    if (( UPGRADE_VELO_REFRESH_ONLY )); then
        if ! declare -F velo_refresh >/dev/null; then
            log_error "--velo-refresh is not available in this build"
            return 2
        fi
        velo_refresh "${UPGRADE_PACKAGE_DIR:-}"
        return $?
    fi

    # ---------------------------------------------------------- acquire -----
    local assets=()
    if [[ -n "${UPGRADE_PACKAGE_DIR:-}" ]]; then
        # Handed to us already extracted and verified by the stage-0 re-exec.
        UPKG_DIR="$UPGRADE_PACKAGE_DIR"
        UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
        log_info "Using the package extracted by the previous stage: ${UPKG_DIR}"
        upkg_read_manifest || return 2
    else
        if [[ -n "$UPGRADE_TAG" ]]; then
            local dl="${SCRIPT_DIR}/data/tmp/upgrade-dl-${UPGRADE_TAG}"
            log_info "Fetching release ${UPGRADE_TAG} …"
            upgrade_fetch_release "$UPGRADE_TAG" "$dl" || return 2
            upkg_expand_args "$dl" || return 2
        else
            upkg_expand_args "${UPGRADE_PACKAGE_ARGS[@]}" || return 2
        fi
        assets=("${UPKG_ASSETS[@]}")
        upkg_acquire "${assets[@]}" || return 2
    fi

    # -------------------------------------------------------- stage-0 hop ---
    # Hand control to the TARGET release's upgrade.sh, once. The logic that
    # runs is then always the one shipped WITH the version being installed --
    # which is the thing the old two-phase restart dance was straining to
    # achieve from inside a container it was replacing, for ~1,300 lines.
    local target_sh="${UPKG_DIR}/source/intact/upgrade.sh"
    if [[ -z "${INTACT_UPGRADE_REEXEC:-}" && -f "$target_sh" ]]; then
        if ! cmp -s "$target_sh" "${BASH_SOURCE[0]}"; then
            log_info ""
            log_info "This package ships its own upgrade.sh; handing over to it so the"
            log_info "upgrade runs the logic that was tested with ${UPKG_VERSIONS[intact]:-this release}."
            export INTACT_UPGRADE_REEXEC=1
            exec bash "$target_sh" --package-dir "$UPKG_DIR" --log "$LOG_FILE" \
                 "${_ORIG_ARGS[@]}"
        fi
    fi

    # ------------------------------------------------------------- plan -----
    plan_current_versions
    plan_build
    plan_print_table
    plan_reject_downgrades || return 2
    plan_check_disk || return 2

    local work; work="$(plan_work_count)"
    if (( UPGRADE_DRY_RUN )); then
        log_info "--dry-run: ${work} module(s) would be upgraded. Nothing was changed."
        upkg_cleanup
        return 0
    fi
    if (( work == 0 )); then
        log_success "Every module is already at the version this package carries."
        upkg_cleanup
        return 0
    fi

    # ------------------------------------------------------- module loop ----
    log_info ""
    log_info "Upgrading ${work} module(s)…"
    U_STEP_TOTAL="$work"
    U_STEP_N=0

    local m fn
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in
            upgrade|install) ;;
            noop:*)  u_skip "$m" "${PLAN_ACTION[$m]#noop:}"; continue ;;
            skip:*)  u_skip "$m" "${PLAN_ACTION[$m]#skip:}"; continue ;;
            *)       continue ;;
        esac

        fn="upgrade_module_${m}"
        if ! declare -F "$fn" >/dev/null; then
            # Named explicitly rather than skipped quietly: a module in the
            # package with no implementation is a gap in THIS script, and an
            # operator who is not told will believe it upgraded.
            log_error "${m}: no upgrade implementation (${fn}); leaving it at ${PLAN_CURRENT[$m]:-its current version}"
            UPGRADE_FAILED+=("${m} — not implemented in this upgrader")
            continue
        fi

        U_STEP_N=$((U_STEP_N + 1))
        U_FROM="${PLAN_CURRENT[$m]:-not installed}"
        U_TO="${PLAN_TARGET[$m]}"
        "$fn" "${PLAN_TARGET[$m]}"
    done

    # ------------------------------------------------------------ after -----
    if declare -F velo_refresh >/dev/null && [[ " ${UPGRADE_OK[*]} " == *" velociraptor "* ]]; then
        velo_refresh "$UPKG_DIR"
    fi

    refresh_nginx_upstreams
    fix_source_permissions

    print_upgrade_report
    print_final_issues_report
    upkg_cleanup

    return "$(upgrade_exit_code)"
}

main
exit $?
