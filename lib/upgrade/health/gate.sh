#!/bin/bash
# Intact.AI upgrade — u_post_upgrade_gate: observe whether the platform is
# ACTUALLY serving, after every module has already committed via u_end.
#
# u_end's own probe (core.sh's u_probe_module) checks its module in
# isolation, right after that module's own swap. It cannot see a container a
# LATER step leaves in `created` (compose recreated it but the start never
# happened), nor a crash-loop that starts moments after u_end's probe window
# already closed. Both are real failure shapes the Python engine this
# replaced was written to catch after shipping a run that reported
# "completed, 0 errors" while intact_tusd sat in `created` and uploads were
# dead until an operator ran `docker start` by hand.
#
# STRICTLY OBSERVATIONAL. Never fails a run, never rolls anything back, never
# touches UPGRADE_OK/UPGRADE_DEGRADED -- u_end is still the only thing that
# may commit those. The worst this does is add a line to
# INSTALL_WARNINGS/INSTALL_ERRORS, which print_final_issues_report already
# prints; today those arrays are never populated on the upgrade path at all.
#
# Scoped to containers of modules THIS RUN attempted (upgrade or install
# action) rather than every intact_* container on the box: a module nobody
# touched crash-looping for an unrelated reason is a real fact worth an
# operator's attention, but it is not evidence about THIS upgrade, and
# blaming it here would be exactly the false attribution this exists to
# avoid, not commit.
u_post_upgrade_gate() {
    local touched=() m c state
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in
            upgrade|install) touched+=("$m") ;;
        esac
    done
    (( ${#touched[@]} )) || return 0

    log_info ""
    log_info "Post-upgrade check..."
    local checked=0
    for m in "${touched[@]}"; do
        for c in $(u_containers_of "$m"); do
            state="$(_u_container_state "$c")"
            [[ "$state" == "absent" ]] && continue
            checked=$((checked + 1))
            case "$state" in
                created)
                    log_warn "  ${c} is created but was never started — starting it now"
                    "${DOCKER_BIN:-docker}" start "$c" >/dev/null 2>&1
                    sleep 2
                    state="$(_u_container_state "$c")"
                    if [[ "$state" == "running" ]]; then
                        log_success "  ${c} is now running"
                    else
                        INSTALL_ERRORS+=("${c} was left in 'created' after the upgrade and would not start (now ${state})")
                    fi
                    ;;
                restarting)
                    INSTALL_ERRORS+=("${c} is crash-looping after the upgrade")
                    ;;
                exited)
                    local rc
                    rc="$("${DOCKER_BIN:-docker}" inspect -f '{{.State.ExitCode}}' "$c" 2>/dev/null)"
                    [[ -n "$rc" && "$rc" != "0" ]] && \
                        INSTALL_WARNINGS+=("${c} exited with code ${rc} after the upgrade")
                    ;;
            esac
        done
    done
    log_info "  ${checked} container(s) checked"

    # The backend image tag: config.yaml's versions.backend / the stamped
    # VERSION file is what every later boot resolves its image from (see
    # scripts/ci/build_release_package.py's self-check for the same class of
    # bug on the BUILD side -- a bundled image baked under the wrong tag is
    # invisible to the box that is supposed to load it). If the running
    # container is on a different tag than the plan says it upgraded to,
    # every per-step claim the intact module made about itself was true and
    # the platform is still wrong underneath them.
    local committed=0 e
    for e in "${UPGRADE_OK[@]}" "${UPGRADE_DEGRADED[@]}"; do
        [[ "$e" == "intact "* ]] && { committed=1; break; }
    done
    if (( committed )) && [[ -n "${PLAN_TARGET[intact]:-}" ]]; then
        local running_image want_image
        running_image="$("${DOCKER_BIN:-docker}" inspect -f '{{.Config.Image}}' intact_backend 2>/dev/null)"
        want_image="intact-backend:${PLAN_TARGET[intact]}"
        if [[ -n "$running_image" && "$running_image" != "$want_image" ]]; then
            INSTALL_ERRORS+=("intact_backend is running ${running_image}, expected ${want_image} — the backend did not actually swap")
        fi
    fi
    return 0
}
