#!/bin/bash
# Intact.AI — module upgrade, run on the host.
#
#   sudo bash scripts/upgrade.sh <tag>
#   sudo bash scripts/upgrade.sh --package <file|dir>...
#   sudo bash scripts/upgrade.sh --list
#
# STANDALONE BY DESIGN. Nothing here talks to the backend, the dashboard or
# any API. It needs a shell, docker, and this checkout -- so it works on a box
# whose backend is stopped, crash-looping, or not installed at all, which is
# exactly when an operator most needs to upgrade. The only mention of
# intact_backend anywhere in lib/upgrade/ is as the health probe for the
# `intact` module itself.
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

# This file is bash, not POSIX sh: arrays, [[ ]], local, ${BASH_SOURCE[0]}.
# `sh scripts/upgrade.sh` would otherwise die somewhere in the middle with a
# baffling syntax error instead of at the top with a reason. Re-exec rather
# than refuse, because typing `sh` is a habit, not a decision.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

set -o pipefail

# Before $LOG_FILE is created, so the log is not world-writable.
umask 022

# ---------------------------------------------------------------------------
# Locate the CODE (this checkout, or an extracted release tree the stage-0
# hop below handed control to) and, separately, the APPLIANCE it will act on.
#
# These are the SAME directory for every operator invocation -- someone runs
# `sudo bash scripts/upgrade.sh <tag>` sitting inside their own install. They
# are DIFFERENT exactly once: after the hop, when this process is running the
# TARGET release's upgrade.sh out of an extracted package under
# data/tmp/upgrade-pkg-*/source/intact/, but must still read config.yaml,
# stamp .env files and swap containers on the REAL appliance. Conflating the
# two there was the bug: the hop used to compute one directory from
# ${BASH_SOURCE[0]}, which after `exec` pointed at the package scratch tree,
# and everything downstream -- config.yaml, .env stamping, permission fixes,
# cleanup -- silently ran against THAT instead of the appliance. The run
# reported success and touched nothing real.
#
# `dirname "$0"` alone handles neither directory nor symlinks, and
# `readlink -f` is GNU-only, so the symlink chain is walked by hand --
# resolving each link relative to the directory it lives in, which is what a
# relative symlink target means. `ln -s .../scripts/upgrade.sh
# /usr/local/bin/intact-upgrade` is the obvious thing to do once this is the
# documented entry point.
# ---------------------------------------------------------------------------
_self="${BASH_SOURCE[0]}"
while [ -L "$_self" ]; do
    _link_dir="$(cd -P "$(dirname "$_self")" && pwd)"
    _self="$(readlink "$_self")"
    case "$_self" in
        /*) ;;                       # absolute target: use as-is
        *)  _self="${_link_dir}/${_self}" ;;
    esac
done
_CODE_DIR="$(cd -P "$(dirname "$_self")/.." && pwd)"
unset _self _link_dir

_ORIG_ARGS=("$@")

# The APPLIANCE root: --root wins (this is what the stage-0 hop passes),
# then $INTACT_PATH (install.sh's own convention for "where is the
# appliance"), then default to the code's own location -- the normal case,
# where an operator runs this script from inside their install. A lightweight
# scan rather than the real arg parser: UPGRADE_ORDER and the rest of
# args.sh's machinery are not sourced yet, and --root has to be known before
# we can even find lib/upgrade/core.sh to source it FROM the appliance if
# --root also happens to equal _CODE_DIR (the common case).
SCRIPT_DIR=""
_scan=("$@")
while [ ${#_scan[@]} -gt 0 ]; do
    case "${_scan[0]}" in
        --root)   SCRIPT_DIR="${_scan[1]:-}"; break ;;
        --root=*) SCRIPT_DIR="${_scan[0]#*=}"; break ;;
        *)        _scan=("${_scan[@]:1}") ;;
    esac
done
unset _scan
if [ -z "$SCRIPT_DIR" ]; then
    SCRIPT_DIR="${INTACT_PATH:-$_CODE_DIR}"
fi
[ -d "$SCRIPT_DIR" ] && SCRIPT_DIR="$(cd -P "$SCRIPT_DIR" && pwd)"

# Fail here, with the path we resolved, rather than 200 lines later with
# "cannot source lib/common.sh". Someone who copied one file out of the repo
# gets told that is what happened. Checked BEFORE the appliance-root probe
# below: without working code there is nothing that could even report the
# second problem.
for _need in lib/common.sh lib/upgrade/core.sh; do
    if [ ! -e "${_CODE_DIR}/${_need}" ]; then
        echo "This does not look like an Intact.AI checkout:" >&2
        echo "  resolved root: ${_CODE_DIR}" >&2
        echo "  missing:       ${_need}" >&2
        echo >&2
        echo "upgrade.sh runs from inside the appliance's checkout — it reads" >&2
        echo "lib/, modules/ and config.yaml from there. Copying the single" >&2
        echo "file somewhere else will not work; run it in place:" >&2
        echo "  sudo bash /path/to/intact/scripts/upgrade.sh --help" >&2
        exit 2
    fi
done
unset _need

# The APPLIANCE this run will actually modify -- distinct from the code probe
# above whenever --root/$INTACT_PATH points somewhere else (the hop).
for _need in install.sh config.yaml modules; do
    if [ ! -e "${SCRIPT_DIR}/${_need}" ]; then
        echo "This does not look like an Intact.AI appliance:" >&2
        echo "  resolved root: ${SCRIPT_DIR}" >&2
        echo "  missing:       ${_need}" >&2
        echo >&2
        if [ "$SCRIPT_DIR" = "$_CODE_DIR" ]; then
            echo "upgrade.sh runs from inside the appliance's checkout — it reads" >&2
            echo "lib/, modules/ and config.yaml from there. Copying the single" >&2
            echo "file somewhere else will not work; run it in place:" >&2
            echo "  sudo bash /path/to/intact/scripts/upgrade.sh --help" >&2
        else
            echo "Running the code at ${_CODE_DIR} against --root ${SCRIPT_DIR}," >&2
            echo "and that path is not an Intact.AI appliance -- it needs its own" >&2
            echo "config.yaml and modules/, not this release's." >&2
        fi
        exit 2
    fi
done
unset _need

CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/upgrade_$(date +%Y%m%d_%H%M%S).log"

# Same root-escalation guard install.sh:56-73 uses: this runs as root and
# sources these files, so a group-writable lib/ is a privilege-escalation
# path. Fix what we can, warn about what we cannot (vboxsf/9p shares ignore
# chmod entirely). Against _CODE_DIR: these are the files about to be
# sourced, which after the hop live under the extracted package, not
# necessarily under the appliance root.
chmod go-w "${BASH_SOURCE[0]}" 2>/dev/null
while IFS= read -r -d '' _f; do
    chmod go-w "$_f" 2>/dev/null
done < <(find "${_CODE_DIR}/lib" -name '*.sh' -print0 2>/dev/null)
while IFS= read -r -d '' _f; do
    if [[ -w "$_f" && "$(stat -c '%a' "$_f" 2>/dev/null)" =~ [2367][0-9]$|[0-9][2367]$ ]]; then
        echo "WARNING: $_f is group- or world-writable and is sourced as root." >&2
    fi
done < <(find "${_CODE_DIR}/lib" -name '*.sh' -print0 2>/dev/null)
unset _f

for _lib in common config docker health package release permissions state_registry; do
    # shellcheck source=/dev/null
    source "${_CODE_DIR}/lib/${_lib}.sh" || { echo "Cannot source lib/${_lib}.sh" >&2; exit 2; }
done
# install.sh's per-module deploy_* functions: the upgrade path's "install"
# case (a module enabled but never before deployed) calls straight into
# these -- generate_iris_secrets, render_volweb_env_template,
# render_timesketch_conf_templates, create_timesketch_admin_user,
# enforce_iris_admin_password, preflight_host_check -- so every module file
# is sourced here too, not just the ones known to be needed today.
for _lib in shared elk timesketch velociraptor iris portainer volweb backend nginx orchestrator; do
    # shellcheck source=/dev/null
    source "${_CODE_DIR}/lib/modules/${_lib}.sh" || { echo "Cannot source lib/modules/${_lib}.sh" >&2; exit 2; }
done
for _lib in core interrupt helpers report health/core health/probes health/gate \
            plan package args refs \
            modules/shared modules/elk modules/iris modules/portainer modules/volweb \
            modules/plaso modules/aws_sigma modules/o365rc \
            timesketch/postgres timesketch/schema timesketch/health timesketch/timesketch \
            velociraptor/snapshot velociraptor/image velociraptor/velociraptor velo_refresh \
            intact/config intact/tree intact/assets intact/image intact/intact \
            hostdeps; do
    # shellcheck source=/dev/null
    source "${_CODE_DIR}/lib/upgrade/${_lib}.sh" || { echo "Cannot source lib/upgrade/${_lib}.sh" >&2; exit 2; }
done
unset _lib

# lib/upgrade/health.sh defines u_probe_module etc.; lib/health.sh defines the
# install-side verify_installation. Both are wanted, and the upgrade one is
# sourced second so its definitions win where the names collide.

main() {
    parse_upgrade_args "${_ORIG_ARGS[@]}"

    # The log lives beside install_*.log in the checkout. A non-root caller
    # running --list or --help on a root-owned checkout cannot create it, and
    # without this every single log_* line would emit its own "Permission
    # denied" to stderr. Fall back rather than fail: the read-only commands
    # have no reason to need a writable repo.
    if ! touch "$LOG_FILE" 2>/dev/null; then
        LOG_FILE="$(mktemp -t intact-upgrade-XXXXXX.log 2>/dev/null)" || LOG_FILE=/dev/null
    fi
    log_info "Intact.AI upgrade — $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Log: ${LOG_FILE}"

    # --------------------------------------------------------------- list ---
    if (( UPGRADE_LIST )); then
        upgrade_list_releases
        return $?
    fi

    # ------------------------------------------------------------ preflight -
    # Everything past here mutates the appliance, so root is required. Said
    # with the actual command to run: `check_root` alone prints "must be run
    # as root", which is true and unhelpful at 3am.
    #
    # --plan is exempt, for the same reason --list above it is: it fetches a
    # ~0.2 MB manifest, reads .env files and inspects containers, and changes
    # nothing. Requiring root for it contradicted both its own comment below
    # ("nothing here changes the appliance") and docs/UPGRADE.md's promise that
    # the read-only modes do not need root -- and it made the cheap "what would
    # this upgrade do?" question the one thing an operator could not ask
    # without sudo. It still runs the docker checks underneath, so a caller
    # with no docker access gets "Cannot talk to the Docker daemon" rather than
    # a misleading demand for root.
    if [[ "${EUID:-$(id -u)}" -ne 0 && -z "${UPGRADE_PLAN_TAG:-}" ]]; then
        log_error "This needs root — it stops containers, writes module .env files and loads images."
        # _CODE_DIR, not SCRIPT_DIR: the operator should re-run THIS script
        # (the one that just ran), and after the hop those differ.
        log_error "  sudo bash ${_CODE_DIR}/scripts/upgrade.sh ${_ORIG_ARGS[*]}"
        return 2
    fi
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
    check_docker_min_version   # advisory only (lib/common.sh); never blocks

    # ---------------------------------------------------------------- plan --
    # Read-only: no lock, no interrupt trap, no writability check below --
    # nothing here changes the appliance, so none of that machinery applies.
    # Needs docker (plan_current_versions inspects running containers to
    # confirm a pin actually matches what is up, not just what .env claims),
    # which is why this sits after the docker checks above rather than beside
    # --list, which needs neither docker nor GitHub beyond the release list.
    if [[ -n "${UPGRADE_PLAN_TAG:-}" ]]; then
        local plan_mf="${SCRIPT_DIR}/data/tmp/upgrade-plan-${UPGRADE_PLAN_TAG}.manifest.json"
        mkdir -p "$(dirname "$plan_mf")" 2>/dev/null
        if ! upgrade_fetch_manifest_only "$UPGRADE_PLAN_TAG" "$plan_mf"; then
            if (( UPGRADE_JSON )); then
                printf '{"error":"no-manifest-asset","tag":"%s"}\n' "$UPGRADE_PLAN_TAG"
            fi
            rm -f "$plan_mf"
            return 2
        fi
        UPKG_MANIFEST="$plan_mf"
        UPKG_DIR="$(dirname "$plan_mf")"
        upkg_read_manifest || { rm -f "$plan_mf"; return 2; }
        plan_current_versions
        plan_build
        if (( UPGRADE_JSON )); then
            plan_print_json
        else
            plan_print_table
        fi
        rm -f "$plan_mf"
        return 0
    fi

    if [[ ! -w "$SCRIPT_DIR" ]]; then
        log_error "${SCRIPT_DIR} is not writable."
        return 2
    fi

    # Ctrl-C / SIGTERM from here on unwinds whatever module is in flight and
    # stops whatever step is running, instead of leaving both exactly where
    # they were. Registered once we know we are actually going to touch the
    # appliance -- --list and --help never reach this line.
    u_install_interrupt_trap

    # ---------------------------------------------------------------- lock -
    # Two concurrent runs would interleave `compose down`/`up` and .env
    # stamping against the SAME module directories -- there is no per-module
    # locking, only this one. `flock` on an fd held for the rest of the
    # process's life (released automatically at exit, whichever path gets
    # there) rather than a PID file: a PID file left behind by a killed -9
    # process is indistinguishable from one still running; an flock cannot be
    # held by a dead process, by construction.
    #
    # The fd survives the stage-0 hop's `exec` unchanged (exec does not close
    # descriptors that were not opened with the close-on-exec flag), so the
    # lock stays held continuously from before the hop through to the
    # process that actually finishes -- there is no gap where a second
    # invocation could slip in between "handing over" and the target
    # release's own upgrade.sh resuming.
    if [[ -z "${INTACT_UPGRADE_REEXEC:-}" ]]; then
        mkdir -p "${SCRIPT_DIR}/data/tmp" 2>/dev/null || true
        exec 9>"${SCRIPT_DIR}/data/tmp/upgrade.lock" 2>/dev/null || true
        if ! flock -n 9; then
            log_error "Another upgrade is already running against this appliance."
            log_error "  If you are certain nothing is running, remove:"
            log_error "  ${SCRIPT_DIR}/data/tmp/upgrade.lock"
            return 2
        fi
        # Reclaim scratch a KILLED earlier run left behind before this run's
        # own acquire adds more -- upkg_cleanup only ever knows what ITS OWN
        # process extracted, so a run that never reached it (kill -9, OOM, a
        # lost SSH session) leaked its extraction forever until now.
        upkg_sweep_stale_scratch
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

    # ------------------------------------------------- early hop (stage 1) ---
    # HAND OVER BEFORE ACQUIRING ANYTHING.
    #
    # The late hop further down has always run AFTER acquire -- download the
    # release, sniff the wrapper, read the manifest, and only then exec the
    # target's engine. Which means the OLD engine had to correctly parse the
    # NEW release's package in order to reach the new engine whose job was to
    # parse it. A release changed its wrapper from .tar to .tar.gz and boxes
    # could not upgrade at all: the failure landed inside the circle.
    #
    # So: before a single byte of payload is touched, delegate to
    # scripts/bootstrap_upgrade.sh, whose entire job is fetch -> verify -> exec
    # and which understands no format that can change. Everything below this
    # point then runs in the TARGET release's code, which is the only code that
    # can be expected to understand the target release's package.
    #
    # THE ONLY HANDOVER. There is no fallback and no second mechanism: if the
    # target release's engine cannot be obtained, the bootstrap refuses and
    # nothing is touched. Falling back to THIS engine would mean the upgrade was
    # driven by the code already on the box instead of the code that shipped
    # with the release being installed -- silently, which is the worst version
    # of that, because "upgrade complete" would not say which engine produced
    # it.
    if [[ -z "${INTACT_UPGRADE_REEXEC:-}" ]]; then
        local _boot="${_CODE_DIR}/scripts/bootstrap_upgrade.sh"
        if [[ -f "$_boot" ]]; then
            log_info ""
            log_info "Fetching the target release's own upgrade engine before touching anything."
            exec bash "$_boot" --root "$SCRIPT_DIR" "${_ORIG_ARGS[@]}"
        fi
        # No bootstrap beside this script. NOT refused, because this is also
        # the shape of the legitimate manual path: an operator who cloned the
        # TARGET release and ran its upgrade.sh is already running target-side,
        # which is the whole objective -- there is nothing left to hand over
        # to. It is the documented route for a box too old to bootstrap itself.
        #
        # Said out loud anyway, because the same shape covers the bad case:
        # running an OLD checkout's upgrade.sh against a newer tag. Only the
        # operator knows which of the two this is.
        log_warn "No scripts/bootstrap_upgrade.sh beside this script, so this run"
        log_warn "  uses the engine at ${_CODE_DIR}."
        log_warn "  That is correct if this checkout IS the release you are"
        log_warn "  installing. If it is not, stop and run the target release's"
        log_warn "  own upgrade.sh instead."
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
            # Registered BEFORE the fetch, not after: a download interrupted
            # half way still leaves several GB behind, and registering on
            # success would miss exactly the case that strands the most.
            # Until now this directory was never registered at all, so
            # upkg_cleanup never removed it and only the 48h sweep ever did --
            # which is why two upgrade-dl-intact-2026082* dirs totalling 2.2 GB
            # were still on the dev box days later.
            UPKG_SCRATCH="${UPKG_SCRATCH} ${dl}"
            # An explicit --only is the operator stating exactly which modules
            # they want, so there is no reason to download the rest: a release
            # carries ~5.5 GB across nine assets and `--only elk` applies one of
            # them. Driven by --only rather than by the computed plan because
            # the plan is only knowable AFTER extraction, and --only is knowable
            # now -- the automatic version needs a manifest-first restructure
            # and is deliberately not attempted here.
            #
            # `intact` is added whether or not it was asked for. Even when it is
            # NOT being upgraded, its asset carries
            # source/intact/scripts/upgrade.sh, and without that on disk the
            # stage-0 hop below has nothing to exec into -- the box would then
            # apply the release using its own older engine and say nothing.
            if [[ -n "${UPGRADE_ONLY:-}" ]]; then
                # De-duplicated: --only intact already names it, and appending
                # unconditionally logged "Fetching only: intact elk portainer
                # intact". Harmless downstream (the filter is a set) but it reads
                # like a bug in a support log, which costs someone a diagnosis.
                INTACT_RELEASE_ONLY_MODULES="$(printf '%s\n' ${UPGRADE_ONLY//,/ } intact | awk '!seen[$0]++' | tr '\n' ' ')"
                INTACT_RELEASE_ONLY_MODULES="${INTACT_RELEASE_ONLY_MODULES% }"
                export INTACT_RELEASE_ONLY_MODULES
                log_info "Fetching only: ${INTACT_RELEASE_ONLY_MODULES}"
            fi
            log_info "Fetching release ${UPGRADE_TAG} …"
            upgrade_fetch_release "$UPGRADE_TAG" "$dl" || return 2
            upkg_expand_args "$dl" || return 2
        else
            # --package is documented (args.sh) as "implies no network
            # access" but never actually set the flag every air-gap guard in
            # timesketch.sh/velociraptor.sh/modules.sh reads -- they have
            # never fired. Exported so it survives the stage-0 hop's `exec`
            # the same way UPKG_SCRATCH does.
            INTACT_UPGRADE_OFFLINE=1
            export INTACT_UPGRADE_OFFLINE
            upkg_expand_args "${UPGRADE_PACKAGE_ARGS[@]}" || return 2
        fi
        assets=("${UPKG_ASSETS[@]}")
        upkg_acquire "${assets[@]}" || return 2
    fi

    # NO SECOND HOP HERE, ON PURPOSE.
    #
    # This used to be where control passed to the target release's own
    # upgrade.sh -- AFTER acquire had already downloaded the release, sniffed
    # the wrapper with `tar -tf` and read the manifest. Which meant the OLD
    # engine had to parse the NEW release's package in order to reach the new
    # engine whose job was to parse it. A .tar -> .tar.gz change landed inside
    # that circle and boxes could not upgrade at all.
    #
    # scripts/bootstrap_upgrade.sh does the same handover BEFORE any of that,
    # against a fixed asset name it cannot misparse, so by the time execution
    # reaches this line it is ALREADY the target release's code. A second hop
    # here would be a no-op at best and a re-entry loop at worst, and keeping
    # two handover mechanisms means two things to keep in agreement forever.
    #
    # Deleted with it: _U_DROPPABLE_OPTS and _u_forwardable_args, which existed
    # only because this hop forwarded argv -- a cross-release contract that
    # changed. The bootstrap passes a versioned --handoff file instead.


    # Past the hop, so `exec` cannot have skipped it and the scratch this
    # process is about to read belongs to this process. Before the plan, so
    # every refusal below reclaims its extraction instead of leaving it on a
    # disk it may just have called too small.
    u_install_exit_cleanup_trap

    # ------------------------------------------------------------- plan -----
    plan_current_versions
    plan_log_environment
    plan_build
    # --dry-run --json is a MACHINE-READABLE answer for the dashboard, so the
    # human table and the advisory chatter below would corrupt the stream.
    # Everything that follows still runs -- the refusals below are the point of
    # asking -- their output just goes to the log rather than to stdout.
    if (( UPGRADE_DRY_RUN )) && (( UPGRADE_JSON )); then
        plan_reject_downgrades || return 2
        plan_check_disk || return 2
        plan_print_json
        upkg_cleanup
        return 0
    fi
    plan_print_table
    hostdeps_report
    plan_reject_downgrades || return 2
    plan_check_disk || return 2
    # Advisory, and intentionally not `|| return 2`: see plan_check_memory.
    # It must run AFTER plan_check_disk, which publishes PLAN_LARGEST_TAR.
    plan_check_memory

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

    # Offline only: catches a missing image before three OTHER modules have
    # already swapped and the fourth discovers it cannot pull. Online, a
    # missing image is just a pull -- nothing to preflight.
    _u_preflight_images || return 2

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

        # Lazy extraction: this module's asset is still compressed. Unpack and
        # verify it now, immediately before it is needed, so the peak on disk
        # is one module rather than the whole release. A no-op unless
        # INTACT_UPGRADE_LAZY_EXTRACT=1 put it on the deferred list.
        if ! upkg_extract_deferred "$m"; then
            log_error "${m}: could not unpack its asset; leaving it at ${PLAN_CURRENT[$m]:-its current version}"
            UPGRADE_FAILED+=("${m} — its asset could not be unpacked or verified")
            U_KEEP_SCRATCH=1
            continue
        fi

        U_STEP_N=$((U_STEP_N + 1))
        U_FROM="${PLAN_CURRENT[$m]:-not installed}"
        U_TO="${PLAN_TARGET[$m]}"
        "$fn" "${PLAN_TARGET[$m]}"

        # Prune the tag this module just swapped AWAY from. Only once it has
        # genuinely committed (UPGRADE_OK) -- a rolled-back or degraded
        # module is still using its old image, sometimes literally (the
        # rollback undo brings it back up on that exact tag).
        if [[ " ${UPGRADE_OK[*]} " == *" ${m} "* ]]; then
            _u_prune_old_module_images "$m" "$U_FROM" "$U_TO"
        fi
    done

    # ------------------------------------------------------------ after -----
    if declare -F velo_refresh >/dev/null && [[ " ${UPGRADE_OK[*]} " == *" velociraptor "* ]]; then
        velo_refresh "$UPKG_DIR"
    fi

    refresh_nginx_upstreams
    fix_source_permissions
    u_post_upgrade_gate

    print_upgrade_report
    print_final_issues_report
    upkg_cleanup

    return "$(upgrade_exit_code)"
}

main
exit $?
