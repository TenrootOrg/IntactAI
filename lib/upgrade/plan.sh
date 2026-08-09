#!/bin/bash
# Intact.AI upgrade — what is installed, what the package offers, what to do.
#
# Produces the plan and refuses the two situations that must never reach the
# module loop: a downgrade, and a package that would not fit on the disk.

# The order modules are upgraded in. `intact` FIRST and always: it carries the
# new backend code, the sidecar compose files and the config.yaml merge that
# every later module reads its pins from. Ported from __init__.py:71-74.
UPGRADE_ORDER=(intact elk timesketch plaso iris velociraptor aws_sigma o365rc volweb portainer)

# module -> "<env file>:<KEY>". The pin that says what is actually RUNNING, as
# opposed to config.yaml which says what the operator asked for. base.py:1473
# reads exactly these.
declare -gA _PIN_SOURCE=(
    [elk]="modules/elk/.env:ELASTIC_VERSION"
    [iris]="modules/iris/.env:IRIS_VERSION"
    [timesketch]="modules/timesketch/.env:TIMESKETCH_VERSION"
    [velociraptor]="modules/velociraptor/.env:VELOCIRAPTOR_VERSION"
    [volweb]="modules/volweb/.env:VOLWEB_BACKEND_VERSION"
    [portainer]="modules/portainer/.env:PORTAINER_VERSION"
    [plaso]="modules/backend/.env:PLASO_VERSION"
    [aws_sigma]="modules/backend/.env:CLOUDTRAIL_VERSION"
    [o365rc]="modules/backend/.env:DFIR_O365RC_VERSION"
    [intact]="modules/backend/.env:BACKEND_VERSION"
)

declare -gA PLAN_CURRENT=()   # module -> running version, or "" if not installed
declare -gA PLAN_TARGET=()    # module -> version the package offers
declare -gA PLAN_ACTION=()    # module -> upgrade | install | noop | skip

# ---------------------------------------------------------------------------
# _version_is_older <a> <b>   — true when a < b, CONSERVATIVELY.
#
# Returns 1 (not older) whenever it cannot be sure. A false "older" would let
# a genuine downgrade through, and a downgrade is unrecoverable for the two
# modules that matter: Elasticsearch refuses to open a data directory written
# by a newer version, and Postgres/OpenSearch forward-migrate their volumes on
# first boot with no way back. Refusing an upgrade we could have done is an
# inconvenience; allowing a downgrade destroys evidence.
#
# Handles: 9.4.4, v2.4.27, 0.77.1, 2.39.5, 20260630, 2026.04, intact-20260809.
# ---------------------------------------------------------------------------
_version_is_older() {
    local a="$1" b="$2"
    [[ -n "$a" && -n "$b" ]] || return 1
    [[ "$a" == "$b" ]] && return 1

    # Release-tag shape: compare the date suffix.
    if [[ "$a" =~ ^intact-([0-9]{8})$ && "$b" =~ ^intact-([0-9]{8})$ ]]; then
        local da="${a#intact-}" db="${b#intact-}"
        (( 10#$da < 10#$db )) && return 0
        return 1
    fi

    local na="${a#v}" nb="${b#v}"
    # Anything that is not purely dotted-numeric (a git sha, 'latest',
    # 'development', '3-management-alpine') is not ordered — say nothing.
    [[ "$na" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1
    [[ "$nb" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1

    local -a pa pb
    IFS='.' read -ra pa <<< "$na"
    IFS='.' read -ra pb <<< "$nb"
    local i max=${#pa[@]}
    (( ${#pb[@]} > max )) && max=${#pb[@]}
    for (( i = 0; i < max; i++ )); do
        local x="${pa[i]:-0}" y="${pb[i]:-0}"
        (( 10#$x < 10#$y )) && return 0
        (( 10#$x > 10#$y )) && return 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# plan_current_versions — what is running right now.
# ---------------------------------------------------------------------------
plan_current_versions() {
    local m spec file key val primary
    for m in "${UPGRADE_ORDER[@]}"; do
        spec="${_PIN_SOURCE[$m]:-}"
        [[ -n "$spec" ]] || { PLAN_CURRENT[$m]=""; continue; }
        file="${SCRIPT_DIR}/${spec%%:*}"
        key="${spec##*:}"
        val="$(read_env_var "$file" "$key" 2>/dev/null || echo "")"

        # A pin in .env does not mean the module is running -- a full package
        # seeds pins for modules the operator has turned off. Where there is a
        # container to look at, its absence is the truth.
        primary="$(u_primary_container_of "$m")"
        if [[ -n "$primary" ]] && ! "${DOCKER_BIN:-docker}" inspect "$primary" >/dev/null 2>&1; then
            PLAN_CURRENT[$m]=""
        else
            PLAN_CURRENT[$m]="$val"
        fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# plan_build [--only a,b] [--skip c,d]
# ---------------------------------------------------------------------------
plan_build() {
    local only="${UPGRADE_ONLY:-}" skip="${UPGRADE_SKIP:-}"
    local m target current

    for m in "${UPGRADE_ORDER[@]}"; do
        target="${UPKG_VERSIONS[$m]:-}"
        current="${PLAN_CURRENT[$m]:-}"
        PLAN_TARGET[$m]="$target"

        if [[ -z "$target" ]]; then
            PLAN_ACTION[$m]="skip:not in this package"
            continue
        fi
        if [[ -n "$only" ]] && [[ ",${only}," != *",${m},"* ]]; then
            PLAN_ACTION[$m]="skip:excluded by --only"
            continue
        fi
        if [[ -n "$skip" ]] && [[ ",${skip}," == *",${m},"* ]]; then
            PLAN_ACTION[$m]="skip:excluded by --skip"
            continue
        fi
        if ! _plan_module_enabled "$m"; then
            PLAN_ACTION[$m]="skip:disabled in config.yaml"
            continue
        fi
        if [[ -z "$current" ]]; then
            PLAN_ACTION[$m]="install"
            continue
        fi
        if [[ "$current" == "$target" ]]; then
            PLAN_ACTION[$m]="noop:already at ${target}"
            continue
        fi
        PLAN_ACTION[$m]="upgrade"
    done

    # `intact` is never a no-op when the package carries it: a rolling tag can
    # map to different commits, and skipping it would leave the box running the
    # old backend code while every other module moved. __init__.py:855-864 makes
    # the same exception for the same reason.
    if [[ -n "${UPKG_VERSIONS[intact]:-}" && "${PLAN_ACTION[intact]}" == noop:* ]]; then
        if [[ -z "${UPGRADE_ONLY:-}" || ",${UPGRADE_ONLY}," == *",intact,"* ]]; then
            PLAN_ACTION[intact]="upgrade"
        fi
    fi
    return 0
}

# A module counts as enabled unless config.yaml explicitly says otherwise.
# Absent block => enabled, because older config.yaml files predate several of
# these keys and defaulting them off would silently skip a real upgrade.
_plan_module_enabled() {
    local m="$1" v
    v="$(read_config "['modules']['${m}']['enabled']" 2>/dev/null || echo "")"
    [[ -z "$v" || "$v" == "None" ]] && return 0
    is_enabled "$v"
}

# ---------------------------------------------------------------------------
# plan_reject_downgrades — hard abort, no --force.
# ---------------------------------------------------------------------------
plan_reject_downgrades() {
    local m current target bad=0
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in upgrade) ;; *) continue ;; esac
        current="${PLAN_CURRENT[$m]}"
        target="${PLAN_TARGET[$m]}"
        if _version_is_older "$target" "$current"; then
            log_error "DOWNGRADE REFUSED: ${m} ${current} -> ${target}"
            bad=1
        fi
    done
    if (( bad )); then
        log_error ""
        log_error "This package is older than what is installed, for at least one module."
        log_error "There is deliberately no --force for this. Elasticsearch will not open"
        log_error "a data directory written by a newer version, and Postgres and OpenSearch"
        log_error "forward-migrate their volumes on first boot with no way back — so a"
        log_error "downgrade does not restore the old state, it destroys the current one."
        log_error "To genuinely roll a module back you must wipe its volume and restore"
        log_error "from a backup, which is a deliberate operation, not an upgrade."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# plan_check_disk — enough headroom for the images this package will load.
#
# Sized on the image tars because that is what doubles: each tar's layers are
# written into the docker store while the tar still exists. Ported from
# config_validate.py:172-268.
# ---------------------------------------------------------------------------
plan_check_disk() {
    local images_dir="${UPKG_DIR}/images"
    local need_gb=2 tars_bytes=0 largest=0 sz f
    if [[ -d "$images_dir" ]]; then
        while IFS= read -r f; do
            sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
            tars_bytes=$((tars_bytes + sz))
            (( sz > largest )) && largest=$sz
        done < <(find "$images_dir" -maxdepth 1 -name '*.tar' 2>/dev/null)
        # Layers land in the docker store while the tar is still on disk, but
        # each tar is deleted as soon as it loads -- so the peak is roughly
        # half the total plus the biggest single tar, not the whole set twice.
        need_gb=$(( (tars_bytes / 2 + largest) / 1000000000 + 2 ))
    fi

    local free_gb
    free_gb="$(df -B1G --output=avail "${SCRIPT_DIR}" 2>/dev/null | tail -1 | tr -d ' ')"
    [[ -n "$free_gb" ]] || { log_warn "could not determine free disk space"; return 0; }

    if (( free_gb < need_gb )); then
        log_error "Not enough disk: ${free_gb}G free, this package needs about ${need_gb}G"
        log_error "  Free space and re-run. 'docker image prune -a' on images no module"
        log_error "  pins is usually the biggest win."
        return 1
    fi
    log_info "Disk: ${free_gb}G free, ~${need_gb}G needed"
    return 0
}

# ---------------------------------------------------------------------------
# plan_print_table
# ---------------------------------------------------------------------------
plan_print_table() {
    local m action note cur tgt
    log_info ""
    log_info "=================================================================="
    log_info "Upgrade plan"
    log_info "=================================================================="
    printf '  %-16s %-20s %-20s %s\n' "MODULE" "INSTALLED" "PACKAGE" "ACTION" | tee -a "${LOG_FILE:-/dev/null}"
    for m in "${UPGRADE_ORDER[@]}"; do
        action="${PLAN_ACTION[$m]:-skip:unknown}"
        note="${action#*:}"
        [[ "$note" == "$action" ]] && note=""
        cur="${PLAN_CURRENT[$m]:-—}"; [[ -z "${PLAN_CURRENT[$m]:-}" ]] && cur="not installed"
        tgt="${PLAN_TARGET[$m]:-—}"
        case "${action%%:*}" in
            upgrade) printf '  %-16s %-20s %-20s UPGRADE\n' "$m" "$cur" "$tgt" ;;
            install) printf '  %-16s %-20s %-20s INSTALL\n' "$m" "$cur" "$tgt" ;;
            noop)    printf '  %-16s %-20s %-20s -\n'       "$m" "$cur" "$tgt" ;;
            *)       printf '  %-16s %-20s %-20s skip (%s)\n' "$m" "$cur" "$tgt" "$note" ;;
        esac
    done | tee -a "${LOG_FILE:-/dev/null}"
    log_info ""
    return 0
}

# How many modules will actually be touched.
plan_work_count() {
    local m n=0
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in upgrade|install) n=$((n + 1)) ;; esac
    done
    echo "$n"
}
