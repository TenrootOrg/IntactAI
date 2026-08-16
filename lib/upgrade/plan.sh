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
    local m spec file key val
    for m in "${UPGRADE_ORDER[@]}"; do
        spec="${_PIN_SOURCE[$m]:-}"
        [[ -n "$spec" ]] || { PLAN_CURRENT[$m]=""; continue; }
        file="${SCRIPT_DIR}/${spec%%:*}"
        key="${spec##*:}"
        val="$(read_env_var "$file" "$key" 2>/dev/null || echo "")"

        # A pin in .env does not mean the module is installed -- a full package
        # seeds pins for modules the operator never deployed, so a pin proves
        # only that a package went past. The box itself is the truth.
        #
        # u_module_is_present covers all ten: the container for the seven that
        # run one, an image probe over the docker socket for plaso and o365rc,
        # and the rules directory for aws_sigma. It returns 2 for "cannot tell"
        # -- aws_sigma's rules are on the host and the dashboard's helper
        # container cannot see them -- and that case KEEPS THE PIN rather than
        # guessing. Reading "absent" there would silently drop the module from
        # every upgrade driven from the UI while a shell run still upgraded it,
        # which is worse than the pin being slightly optimistic.
        u_module_is_present "$m"
        case $? in
            0) PLAN_CURRENT[$m]="$val" ;;
            1) PLAN_CURRENT[$m]="" ;;
            *) PLAN_CURRENT[$m]="$val" ;;
        esac
    done
    return 0
}

# ---------------------------------------------------------------------------
# plan_build [--only a,b] [--skip c,d]
# ---------------------------------------------------------------------------
plan_build() {
    local only="${UPGRADE_ONLY:-}" skip="${UPGRADE_SKIP:-}"
    local m target current

    # WARN, do not override. A --only that leaves intact out upgrades modules
    # against the old backend code, the old sidecar compose files and the old
    # config.yaml merge -- the things UPGRADE_ORDER's comment says every later
    # module reads its pins from. That is usually a mistake, and until
    # 2026-08-11 nothing said so (the --only help even claimed intact was added
    # back, which no code did).
    #
    # But it is not always a mistake: repairing or installing one module from a
    # shell, deliberately, without moving the platform is a real thing to want,
    # and the CLI is where an operator gets to mean exactly what they typed. So
    # this is a warning here and a guarantee in the dashboard -- upgrade_routes
    # always sends intact, because the UI offers no way to express the
    # deliberate version and a stray untick should not silently half-upgrade a
    # box.
    if [[ -n "$only" && ",${only}," != *",intact,"* && -n "${UPKG_VERSIONS[intact]:-}" ]]; then
        log_warn "  --only does not include intact, but this package carries it."
        log_warn "  The modules below will be upgraded against the CURRENT backend"
        log_warn "  code and pins. That is supported, but it is rarely what you want"
        log_warn "  outside a deliberate single-module repair."
    fi

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
            # A pin match is not the same claim as a running-container match.
            # .env can say 9.4.4 while the container is still actually
            # running 9.4.2 -- a previous upgrade that stamped the pin but
            # then failed before the swap, or a manual `docker run` outside
            # this engine entirely. Planning that as a noop leaves the box
            # silently wrong while every later check believes the pin.
            local running_tag; running_tag="$(_plan_running_image_tag "$m" 2>/dev/null || echo '')"
            if [[ -n "$running_tag" && "$running_tag" != "$target" ]]; then
                log_warn "  ${m}: versions pin says ${target} but the running container is tagged ${running_tag} — upgrading instead of skipping"
                PLAN_ACTION[$m]="upgrade"
                continue
            fi
            # A version match is not a health claim either. The intact module
            # refreshes every module's compose file, so a same-version module
            # can end the run mounting a file it has never owned: portainer's
            # secrets/agent.env is named by `env_file:` in the new compose and
            # by nothing in a 20260726 one. Planned noop, the module never
            # runs, the secret is never generated -- and the box only finds out
            # on the next `compose up`, which is a reboot, not an upgrade.
            # Observed on a real 0726 -> 0811 run (2026-08-12).
            #
            # Only per-box generated files reach here: anything the package
            # carries is delivered by the intact module before this matters.
            local absent; absent="$(_plan_missing_generated_assets "$m")"
            if [[ -n "$absent" ]]; then
                log_warn "  ${m}: already at ${target}, but ${absent} is missing — re-applying instead of skipping"
                PLAN_ACTION[$m]="upgrade"
                continue
            fi
            # The operator explicitly asked for this one to be re-applied.
            #
            # --only is NOT that request: it is checked further up, and a
            # module is in it simply because it is part of this run. Until
            # 2026-08-11 the GUI's "reinstall" tick was translated into --only
            # and nothing else, so a same-version module was ticked,
            # submitted, classified noop here and silently skipped -- the
            # checkbox did nothing at all, on both the online and the Import
            # path. Hence a separate list, disjoint from the modules that are
            # actually moving (those are already in the plan and need no flag).
            if [[ -n "${UPGRADE_REINSTALL:-}" && ",${UPGRADE_REINSTALL}," == *",${m},"* ]]; then
                log_info "  ${m}: already at ${target}, re-applying as requested"
                PLAN_ACTION[$m]="upgrade"
                continue
            fi
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

# ---------------------------------------------------------------------------
# _plan_missing_generated_assets <module>
#
# The bind-mount / env_file sources the module will need AFTER this run that
# do not exist and cannot be delivered from the package -- i.e. the per-box
# generated ones (portainer's agent.env and admin_password, the shared TLS
# pair). Prints them comma-separated, or nothing.
#
# Read from the PACKAGE's compose, not the box's: the box's is still the old
# one when the plan is built, and the whole point is to see what the module
# will be mounting once intact has refreshed it. Falls back to the box's
# compose when the package has none for this module.
# ---------------------------------------------------------------------------
_plan_missing_generated_assets() {
    local m="$1"
    local box="${SCRIPT_DIR}/modules/${m}"
    local pkg="${UPKG_DIR:-}/source/intact/modules/${m}"
    local compose="${pkg}/docker-compose.yaml"
    [[ -n "${UPKG_DIR:-}" && -f "$compose" ]] || compose="${box}/docker-compose.yaml"
    [[ -f "$compose" ]] || return 0
    declare -F _u_compose_sources >/dev/null || return 0

    local kind rel src; local -a absent=()
    while read -r kind rel; do
        [[ -n "${rel:-}" ]] || continue
        src="${box}/${rel}"
        # An EMPTY directory is Docker's fabrication where a file belongs, so
        # it counts as absent -- same convention as _u_precheck_compose_sources.
        # A non-empty one is a real directory mount and is fine.
        if [[ -e "$src" ]] && ! { [[ -d "$src" ]] && [[ -z "$(ls -A "$src" 2>/dev/null)" ]]; }; then
            continue
        fi
        # The package can supply it -> _intact_refresh_sidecars will, for every
        # module, before any module is upgraded. Not a reason to re-run one.
        [[ "$rel" != ../* && -n "${UPKG_DIR:-}" && -e "${pkg}/${rel}" ]] && continue
        absent+=("$rel")
    done < <(_u_compose_sources "$compose" | sort -u)

    (( ${#absent[@]} )) || return 0
    local IFS=','; echo "${absent[*]}"
}

# The image TAG the module's primary container is actually running, or ""
# when there is no primary container / no way to tell. Comparing only the
# tag (not the full repo:tag) works across every module without a second
# module->repo table: what plan_build cares about is whether the box is
# running the VERSION the pin claims, not which registry it came from.
_plan_running_image_tag() {
    local primary; primary="$(u_primary_container_of "$1")"
    [[ -n "$primary" ]] || return 1
    local img
    img="$("${DOCKER_BIN:-docker}" inspect -f '{{.Config.Image}}' "$primary" 2>/dev/null)" || return 1
    [[ -n "$img" ]] || return 1
    echo "${img##*:}"
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
# plan_image_tars — "<path>\t<bytes>" for every tar THIS PLAN will actually
# load, newline separated. Empty when there is nothing to load.
#
# Three things it fixes, all of which made the old inline `find` wrong:
#
#   scope    it summed every tar in images/, including modules the plan had
#            already decided to skip. A 9-asset package upgrading 2 modules
#            demanded headroom for all 9 and refused upgrades it could do.
#   format   the glob was '*.tar', but _intact_ensure_image also accepts
#            intact-backend-<tag>.tar.gz -- which was therefore sized at zero
#            AND expands to more than its on-disk size.
#   kind     the aws_sigma rule pack is a plain data tar streamed into
#            /opt/sigma-rules by _u_install_sigma_pack; it never enters the
#            docker store, so budgeting for its layers is pure over-count.
#
# Attribution comes from the manifests/<module>.json sidecars each per-module
# asset carries (contents.images + contents.image_sizes) -- the same source
# lib/package.sh already reads on the install path, and exact rather than
# guessed from filename prefixes. A legacy single bundle has no sidecars, so
# it falls back to every tar in images/: over-estimating is the safe direction
# for a check whose failure mode is refusing an upgrade.
# ---------------------------------------------------------------------------
plan_image_tars() {
    local images_dir="${UPKG_DIR}/images"
    [[ -d "$images_dir" ]] || return 0

    # Modules this run will actually touch.
    local m wanted=""
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in
            upgrade|install) wanted+="${m} " ;;
        esac
    done

    local emitted=0 img owner size f
    if compgen -G "${UPKG_DIR}/manifests/*.json" >/dev/null 2>&1; then
        while IFS='|' read -r img owner size; do
            [[ -n "$img" && -n "$owner" ]] || continue
            [[ " $wanted " == *" $owner "* ]] || continue
            f="${images_dir}/${img}"
            [[ -f "$f" ]] || continue
            [[ -n "$size" ]] || size="$(stat -c%s "$f" 2>/dev/null || echo 0)"
            printf '%s\t%s\n' "$f" "$size"
            emitted=1
        done < <(python3 -c "
import json, glob, os, sys
root = sys.argv[1]
owner, size = {}, {}
for p in glob.glob(os.path.join(root, 'manifests', '*.json')):
    module = os.path.splitext(os.path.basename(p))[0]
    try:
        m = json.load(open(p))
    except Exception:
        continue
    c = m.get('contents') or {}
    sizes = c.get('image_sizes') or {}
    for img in c.get('images') or []:
        owner[img] = module
        if img in sizes:
            size[img] = sizes[img]
for img in sorted(owner):
    print(f'{img}|{owner[img]}|{size.get(img, \"\")}')
" "$UPKG_DIR" 2>/dev/null)
    fi

    # Assets still compressed contribute their own size: their tars are not on
    # disk to stat, but the space they will need is real. Compressed is an
    # under-estimate of what they expand to, which the caller's +2G floor and
    # the halving both absorb -- and in lazy mode the true peak is one module
    # anyway, so this errs in the direction of asking for more than needed.
    local e p
    for e in ${UPKG_DEFERRED:-}; do
        p="${e#*=}"
        [[ -f "$p" ]] || continue
        printf '%s\t%s\n' "$p" "$(stat -c%s "$p" 2>/dev/null || echo 0)"
        emitted=1
    done

    (( emitted )) && return 0

    # Legacy bundle, or sidecars that named nothing we recognise. Count
    # everything loadable and let the estimate run high.
    for f in "$images_dir"/*.tar "$images_dir"/*.tar.gz; do
        [[ -f "$f" ]] || continue
        # A .tar.gz cannot be inspected by _tar_is_docker_image without
        # decompressing it; the only one we ship is the backend image, so
        # treat it as an image and move on.
        case "$f" in
            *.tar) _tar_is_docker_image "$f" || continue ;;
        esac
        printf '%s\t%s\n' "$f" "$(stat -c%s "$f" 2>/dev/null || echo 0)"
    done
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
    local need_gb=2 tars_bytes=0 largest=0 n=0 sz f
    while IFS=$'\t' read -r f sz; do
        [[ -n "$f" ]] || continue
        tars_bytes=$((tars_bytes + sz))
        (( sz > largest )) && largest=$sz
        n=$((n + 1))
    done < <(plan_image_tars)
    if (( n )); then
        # Layers land in the docker store while the tar is still on disk, but
        # each tar is deleted as soon as it loads -- so the peak is roughly
        # half the total plus the biggest single tar, not the whole set twice.
        #
        # That was ASPIRATIONAL until 2026-08-13: it described lib/package.sh's
        # installer, and this function's own caller kept every tar for the
        # whole run. upkg_release_loaded_tar (lib/upgrade/package.sh) is what
        # makes the sentence above true; do not change one without the other.
        need_gb=$(( (tars_bytes / 2 + largest) / 1000000000 + 2 ))
    fi
    # Publish for plan_check_memory, so a box is not scanned twice.
    PLAN_LARGEST_TAR="$largest"

    local free_gb
    free_gb="$(_free_gb "${SCRIPT_DIR}")"
    [[ -n "$free_gb" ]] || { log_warn "could not determine free disk space"; return 0; }

    if (( free_gb < need_gb )); then
        log_error "Not enough disk: ${free_gb}G free on ${SCRIPT_DIR}, this package needs about ${need_gb}G"
        log_error "  Free space and re-run. 'docker image prune -a' on images no module"
        log_error "  pins is usually the biggest win."
        return 1
    fi
    log_info "Disk: ${free_gb}G free on ${SCRIPT_DIR}, ~${need_gb}G needed for ${n} image tar(s)"

    # The tars extract under $SCRIPT_DIR, but the LAYERS they unpack into
    # live wherever Docker's own data root is -- a separate mount on many
    # production hosts, precisely to keep image growth off the app
    # filesystem. Checking only $SCRIPT_DIR above would report "plenty of
    # room" while THAT filesystem fills mid-load.
    local docker_root
    docker_root="$("${DOCKER_BIN:-docker}" info --format '{{.DockerRootDir}}' 2>/dev/null)"
    if [[ -n "$docker_root" && -d "$docker_root" ]]; then
        local docker_free_gb
        docker_free_gb="$(_free_gb "$docker_root")"
        if [[ -n "$docker_free_gb" ]] && (( docker_free_gb < need_gb )); then
            log_error "Not enough disk: ${docker_free_gb}G free on ${docker_root} (Docker's data root)"
            log_error "  for images this package needs to load (~${need_gb}G)."
            log_error "  Free space and re-run. 'docker image prune -a' on images no module"
            log_error "  pins is usually the biggest win."
            return 1
        fi
        log_info "Disk: ${docker_free_gb:-?}G free on ${docker_root} (Docker's data root)"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# _plan_stack_memory — "<module>\t<anon bytes>" for each running module,
# heaviest first. Empty when nothing can be measured.
#
# Reads the cgroup directly rather than shelling out to `docker stats`.
# `docker stats` SAMPLES: it waits a full interval per container even with
# --no-stream, and on a box that is already thrashing -- which is precisely
# when this runs -- it is slow enough to be indistinguishable from the stall
# it is trying to explain. A preflight must never become the hang.
#
# `anon` and not `memory.current`: current includes page cache, which the
# kernel reclaims under pressure. Counting it would rank a container that has
# merely READ a lot of data above one genuinely holding the RAM, and tell the
# operator to stop the wrong stack.
# ---------------------------------------------------------------------------
_plan_stack_memory() {
    declare -F u_containers_of >/dev/null 2>&1 || return 0
    local ps_out
    ps_out="$(timeout 10 "${DOCKER_BIN:-docker}" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)" || return 0
    [[ -n "$ps_out" ]] || return 0

    # container name -> module
    declare -A owner=()
    local m c
    for m in "${UPGRADE_ORDER[@]}"; do
        for c in $(u_containers_of "$m"); do owner["$c"]="$m"; done
    done

    declare -A total=()
    local id name bytes p
    while read -r id name; do
        [[ -n "$id" && -n "$name" ]] || continue
        m="${owner[$name]:-}"
        [[ -n "$m" ]] || continue
        bytes=""
        for p in "/sys/fs/cgroup/system.slice/docker-${id}*.scope/memory.stat" \
                 "/sys/fs/cgroup/docker/${id}*/memory.stat"; do
            local f; for f in $p; do
                [[ -r "$f" ]] || continue
                bytes="$(awk '$1=="anon"{print $2; exit}' "$f" 2>/dev/null)"
                [[ -n "$bytes" ]] && break 2
            done
        done
        if [[ -z "$bytes" ]]; then
            for p in "/sys/fs/cgroup/memory/docker/${id}*/memory.usage_in_bytes" \
                     "/sys/fs/cgroup/memory/system.slice/docker-${id}*.scope/memory.usage_in_bytes"; do
                local f2; for f2 in $p; do
                    [[ -r "$f2" ]] || continue
                    bytes="$(cat "$f2" 2>/dev/null)"
                    [[ -n "$bytes" ]] && break 2
                done
            done
        fi
        [[ "$bytes" =~ ^[0-9]+$ ]] || continue
        total["$m"]=$(( ${total[$m]:-0} + bytes ))
    done <<< "$ps_out"

    for m in "${!total[@]}"; do printf '%s\t%s\n' "$m" "${total[$m]}"; done \
        | sort -k2 -rn
    return 0
}

# ---------------------------------------------------------------------------
# plan_check_memory — advisory. NEVER blocks, NEVER logs at error level.
#
# Nothing in either engine has ever looked at memory before a multi-GB
# `docker load`. On 2026-08-13 a box with 25 containers, 296 MiB available and
# 2.3 GiB of swap already in use sat on a 1.6 GB kibana load for six minutes
# with no output at all; disk was fine (47 G free) so every existing preflight
# passed. Those two numbers are where the thresholds below come from.
#
# WARN ONLY, and deliberately so:
#   * upgrade_launcher.py maps any [ERROR] line to run status `failed`, so
#     even a non-blocking log_error would mark a perfectly good customer
#     upgrade as failed in the dashboard.
#   * memory is recoverable mid-run -- the operator stops a stack and the load
#     proceeds. Disk is not. Refusing on a transient reading is worse than the
#     slow load it warns about.
#   * lib/modules/shared.sh already established "memory is log-only, by
#     explicit design" in this codebase. This extends that with something
#     actionable rather than reversing it.
# ---------------------------------------------------------------------------
plan_check_memory() {
    local mi=/proc/meminfo
    [[ -r "$mi" ]] || return 0

    local avail_kb swap_total_kb swap_free_kb
    avail_kb="$(awk '/^MemAvailable:/{print $2; exit}' "$mi" 2>/dev/null)"
    swap_total_kb="$(awk '/^SwapTotal:/{print $2; exit}' "$mi" 2>/dev/null)"
    swap_free_kb="$(awk '/^SwapFree:/{print $2; exit}' "$mi" 2>/dev/null)"
    [[ "$avail_kb" =~ ^[0-9]+$ ]] || return 0
    : "${swap_total_kb:=0}"; : "${swap_free_kb:=0}"
    [[ "$swap_total_kb" =~ ^[0-9]+$ ]] || swap_total_kb=0
    [[ "$swap_free_kb"  =~ ^[0-9]+$ ]] || swap_free_kb=0

    local avail=$(( avail_kb * 1024 ))
    local swap_used=$(( (swap_total_kb - swap_free_kb) * 1024 ))
    local largest="${PLAN_LARGEST_TAR:-0}"
    (( largest > 0 )) || return 0

    local tight=0
    (( avail < largest ))       && tight=1
    (( swap_used > 536870912 )) && tight=1
    (( tight )) || return 0

    log_warn "Memory looks tight for this upgrade."
    log_warn "  available: $(_human_size "$avail"), swap in use: $(_human_size "$swap_used")"
    log_warn "  largest image to load: $(_human_size "$largest")"
    log_warn "  The upgrade will still run, but 'docker load' may take many minutes"
    log_warn "  with no output while the kernel swaps."

    # Name stacks worth stopping -- but never one this run is about to upgrade
    # anyway, since the module brings it down itself.
    local shown=0 m bytes
    while IFS=$'\t' read -r m bytes; do
        [[ -n "$m" ]] || continue
        case "${PLAN_ACTION[$m]:-}" in upgrade|install) continue ;; esac
        (( shown == 0 )) && log_warn "  To speed it up, stop a stack you are not using and re-run:"
        log_warn "    $(printf '%-12s %8s' "$m" "$(_human_size "$bytes")")  sudo docker compose -f modules/${m}/docker-compose.yaml stop"
        shown=$((shown + 1))
        (( shown >= 3 )) && break
    done < <(_plan_stack_memory)

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
        cur="${PLAN_CURRENT[$m]:-}"; [[ -z "$cur" ]] && cur="not installed"
        # ASCII '-', not an em-dash: printf's %-20s pads to twenty BYTES, and
        # U+2014 is three of them, so every row using it lost two columns and
        # the ACTION column stepped left -- visible on any plan where a module
        # is absent from the package, which is most of them.
        tgt="${PLAN_TARGET[$m]:--}"
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

# ---------------------------------------------------------------------------
# plan_print_json — same data as plan_print_table, machine-readable.
#
# For `scripts/upgrade.sh --plan <tag> --json`, which is what the restored
# UI's module-selection table reads. Deliberately the SAME PLAN_* state
# plan_print_table renders and the real run's module loop drives -- the
# operator sees, and chooses from, the actual decision the run would make,
# not a second implementation of it in Python that could drift from this one.
# ---------------------------------------------------------------------------
plan_print_json() {
    local m action note cur tgt
    {
        for m in "${UPGRADE_ORDER[@]}"; do
            action="${PLAN_ACTION[$m]:-skip:unknown}"
            note="${action#*:}"; [[ "$note" == "$action" ]] && note=""
            cur="${PLAN_CURRENT[$m]:-}"
            tgt="${PLAN_TARGET[$m]:-}"
            printf '%s\t%s\t%s\t%s\t%s\n' "$m" "$cur" "$tgt" "${action%%:*}" "$note"
        done
    } | python3 -c '
import json, sys
modules = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    m, cur, tgt, act, note = line.split("\t")
    modules.append({
        "module": m,
        "current": cur or None,
        "target": tgt or None,
        "action": act,
        "note": note or None,
    })
print(json.dumps({"modules": modules}))
'
    return 0
}
