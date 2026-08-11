#!/bin/bash
# Intact.AI upgrade — sidecar compose files and the files they bind-mount.
#
# THE MOUNT ASSET RULE: if a compose file arrives referencing a bind-mounted
# file that is not on disk, Docker fabricates an empty DIRECTORY at the mount
# path and the container dies with exit 126. So the compose file and its
# assets have to land together.
# Whether config.yaml has this module switched on. `backend` and `nginx` are
# the platform itself and have no entry, so they always count as enabled.
_intact_module_is_enabled() {
    local m="$1"
    case "$m" in backend|nginx) return 0 ;; esac
    local v
    v="$(read_config "['modules']['${m}']['enabled']" 2>/dev/null || echo "")"
    case "$v" in True|true|1|yes) return 0 ;; *) return 1 ;; esac
}

_intact_refresh_sidecars() {
    local src="$1" m n=0
    for m in elk iris timesketch velociraptor volweb portainer nginx backend; do
        local s="${src}/modules/${m}/docker-compose.yaml"
        local d="${SCRIPT_DIR}/modules/${m}/docker-compose.yaml"
        [[ -f "$s" ]] || continue
        if ! cmp -s "$s" "$d"; then
            mkdir -p "$(dirname "$d")"
            cp -p "$s" "$d" || return 1
            n=$((n + 1))
            log_info "    refreshed modules/${m}/docker-compose.yaml"
        fi
        _intact_deliver_mount_assets "${src}/modules/${m}" "${SCRIPT_DIR}/modules/${m}" "$d" || return 1
        _intact_refresh_module_code "${src}/modules/${m}" "${SCRIPT_DIR}/modules/${m}" "$m" || return 1
    done
    log_info "  refreshed ${n} sidecar compose file(s)"
    return 0
}

# ---------------------------------------------------------------------------
# _intact_refresh_module_code <package module dir> <box module dir> <name>
#
# The module's BUILD INPUTS -- Dockerfile, entrypoint.sh and the helper scripts
# beside them. An upgrade replaces the platform's own code (modules/backend,
# nginx/html, lib/, scripts/, install.sh) but used to leave these untouched,
# and lib/upgrade/velociraptor/image.sh runs `docker compose build` in this
# very directory. So a release that fixed modules/velociraptor/Dockerfile or
# entrypoint.sh rebuilt the image on the box FROM THE OLD ONES, and the fix
# never arrived -- the same silent staleness as the logstash pipeline, one
# level up.
#
# DEPTH 1 ONLY, and that is the safety property, not a shortcut. Everything
# that carries per-box state lives in a SUBdirectory:
#
#   config/             velociraptor's server config and its CA, timesketch's
#                       runtime LLM settings   (the mount-asset path above
#                       handles what the package legitimately ships there,
#                       with backups)
#   secrets/            generated passwords
#   clients/            the MSI/deb installers generated for this box
#   bundled_artifacts/  written by the backend at runtime
#
# Staying at depth 1 means none of those can be touched here. No deletion
# either: only files the package actually ships are considered, so anything
# local simply stays.
# ---------------------------------------------------------------------------
_intact_refresh_module_code() {
    local psrc="$1" pdst="$2" name="$3" f base d n=0
    [[ -d "$psrc" ]] || return 0

    while IFS= read -r f; do
        base="$(basename "$f")"
        # docker-compose.yaml is refreshed by the caller; .env is the
        # operator's and is never shipped over.
        case "$base" in
            docker-compose.yaml|.env|.env.*) continue ;;
        esac
        d="${pdst}/${base}"
        if [[ ! -f "$d" ]] || ! cmp -s "$f" "$d"; then
            mkdir -p "$pdst" 2>/dev/null
            if [[ -f "$d" ]]; then
                local keep="${SCRIPT_DIR}/data/upgrade-backups/${name}/${base}"
                mkdir -p "$(dirname "$keep")" 2>/dev/null
                cp -p "$d" "$keep" 2>/dev/null
            fi
            cp -p "$f" "$d" || return 1
            n=$((n + 1))
            log_info "    refreshed modules/${name}/${base}"
        fi
    done < <(find "$psrc" -maxdepth 1 -type f 2>/dev/null | sort)

    (( n )) && log_info "    modules/${name}: ${n} code file(s) refreshed"
    return 0
}

# Deliver every host-side bind-mount source the compose file names, when the
# package carries one and the destination is missing or is the empty directory
# Docker fabricated last time.
_intact_deliver_mount_assets() {
    local psrc="$1" pdst="$2" compose="$3"
    local rel
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        local s="${psrc}/${rel}" d="${pdst}/${rel}"

        # A bind-mounted DIRECTORY of config, e.g. elk's ./config/pipeline.
        #
        # This used to fall straight into the "nothing to deliver" branch
        # below, which only ever accepted a regular file -- so the contents of
        # any mounted directory were frozen at whatever the box first
        # installed, and a config fix shipped in a later release never
        # arrived. Found on a real 0726 -> current upgrade: `main` had added
        # `user`/`password` to logstash's elasticsearch output, the box kept
        # 0726's credential-less main.conf, and logstash crash-looped on 401
        # "missing authentication credentials for REST request" after an
        # upgrade that otherwise reported success.
        #
        # Same policy as a single file, applied per file inside: keep a copy
        # under data/upgrade-backups, then overwrite. That is a real judgement
        # call, because some of these directories also hold state written at
        # runtime (modules/timesketch/config is mounted rw for LLM settings),
        # so this can overwrite an operator's edit to a file the package also
        # ships. Leaving them stale is the worse failure: it silently withholds
        # every config fix a release makes, and it surfaces later as an
        # unrelated container crash-looping. The backup is what makes it
        # recoverable.
        if [[ -d "$s" ]]; then
            local sub
            while IFS= read -r sub; do
                [[ -n "$sub" ]] || continue
                local ss="${s}/${sub}" dd="${d}/${sub}"
                if [[ ! -f "$dd" ]] || ! cmp -s "$ss" "$dd"; then
                    mkdir -p "$(dirname "$dd")" 2>/dev/null
                    if [[ -f "$dd" ]]; then
                        local dkeep="${SCRIPT_DIR}/data/upgrade-backups/$(basename "$pdst")/${rel}/${sub}"
                        mkdir -p "$(dirname "$dkeep")" 2>/dev/null
                        cp -p "$dd" "$dkeep" 2>/dev/null
                    fi
                    cp -p "$ss" "$dd" || return 1
                    log_info "    delivered ${rel}/${sub}"
                fi
            done < <(cd "$s" && find . -type f -printf '%P\n' 2>/dev/null)
            continue
        fi

        if [[ ! -e "$s" || ! -f "$s" ]]; then
            # The package has nothing to deliver here. If the box has
            # nothing either, `docker compose up` will fabricate an EMPTY
            # DIRECTORY at this path -- and if the container expects a FILE
            # there, that is the exact exit-126 crash loop the cleanup
            # branch below exists to recover FROM on a later run. Naming it
            # now, before compose ever runs, turns that into a warning
            # instead of a mystery.
            # Only worth saying for a module that actually runs here. The
            # refresh walks every module's compose so a later-enabled one is
            # current, which means on a box with (say) only portainer up it was
            # warning about timesketch's llm_providers mount -- a module with
            # no containers, no data and nothing to break. Noise in an upgrade
            # log is not free: it trains people to skim past the line that
            # matters.
            if [[ -e "$d" ]] || ! _intact_module_is_enabled "$(basename "$pdst")"; then
                continue
            fi
            log_warn "    ${rel} is referenced by ${compose} but neither the package nor this box has it -- compose may fabricate an empty directory there"
            continue
        fi
        if [[ -d "$d" ]]; then
            if [[ -z "$(ls -A "$d" 2>/dev/null)" ]]; then
                # Docker's fabricated empty directory. Removing it is what
                # turns an exit-126 crash loop back into a working container.
                rmdir "$d" 2>/dev/null && log_info "    removed the empty directory Docker created at ${rel}"
            else
                log_warn "    ${rel} is a non-empty directory but the package ships a file; leaving it"
                continue
            fi
        fi
        if [[ ! -f "$d" ]] || ! cmp -s "$s" "$d"; then
            mkdir -p "$(dirname "$d")" 2>/dev/null
            # Keep what was there, under data/upgrade-backups, never beside
            # the original where it would be picked up as config.
            if [[ -f "$d" ]]; then
                local keep="${SCRIPT_DIR}/data/upgrade-backups/$(basename "$pdst")/${rel}"
                mkdir -p "$(dirname "$keep")" 2>/dev/null
                cp -p "$d" "$keep" 2>/dev/null
            fi
            cp -p "$s" "$d" || return 1
            log_info "    delivered ${rel}"
        fi
        # Verify what was just written is actually there and matches --
        # `cp`'s own exit code already covers most of this, but a race with
        # something else touching ${d} between the copy and now (a
        # concurrent recreate, a symlink resolving unexpectedly) would
        # otherwise go unnoticed until the container fails to start.
        if [[ ! -f "$d" ]] || ! cmp -s "$s" "$d"; then
            log_error "    ${rel} does not match the package after delivery"
            return 1
        fi
    done < <(grep -oE '^\s*-\s*\./[^:]+:' "$compose" 2>/dev/null | sed 's/^[[:space:]]*-[[:space:]]*\.\///; s/:$//')
    return 0
}
