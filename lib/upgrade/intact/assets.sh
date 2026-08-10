#!/bin/bash
# Intact.AI upgrade — sidecar compose files and the files they bind-mount.
#
# THE MOUNT ASSET RULE: if a compose file arrives referencing a bind-mounted
# file that is not on disk, Docker fabricates an empty DIRECTORY at the mount
# path and the container dies with exit 126. So the compose file and its
# assets have to land together.
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
    done
    log_info "  refreshed ${n} sidecar compose file(s)"
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

        if [[ ! -e "$s" || ! -f "$s" ]]; then
            # The package has nothing to deliver here. If the box has
            # nothing either, `docker compose up` will fabricate an EMPTY
            # DIRECTORY at this path -- and if the container expects a FILE
            # there, that is the exact exit-126 crash loop the cleanup
            # branch below exists to recover FROM on a later run. Naming it
            # now, before compose ever runs, turns that into a warning
            # instead of a mystery.
            [[ -e "$d" ]] || log_warn "    ${rel} is referenced by ${compose} but neither the package nor this box has it -- compose may fabricate an empty directory there"
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
