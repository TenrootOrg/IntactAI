#!/usr/bin/env bash
# Per-box STATE — the files an upgrade must never lose and a package can never
# ship.
#
# THE PROBLEM THIS SOLVES. Box state lived interleaved with code under
# modules/, and an upgrade replaces code. Every field failure of the
# 20260726 -> 20260811 chain was a consequence: portainer's secrets/agent.env
# and the shared TLS pair are generated per box, CI's secret scan rejects
# secrets/ so no package can carry them, and the new composes that reference
# them arrived on boxes that had never created them. Docker then fabricates an
# empty DIRECTORY at each missing bind-mount source and the container dies --
# "read /certs/cert.pem: is a directory", or elk's exit 126.
#
# THE FIX. data/ is the one tree nothing mirrors over (see lib/upgrade/intact/
# tree.sh: the snapshot copies modules/backend, modules/nginx/html, lib/ and
# scripts/ -- never data/). So data/state/ becomes the canonical home, and a
# SYMLINK is left at the historical path.
#
# WHY SYMLINKS, AND NOT REPOINTED COMPOSE FILES. A 20260726 appliance is
# already shipped and cannot be changed. If the migration required composes
# that point at data/state/..., those composes would land on a box that has no
# such directory yet -- reintroducing the exact "new compose demands a file the
# box lacks" failure this is meant to end. With a symlink at the old path:
#
#   * every existing compose keeps working, unchanged, on every version;
#   * generators keep writing to the old path and land in data/state/
#     automatically, because openssl -out and cp follow the symlink;
#   * a rollback to the previous release still works, because the old code
#     reads the same paths it always did.
#
# So the migration is invisible in both directions, which is what makes it
# safe to run on a box mid-upgrade.
#
# WHAT IS DELIBERATELY NOT HERE
#   modules/*/.env        half state (ELASTIC_PASSWORD) and half pins
#                         (ELASTIC_VERSION) that _u_stamp must rewrite. Moving
#                         the file would move the pins with it. Splitting them
#                         is its own change; until then .env stays put.
#   velociraptor configs  now a HOST path, data/velociraptor/ -- already under
#                         data/, so there is nothing for this registry to move.
#                         (This entry used to claim they lived in the
#                         velociraptor_datastore volume "which is why the CA
#                         survives upgrades". That was wrong twice over:
#                         velociraptor_datastore mounts /var. -- the hunt
#                         datastore -- and the CA was in velociraptor_data,
#                         a SEPARATE volume the host-mount conversion dropped
#                         from the compose file. Believing this comment is why
#                         Velociraptor was left out of the migration and why a
#                         real 0615 -> 0813 run silently minted a new CA. The
#                         volume -> host recovery now lives in
#                         lib/upgrade/velociraptor/snapshot.sh.)
#   data/intact.db        already under data/. Nothing to do.

# Relative to the appliance root. Directories are moved whole.
#
# Derived empirically, not from memory: on a real appliance everything the box
# generated shows up as untracked or ignored under modules/, which is exactly
# `git status --porcelain --ignored modules/`. Re-run that after adding a
# module and anything new is a candidate for this list.
STATE_PATHS=(
    "modules/nginx/ssl/nginx-cert.crt"
    "modules/nginx/ssl/nginx-cert.key"
    "modules/portainer/secrets/agent.env"
    "modules/portainer/secrets/admin_password"
    "modules/iris/config/certificates/rootCA"
    "modules/iris/config/certificates/web_certificates"
    # IRIS_SECRET_KEY, the password salt, and BOTH postgres passwords. Losing
    # these does not merely reset a login: iris_app authenticates to its own
    # database with POSTGRES_PASSWORD, so a regenerated value locks the
    # appliance out of its existing case data.
    "modules/iris/secrets"
    # SECRET_KEY is randomized per box at install (see the installer's
    # "timesketch.conf created from template ... SECRET_KEY randomized").
    "modules/timesketch/config/timesketch.conf"
    "modules/timesketch/config/timesketch_legacy.conf"
    # postgres.env — the Timesketch database password, generated per box and
    # 0600. It was in NEITHER list, which is how a real 0813 run came to log
    # "already at 20260630, but secrets/postgres.env is missing — re-applying
    # instead of skipping": the file had simply not survived. The engine does
    # recover (it rotates the role's password to match the regenerated file), so
    # this is protection against churn rather than data loss -- but it is box
    # state living under modules/, which is exactly what this registry is for,
    # and iris/secrets is already here for the same reason.
    "modules/timesketch/secrets"
)

# STATE, but deliberately NOT moved. Listed so the inventory is honest and so
# backup tooling has one place to read -- not every piece of box state can be
# relocated safely.
#
#   modules/*/.env
#       Half state, half pins: VOLWEB_POSTGRES_PASSWORD next to
#       VOLWEB_BACKEND_VERSION, ELASTIC_PASSWORD next to ELASTIC_VERSION.
#       _u_stamp rewrites the pins in place, so moving the file would move the
#       pins out of reach of the code that maintains them. Splitting secrets
#       out of .env is its own change. Note volweb/.env is the one that is not
#       tracked in git at all -- it exists only on the box, so it is the .env
#       most easily lost and the least obviously missing.
#
#   modules/nginx/html/downloads/, modules/velociraptor/clients/
#       Box-specific but re-derivable (the repacked clients come from the CA,
#       which IS protected) and large enough that copying them would dominate
#       every migration. The upgrade already excludes downloads/ from its
#       snapshot for the same reason.
#
#   velociraptor_datastore volume
#       Already persistent and outside the source tree. It holds the hunt/flow
#       datastore (mounted at /var.), NOT the CA -- see the correction in the
#       header above. Moving it to a host path would be a regression.
STATE_INPLACE=(
    "modules/volweb/.env"
    "modules/elk/.env"
    "modules/iris/.env"
    "modules/timesketch/.env"
    "modules/portainer/.env"
    "modules/backend/.env"
)

# Where a registered path is stored. modules/ is stripped so the tree reads
# data/state/<module>/... rather than data/state/modules/<module>/...
state_canonical_path() {
    printf 'data/state/%s\n' "${1#modules/}"
}

# True when the path has already been migrated (is a symlink into data/state).
state_is_migrated() {
    local root="$1" rel="$2"
    local live="${root}/${rel}"
    local canon="${root}/$(state_canonical_path "$rel")"
    if [[ -L "$live" ]]; then
        local tgt; tgt="$(readlink "$live" 2>/dev/null)" || return 1
        [[ "$tgt" == *"data/state/"* ]] || return 1
        # A FILE behind a symlink is only HALF migrated. Containers that
        # bind-mount the file's parent DIRECTORY (./config:/etc/timesketch)
        # see the symlink itself, and its relative target — ../../../data/…
        # — does not exist inside the container. tsctl then ran against no
        # config at all, "succeeded", and wrote its stamp nowhere. Report
        # not-migrated so the migration replaces the symlink with a hard
        # link (below). Directory entries stay symlinks: directories cannot
        # be hard-linked, and compose files bind them per-path, which Docker
        # resolves on the host at container create.
        [[ -f "$canon" ]] && return 1
        return 0
    fi
    # Hard-linked file: same inode on both paths.
    [[ -e "$live" && "$live" -ef "$canon" ]]
}

# Move one registered path into data/state and leave a relative symlink behind.
#
# Relative, not absolute: the appliance root is wherever the operator extracted
# it, and an absolute link would break the moment a box is moved or restored to
# a different directory -- which is exactly what a disaster-recovery restore
# does.
# "Empty skeleton": a path carrying no state — a zero-byte file, or a
# directory whose only content is git placeholder files. This is exactly what
# the tracked repo ships at state paths (modules/iris/…/rootCA/.gitkeep), so
# it is what a package-delivery step recreates; nothing the box GENERATES at
# these paths ever looks like this.
_state_is_empty_skeleton() {
    local p="$1"
    if [[ -f "$p" ]]; then
        [[ ! -s "$p" ]]
        return
    fi
    [[ -d "$p" ]] || return 1
    local f
    while IFS= read -r f; do
        case "$(basename "$f")" in
            .gitkeep|.gitignore) : ;;
            *) return 1 ;;
        esac
    done < <(find "$p" -mindepth 1 2>/dev/null)
    return 0
}

state_migrate_one() {
    local root="$1" rel="$2"
    local live="${root}/${rel}"
    local canon_rel; canon_rel="$(state_canonical_path "$rel")"
    local canon="${root}/${canon_rel}"

    state_is_migrated "$root" "$rel" && return 0

    mkdir -p "$(dirname "$canon")" 2>/dev/null || return 1

    if [[ -e "$live" && ! -L "$live" ]]; then
        # Real file or directory still at the historical path.
        if [[ -e "$canon" ]]; then
            # Both exist. The live copy NORMALLY wins -- it is the one the box
            # has been running with (verified live: timesketch.conf's live
            # copy carried the migrated postgres credential while the stored
            # one was stale).
            #
            # EXCEPT when the live copy is an empty skeleton. The package
            # tracks placeholder dirs (.gitkeep) at several state paths, and
            # a delivery step recreating one of those OVER the symlink must
            # not dethrone real state: on a live box this exact case moved
            # the IRIS CA, web certs and ALL FIVE iris secrets (including the
            # postgres password guarding existing case data) aside into
            # .superseded and left .gitkeep-only dirs as canonical -- the
            # next iris recreate would have regenerated secrets and locked
            # the appliance out of its own database.
            if _state_is_empty_skeleton "$live" && ! _state_is_empty_skeleton "$canon"; then
                rm -rf "$live" 2>/dev/null
            else
                mv "$canon" "${canon}.superseded.$$" 2>/dev/null || true
            fi
        fi
        if [[ -e "$live" ]]; then
            mv "$live" "$canon" || return 1
        fi
    elif [[ ! -e "$canon" ]]; then
        # Nothing to migrate and nothing stored: the generator has not run yet.
        # Leaving no symlink is correct -- the generator creates a real file at
        # the old path and the next migration picks it up.
        return 0
    fi

    # Link the historical path at the stored one.
    #
    # FILES get a HARD link: a real file at both paths, so a container that
    # bind-mounts the parent directory reads real content — the symlink form
    # dangled inside every timesketch container (its relative target lives
    # outside the mounted directory) and tsctl "stamped" a database it never
    # reached. Host-side generators keep working: the render/openssl writers
    # truncate in place, which updates the shared inode. data/ still survives
    # every mirror because the inode lives on regardless of which name a tree
    # operation removes; the next migration run re-links whichever side is
    # missing.
    #
    # DIRECTORIES keep the relative symlink (directories cannot be
    # hard-linked); their composes bind them per-path, which Docker resolves
    # on the host at container create — verified live by IRIS, whose cert
    # dirs are migrated and whose stack is healthy.
    rm -rf "$live" 2>/dev/null
    if [[ -f "$canon" ]]; then
        ln "$canon" "$live" 2>/dev/null && return 0
        # Cross-device (data/ on another filesystem): fall through to the
        # symlink, which at least keeps every host-side path working.
    fi
    local up; up="$(dirname "$rel")"
    local depth; depth="$(awk -F/ '{print NF}' <<< "$up")"
    local prefix=""; local i
    for (( i = 0; i < depth; i++ )); do prefix+="../"; done
    ln -s "${prefix}${canon_rel}" "$live" || return 1
    return 0
}

# Reverse one migration: put the real file back at the historical path.
state_unmigrate_one() {
    local root="$1" rel="$2"
    local live="${root}/${rel}"
    local canon="${root}/$(state_canonical_path "$rel")"
    state_is_migrated "$root" "$rel" || return 0
    [[ -e "$canon" ]] || { rm -f "$live" 2>/dev/null; return 0; }
    rm -f "$live" 2>/dev/null
    mv "$canon" "$live" || return 1
    return 0
}
