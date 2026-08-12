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
#   velociraptor configs  already inside the velociraptor_datastore VOLUME,
#                         which is why its CA survives upgrades that lose other
#                         things. Moving them to a host path is a regression.
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
#       Already persistent, and already outside the source tree -- which is why
#       the Velociraptor CA survives upgrades that lose other things. Moving it
#       to a host path would be a regression.
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
    [[ -L "${root}/${rel}" ]] || return 1
    local tgt; tgt="$(readlink "${root}/${rel}" 2>/dev/null)" || return 1
    [[ "$tgt" == *"data/state/"* ]]
}

# Move one registered path into data/state and leave a relative symlink behind.
#
# Relative, not absolute: the appliance root is wherever the operator extracted
# it, and an absolute link would break the moment a box is moved or restored to
# a different directory -- which is exactly what a disaster-recovery restore
# does.
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
            # Both exist: the live copy is the one the box has been running
            # with, so it wins. Keep the other as .superseded rather than
            # deleting anything that might be the only copy of a CA.
            mv "$canon" "${canon}.superseded.$$" 2>/dev/null || true
        fi
        mv "$live" "$canon" || return 1
    elif [[ ! -e "$canon" ]]; then
        # Nothing to migrate and nothing stored: the generator has not run yet.
        # Leaving no symlink is correct -- the generator creates a real file at
        # the old path and the next migration picks it up.
        return 0
    fi

    # Link the historical path at the stored one, relative to its own directory.
    local up; up="$(dirname "$rel")"
    local depth; depth="$(awk -F/ '{print NF}' <<< "$up")"
    local prefix=""; local i
    for (( i = 0; i < depth; i++ )); do prefix+="../"; done
    rm -rf "$live" 2>/dev/null
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
