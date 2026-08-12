#!/bin/bash
# Intact.AI upgrade — snapshot, restore, and mirror the platform's own
# trees: the backend (mandatory), and the frontend + upgrade engine itself
# (lib/, scripts/, install.sh) when the package carries them.

_intact_snapshot() {
    local snap="$1"
    mkdir -p "$snap" || return 1
    tar -C "${SCRIPT_DIR}/modules" -cf - \
        --exclude='__pycache__' --exclude='*.pyc' backend 2>/dev/null \
      | tar -C "$snap" -xf - 2>/dev/null || return 1
    log_info "  snapshotted modules/backend to ${snap}"

    # Frontend, upgrade engine, installer. Same rollback safety as the
    # backend snapshot above, but best-effort: these are new to this
    # module (see the mirror calls in intact.sh) and every box already has
    # them from its own install, so a snapshot failure here is logged, not
    # fatal -- it must not block a snapshot of the mandatory backend tree.
    if [[ -d "${SCRIPT_DIR}/modules/nginx/html" ]]; then
        mkdir -p "${snap}/nginx" 2>/dev/null
        tar -C "${SCRIPT_DIR}/modules/nginx" -cf - --exclude='downloads' html 2>/dev/null \
            | tar -C "${snap}/nginx" -xf - 2>/dev/null \
          && log_info "  snapshotted modules/nginx/html to ${snap}" \
          || log_warn "  could not snapshot modules/nginx/html"
    fi
    if [[ -d "${SCRIPT_DIR}/lib" ]]; then
        tar -C "${SCRIPT_DIR}" -cf - lib 2>/dev/null | tar -C "$snap" -xf - 2>/dev/null \
          && log_info "  snapshotted lib/ to ${snap}" \
          || log_warn "  could not snapshot lib/"
    fi
    if [[ -d "${SCRIPT_DIR}/scripts" ]]; then
        tar -C "${SCRIPT_DIR}" -cf - scripts 2>/dev/null | tar -C "$snap" -xf - 2>/dev/null \
          && log_info "  snapshotted scripts/ to ${snap}" \
          || log_warn "  could not snapshot scripts/"
    fi
    if [[ -f "${SCRIPT_DIR}/install.sh" ]]; then
        cp -p "${SCRIPT_DIR}/install.sh" "${snap}/install.sh" 2>/dev/null \
          || log_warn "  could not snapshot install.sh"
    fi

    # VERSION. _intact_stamp writes it BEFORE the backend is recreated, so a
    # recreate failure used to leave the file claiming the new tag while the
    # running image and BACKEND_VERSION were both rolled back to the old one
    # -- the pin-disagrees-with-reality state that is the hardest to diagnose
    # on a customer box. Observed after a failed 20260811 -> 20260813 recreate
    # on 2026-08-12. Restored in _intact_restore below.
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        cp -p "${SCRIPT_DIR}/VERSION" "${snap}/VERSION" 2>/dev/null \
          || log_warn "  could not snapshot VERSION"
    fi

    # data/intact.db: the appliance's own SQLite state (secrets, workflows,
    # blueprints) -- neither this engine nor the one it replaced protects it
    # anywhere else. Nothing here mirrors over data/, so it survives a
    # NORMAL upgrade untouched either way; this exists for the abnormal one
    # (a bad backend swap that gets rolled back after something already
    # wrote to the DB mid-run). Best-effort: no sqlite3 CLI on this box, so
    # this is a plain file copy of the main file plus its WAL/SHM sidecars
    # (present when the DB is in WAL mode) rather than a
    # `sqlite3 .backup`-consistent snapshot -- good enough for a pre-upgrade
    # safety copy, not a substitute for a real backup strategy. A failure
    # here is logged, never fatal: the module must not fail over a backup of
    # something it was never going to touch in the first place.
    local dbf="${SCRIPT_DIR}/data/intact.db" f
    if [[ -f "$dbf" ]]; then
        mkdir -p "${snap}/data" 2>/dev/null
        local copied=1
        for f in "$dbf" "${dbf}-wal" "${dbf}-shm"; do
            [[ -f "$f" ]] || continue
            cp -p "$f" "${snap}/data/" 2>/dev/null || copied=0
        done
        if (( copied )); then
            log_info "  snapshotted data/intact.db"
        else
            log_warn "  could not fully snapshot data/intact.db (continuing anyway)"
        fi
    fi
    return 0
}

_intact_restore() {
    local snap="$1"
    [[ -d "${snap}/backend" ]] || { log_error "  no snapshot at ${snap}"; return 1; }
    # .env and downloads/ are operator/runtime state, not code, and the
    # snapshot's copies are already correct -- but restoring downloads/ would
    # undo a velo refresh that succeeded independently.
    tar -C "$snap" -cf - --exclude='downloads' backend 2>/dev/null \
      | tar -C "${SCRIPT_DIR}/modules" -xf - 2>/dev/null || return 1

    # Same additions as the snapshot above, restored best-effort: a failure
    # here must not abort the rollback of the mandatory backend tree, which
    # is what actually determines whether the box comes back up.
    if [[ -d "${snap}/nginx/html" ]]; then
        tar -C "${snap}/nginx" -cf - --exclude='downloads' html 2>/dev/null \
            | tar -C "${SCRIPT_DIR}/modules/nginx" -xf - 2>/dev/null \
          || log_warn "  could not restore modules/nginx/html"
    fi
    if [[ -d "${snap}/lib" ]]; then
        tar -C "$snap" -cf - lib 2>/dev/null | tar -C "${SCRIPT_DIR}" -xf - 2>/dev/null \
          || log_warn "  could not restore lib/"
    fi
    if [[ -d "${snap}/scripts" ]]; then
        tar -C "$snap" -cf - scripts 2>/dev/null | tar -C "${SCRIPT_DIR}" -xf - 2>/dev/null \
          || log_warn "  could not restore scripts/"
    fi
    if [[ -f "${snap}/install.sh" ]]; then
        cp -p "${snap}/install.sh" "${SCRIPT_DIR}/install.sh" 2>/dev/null \
          || log_warn "  could not restore install.sh"
    fi
    if [[ -f "${snap}/VERSION" ]]; then
        cp -p "${snap}/VERSION" "${SCRIPT_DIR}/VERSION" 2>/dev/null \
          && log_info "  restored VERSION to $(cat "${snap}/VERSION" 2>/dev/null)" \
          || log_warn "  could not restore VERSION"
    fi

    # intact.db is NOT restored here. This engine never writes to data/ on
    # the forward path, so the live DB is still the correct one after a
    # rollback -- restoring the snapshot would UNDO any legitimate workflow
    # activity (a secret rotated, a blueprint saved) that happened to land
    # during the failed run, which is a worse outcome than leaving it alone.
    # The snapshot exists purely as a manual-recovery artifact for the case
    # that genuinely needs it.
    return 0
}

# Overwrite from the package, then PRUNE files the new release retired. An
# additive-only copy leaves a deleted module behind as a stale .py that still
# imports and still registers its routes.
#
# `marker` is a file relative to $src whose presence is the sanity check --
# refuse to mirror something that is not recognisably the tree it claims to
# be, rather than emptying the destination over a malformed or wrong-shaped
# package. Defaults to app.py for backward compatibility (the original,
# backend-only caller); the frontend/lib/scripts callers pass their own.
_intact_mirror() {
    local src="$1" dst="$2" marker="${3:-app.py}"
    [[ -d "$src" ]] || { log_error "  no source at ${src}"; return 1; }
    [[ -f "${src}/${marker}" ]] || { log_error "  ${src} has no ${marker}; refusing to mirror it"; return 1; }

    if command -v rsync >/dev/null 2>&1; then
        # '.env*' not '.env': --delete removes anything in the destination the
        # source lacks, and a bare '.env' exclude does not cover
        # '.env.upgrade-bak-*' or a '.env.local'. Losing the rollback backup
        # one step before the rollback needs it is not a theoretical concern.
        #
        # --checksum, not rsync's default quick-check: rsync's default skips
        # a file when size AND mtime already match the destination, WITHOUT
        # reading either one's content. A package extracted fresh from a
        # tarball routinely produces files whose mtime lands in the same
        # window as what is already on disk, and two DIFFERENT files landing
        # on the same byte count is not rare for short source files --
        # reproduced directly: `echo new` and `echo old` are both 4 bytes,
        # and a same-second mtime was enough for a bare `rsync -a --delete`
        # to silently skip the "changed" file entirely. --checksum compares
        # actual content, so nothing is ever skipped that genuinely differs.
        # This tree is source code, not a multi-GB media library, so the
        # extra read cost is not a concern.
        rsync -a --delete --checksum \
              --exclude='.env' --exclude='.env.*' --exclude='*.upgrade-bak-*' \
              --exclude='downloads/' --exclude='__pycache__/' \
              --exclude='*.pyc' --exclude='config/velociraptor/' \
              "${src}/" "${dst}/" >>"${LOG_FILE:-/dev/null}" 2>&1 || return 1
    else
        # No rsync: copy over the top, then remove files that exist in the
        # destination but not the source.
        tar -C "$src" -cf - --exclude='.env' --exclude='downloads' \
            --exclude='__pycache__' --exclude='*.pyc' . 2>/dev/null \
          | tar -C "$dst" -xf - 2>/dev/null || return 1
        local f rel
        while IFS= read -r f; do
            rel="${f#"${dst}/"}"
            case "$rel" in
                .env|.env.*|*.upgrade-bak-*|downloads/*|config/velociraptor/*|*__pycache__*|*.pyc) continue ;;
            esac
            [[ -e "${src}/${rel}" ]] || rm -f "$f"
        done < <(find "$dst" -type f 2>/dev/null)
    fi
    log_info "  mirrored $(basename "$dst")"
    return 0
}

# install.sh is a single file at the appliance root, not a directory --
# _intact_mirror's rsync/tar --delete machinery doesn't apply to it. A
# package built before the full-repo source/intact/ layout existed carries
# no install.sh at all; skip rather than fail, since that is a legacy
# package shape, not an error.
_intact_mirror_install_sh() {
    local src="$1"
    local s="${src}/install.sh" d="${SCRIPT_DIR}/install.sh"
    if [[ ! -f "$s" ]]; then
        log_warn "  package has no install.sh — this box's installer will not be updated (legacy package layout?)"
        return 0
    fi
    cmp -s "$s" "$d" 2>/dev/null && return 0
    cp -p "$s" "$d" || { log_error "  could not copy install.sh"; return 1; }
    log_info "  updated install.sh"
    return 0
}
