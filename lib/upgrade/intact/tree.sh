#!/bin/bash
# Intact.AI upgrade — the backend tree: snapshot, restore, mirror.

_intact_snapshot() {
    local snap="$1"
    mkdir -p "$snap" || return 1
    tar -C "${SCRIPT_DIR}/modules" -cf - \
        --exclude='__pycache__' --exclude='*.pyc' backend 2>/dev/null \
      | tar -C "$snap" -xf - 2>/dev/null || return 1
    log_info "  snapshotted modules/backend to ${snap}"

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
_intact_mirror() {
    local src="$1" dst="$2"
    [[ -d "$src" ]] || { log_error "  no backend source at ${src}"; return 1; }
    # Sanity: refuse to mirror something that is not recognisably the backend,
    # rather than emptying the directory over a malformed package.
    [[ -f "${src}/app.py" ]] || { log_error "  ${src} has no app.py; refusing to mirror it"; return 1; }

    if command -v rsync >/dev/null 2>&1; then
        # '.env*' not '.env': --delete removes anything in the destination the
        # source lacks, and a bare '.env' exclude does not cover
        # '.env.upgrade-bak-*' or a '.env.local'. Losing the rollback backup
        # one step before the rollback needs it is not a theoretical concern.
        rsync -a --delete \
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
    log_info "  mirrored the backend tree"
    return 0
}
