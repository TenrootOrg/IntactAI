#!/bin/bash
# Intact.AI upgrade — the platform itself (backend + frontend + sidecar files).
#
# This module is the reason the whole engine moved to the host. Inside the
# container it was replacing, swapping the backend needed a two-phase
# awaiting_restart handoff, an upgrade_state table that survived the restart,
# a detached helper container spawned from the outgoing image, a 120s x2
# watchdog, a boot-time self-heal and a source fingerprint -- about 1,475
# lines whose entire job was surviving its own suicide.
#
# From the host the backend is just another container. Mirror the new tree in,
# check it compiles, `compose up -d backend`, poll /api/health. What is kept is
# the part that protected the OPERATOR rather than the upgrader: a snapshot of
# the tree, a compile gate before anything restarts, and a restore on failure.
#
# Runs FIRST in UPGRADE_ORDER, always: it carries the new sidecar compose
# files and the config.yaml versions merge that every later module reads its
# pins from.
#
# Sibling files: config.sh (the version-pin merge, schema migration, and
# post-merge validation), tree.sh (snapshot/restore/mirror of the backend,
# frontend, and the upgrade engine itself -- lib/, scripts/, install.sh),
# assets.sh (sidecar compose files and their bind-mount assets), image.sh (the
# backend image, the compile gate, and the actual swap).

upgrade_module_intact() {
    local target="$1"
    local src=""
    local snap="${SCRIPT_DIR}/data/tmp/intact-rollback-$(date +%Y%m%d_%H%M%S)"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin intact

    # New layout first, legacy second. Packages cut before the tarball change
    # carry source/backend + source/frontend instead of source/intact.
    if [[ -d "${UPKG_DIR}/source/intact" ]]; then
        src="${UPKG_DIR}/source/intact"
    elif [[ -d "${UPKG_DIR}/source/backend" ]]; then
        src="${UPKG_DIR}/source"
        log_info "  package uses the legacy source/{backend,frontend} layout"
    else
        log_error "  package carries no source tree; cannot upgrade the platform"
        UPGRADE_FAILED+=("intact — no source tree in the package")
        # Not u_end: nothing was ever u_do'd, so there is no undo stack to
        # unwind and no container state worth health-probing. But U_MODULE
        # must not stay "intact" past this return -- every OTHER exit from a
        # module function goes through u_end, which is what clears it, and
        # skipping that here left it dangling for whatever ran next to
        # potentially see.
        U_MODULE=""
        U_UNDO=()
        return 1
    fi

    # 1. config.yaml: merge the release's pins in, then run schema migrations.
    #    Both edit in place; see _intact_merge_versions for why that matters.
    u_do "merge version pins into config.yaml" -- _intact_merge_versions "$src"
    u_do "apply config.yaml schema migrations" -- _intact_config_migrations
    u_do "validate config.yaml pins" -- _intact_validate_config_pins

    # 2. Snapshot before touching anything, and register the undos coarsest
    #    first so the tree is back before the container that runs it restarts.
    u_do "snapshot the platform tree" -- _intact_snapshot "$snap"
    # The .env backup goes NEXT TO THE SNAPSHOT, not beside the file. Every
    # other module can back up in place, but this one then mirrors a new tree
    # over modules/backend with rsync --delete -- and `--exclude='.env'` does
    # not match `.env.upgrade-bak-*`, so the backup is deleted a second before
    # it is needed. That is exactly what happened on the first live run: the
    # restore reported "no backup to restore" and the module landed in
    # NEEDS MANUAL REPAIR.
    bak=""
    if [[ -f "$envf" ]]; then
        bak="${snap}/backend.env.bak"
        cp -p "$envf" "$bak" 2>/dev/null || bak=""
    fi
    u_undo "_intact_bring_up"
    # Order matters: the .env restore must run AFTER the tree restore, because
    # the snapshot's tree also carries a copy of .env.
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"
    u_undo "_intact_restore '${snap}'"

    # 3. Mirror the new code in. Backend is mandatory -- every package
    #    layout carries it. The frontend and the upgrade engine itself
    #    (lib/, scripts/, install.sh) are best-effort: a package built
    #    before the full-repo source/intact/ layout existed (legacy
    #    source/{backend,frontend} shape) genuinely does not carry them, and
    #    a missing frontend/engine mirror must not brick an otherwise-good
    #    backend upgrade. Skipping them silently was the actual bug: without
    #    this, an upgraded box never gets a UI update (the restored Actions
    #    UI cards would only ever appear after a fresh install.sh) and never
    #    regains scripts/upgrade.sh + lib/upgrade/ -- so it could not
    #    self-upgrade again even though the box it upgraded FROM could.
    u_do --timeout 600 "mirror the backend tree" -- _intact_mirror "${src}/modules/backend" "${SCRIPT_DIR}/modules/backend"
    if [[ -d "${src}/modules/nginx/html" ]]; then
        u_do --timeout 300 "mirror the frontend" -- _intact_mirror "${src}/modules/nginx/html" "${SCRIPT_DIR}/modules/nginx/html" "index.html"
    else
        log_warn "  package has no modules/nginx/html — the dashboard UI will not be updated"
    fi
    if [[ -d "${src}/lib" ]]; then
        u_do --timeout 120 "mirror lib/" -- _intact_mirror "${src}/lib" "${SCRIPT_DIR}/lib" "common.sh"
    else
        log_warn "  package has no lib/ — this box's upgrade engine will not be updated"
    fi
    if [[ -d "${src}/scripts" ]]; then
        u_do --timeout 120 "mirror scripts/" -- _intact_mirror "${src}/scripts" "${SCRIPT_DIR}/scripts" "upgrade.sh"
    else
        log_warn "  package has no scripts/ — this box's upgrade engine will not be updated"
    fi
    u_do "mirror install.sh" -- _intact_mirror_install_sh "$src"
    u_do --timeout 600 "refresh sidecar compose files and assets" -- _intact_refresh_sidecars "$src"

    # 4. The image, then the compile gate BEFORE anything restarts. A backend
    #    that cannot import is a bricked appliance, and the gate is what turns
    #    that into a clean rollback instead.
    u_do --timeout 1800 "ensure intact-backend:${target}" -- _intact_ensure_image "$target"
    u_do --timeout 300 "verify the new backend compiles" -- _intact_compile_gate "$target"

    # 5. Swap.
    u_do "stamp BACKEND_VERSION and VERSION" -- _intact_stamp "$envf" "$target"
    u_do "stamp backend sidecar pins" -- _u_stamp_transitive intact
    u_do --timeout 600 "recreate the backend" -- _intact_bring_up

    u_end intact rollback 240
    local rc=$?
    if (( rc == 0 )); then
        discard_backup "$bak"
        rm -rf "$snap"
        # Sidecars that proxy the backend cache its IP; recreating them after
        # the swap is what stops a 502 that looks like the upgrade failed.
        _intact_recreate_sidecars || log_warn "  could not recreate tusd/nginx"
        _intact_clear_legacy_upgrade_state || true
    else
        log_warn "  the pre-upgrade tree snapshot is kept at ${snap}"
    fi
    return $rc
}
