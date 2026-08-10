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
        return 1
    fi

    # 1. config.yaml: merge the release's pins in, then run schema migrations.
    #    Both edit in place; see _intact_merge_versions for why that matters.
    u_do "merge version pins into config.yaml" -- _intact_merge_versions "$src"
    u_do "apply config.yaml schema migrations" -- _intact_config_migrations

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

    # 3. Mirror the new code in.
    u_do --timeout 600 "mirror the backend tree" -- _intact_mirror "${src}/modules/backend" "${SCRIPT_DIR}/modules/backend"
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

# ---------------------------------------------------------------------------
# config.yaml
#
# Merges only the `versions:` block from the package's config.yaml into the
# operator's. Text-level and key-by-key, never a yaml load+dump: the operator's
# file carries their github_token, module passwords, domain and the comments
# above half the pins, and a round-trip deletes all of it.
#
# Uses _pin_module_version (lib/config.sh), which truncates the real file in
# place rather than renaming a temp over it -- config.yaml is bind-mounted into
# the backend BY INODE, so a rename leaves the container reading the old file
# while the edit sits on disk looking applied.
# ---------------------------------------------------------------------------
_intact_merge_versions() {
    local src="$1"
    local new="${src}/config.yaml"
    [[ -f "$new" ]] || { log_info "  package carries no config.yaml; keeping local pins"; return 0; }

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-upgrade-backup" 2>/dev/null

    local pairs
    pairs="$(python3 - "$new" <<'PY'
import sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    raise SystemExit(0)
for k, v in (d.get("versions") or {}).items():
    if v is None or str(v).strip() == "":
        continue
    print("%s\t%s" % (k, v))
PY
)"
    [[ -n "$pairs" ]] || { log_info "  package config.yaml has no versions block"; return 0; }

    local n=0 key val cur
    while IFS=$'\t' read -r key val; do
        [[ -n "$key" ]] || continue
        cur="$(read_config "['versions']['${key}']" 2>/dev/null || echo '')"
        [[ "$cur" == "$val" ]] && continue
        _pin_module_version "$key" "$val" && n=$((n + 1))
    done <<< "$pairs"
    log_info "  merged ${n} version pin(s) from the package into config.yaml"
    return 0
}

# The registry currently holds exactly one migration, 1 -> 2: consolidate the
# renamed cloudtrail/prowler modules into aws_sigma, carrying `enabled`
# forward. It does NOT rename the CLOUDTRAIL_VERSION env var -- that is a
# compat contract with every consumer of it.
_intact_config_migrations() {
    local current
    current="$(read_config "['schema_version']" 2>/dev/null || echo '')"
    [[ "$current" == "None" || -z "$current" ]] && current=1

    local CURRENT_SCHEMA_VERSION=2
    if (( current >= CURRENT_SCHEMA_VERSION )); then
        log_info "  config.yaml schema is current (v${current})"
        return 0
    fi

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-migration-backup" 2>/dev/null
    log_info "  migrating config.yaml schema v${current} -> v${CURRENT_SCHEMA_VERSION}"

    if ! python3 - "$CONFIG_FILE" <<'PY'
import re, sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").readlines()
out, changed = [], False

# modules.cloudtrail / modules.prowler -> modules.aws_sigma, keeping enabled.
for ln in lines:
    m = re.match(r"^(\s+)(cloudtrail|prowler)(\s*:\s*)$", ln)
    if m and m.group(2) == "cloudtrail":
        out.append("%saws_sigma%s\n" % (m.group(1), m.group(3))); changed = True; continue
    m2 = re.match(r"^(\s+)cloudtrail(\s*:\s*)(.+)$", ln)
    if m2:
        out.append("%saws_sigma%s%s\n" % (m2.group(1), m2.group(2), m2.group(3)))
        changed = True; continue
    out.append(ln)

# Stamp the new schema_version, inserting it first if absent.
for i, ln in enumerate(out):
    if re.match(r"^schema_version\s*:", ln):
        out[i] = "schema_version: 2\n"; break
else:
    out.insert(0, "schema_version: 2\n")

payload = "".join(out)
# Truncate in place: config.yaml is bind-mounted by inode.
with open(path, "w", encoding="utf-8") as fh:
    fh.write(payload); fh.flush()
    import os; os.fsync(fh.fileno())
PY
    then
        log_error "  schema migration failed; restoring config.yaml"
        cp -p "${CONFIG_FILE}.pre-migration-backup" "$CONFIG_FILE" 2>/dev/null
        return 1
    fi
    log_success "  config.yaml migrated to schema v${CURRENT_SCHEMA_VERSION}"
    return 0
}

# ---------------------------------------------------------------------------
# Tree snapshot / mirror / restore
# ---------------------------------------------------------------------------
_intact_snapshot() {
    local snap="$1"
    mkdir -p "$snap" || return 1
    tar -C "${SCRIPT_DIR}/modules" -cf - \
        --exclude='__pycache__' --exclude='*.pyc' backend 2>/dev/null \
      | tar -C "$snap" -xf - 2>/dev/null || return 1
    log_info "  snapshotted modules/backend to ${snap}"
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

# Sidecar compose files and the files they bind-mount. THE MOUNT ASSET RULE:
# if a compose file arrives referencing a bind-mounted file that is not on
# disk, Docker fabricates an empty DIRECTORY at the mount path and the
# container dies with exit 126. So the compose file and its assets have to
# land together.
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
        [[ -e "$s" ]] || continue
        [[ -f "$s" ]] || continue
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
    done < <(grep -oE '^\s*-\s*\./[^:]+:' "$compose" 2>/dev/null | sed 's/^[[:space:]]*-[[:space:]]*\.\///; s/:$//')
    return 0
}

# ---------------------------------------------------------------------------
# Image, compile gate, swap
# ---------------------------------------------------------------------------
# NOT _u_ensure_image. intact-backend is built by CI and shipped in the
# package; it exists in NO registry, so the generic helper's pull fallback can
# only ever produce "pull access denied for intact-backend, repository does
# not exist" -- which reads like a credentials problem and is really a missing
# asset. Present, or loaded from the package's tar, or a clear failure.
_intact_ensure_image() {
    local target="$1" ref="intact-backend:${target}"

    if _u_image_present "$ref"; then
        log_info "  ${ref} already present"
        return 0
    fi

    local tar
    for tar in "${UPKG_DIR}/images/intact-backend-${target}.tar" \
               "${UPKG_DIR}/images/intact-backend-${target}.tar.gz"; do
        [[ -f "$tar" ]] || continue
        log_info "  loading ${ref} from $(basename "$tar")"
        if RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "loading the backend image" 1800 \
             bash -c '"$1" load -i "$2" >>"$3" 2>&1' _ "${DOCKER_BIN:-docker}" \
             "$tar" "${LOG_FILE:-/dev/null}"; then
            _u_image_present "$ref" && return 0
            log_error "  ${tar} loaded but ${ref} is still absent"
            return 1
        fi
        log_error "  could not load $(basename "$tar")"
        return 1
    done

    log_error "  ${ref} is not present and this package carries no backend image."
    log_error "  intact-backend is built by CI and shipped inside the release package;"
    log_error "  it is not published to any registry, so there is nothing to pull."
    log_error "  This package was built without --module intact, or its image tar is missing."
    return 1
}

# Import-check the mirrored tree inside the TARGET image, before anything
# restarts. A syntax error or a missing dependency turns into a clean rollback
# here instead of a backend that will not boot.
_intact_compile_gate() {
    local target="$1"
    # PYTHONPYCACHEPREFIX is what makes this work against a read-only mount.
    # compileall's whole job is to WRITE .pyc files, so with /src:ro every
    # single file "fails" with OSError: Read-only file system -- a gate that
    # rejects perfectly good code. Redirecting the cache into the container's
    # own /tmp keeps the real check (does every module parse?) and drops the
    # side effect. The mount stays read-only: this must not be able to leave
    # anything behind in the tree it is inspecting.
    if ! "${DOCKER_BIN:-docker}" run --rm \
            -v "${SCRIPT_DIR}/modules/backend:/src:ro" \
            -e PYTHONPYCACHEPREFIX=/tmp/intact-compile-check \
            --entrypoint python3 "intact-backend:${target}" \
            -m compileall -q /src >>"${LOG_FILE:-/dev/null}" 2>&1; then
        log_error "  the mirrored backend tree does not compile under intact-backend:${target}"
        log_error "  Refusing to restart the backend onto code that cannot import."
        return 1
    fi
    log_success "  the new backend tree compiles"
    return 0
}

_intact_stamp() {
    local envf="$1" target="$2"
    _u_stamp "$envf" "BACKEND_VERSION=${target}" || return 1
    # INTACT_HOST_PATH must survive a recreate: compose resolves its `:-`
    # default on any recreate, so a non-default install path breaks silently.
    _u_stamp "$envf" "INTACT_HOST_PATH=${SCRIPT_DIR}" || return 1
    printf '%s\n' "$target" > "${SCRIPT_DIR}/VERSION" || return 1
    _pin_module_version backend "$target" || true
    return 0
}

_intact_bring_up() {
    ( cd "${SCRIPT_DIR}/modules/backend" \
      && "${DOCKER_BIN:-docker}" compose up -d --no-build --pull never backend \
         >>"${LOG_FILE:-/dev/null}" 2>&1 )
}

_intact_recreate_sidecars() {
    ( cd "${SCRIPT_DIR}/modules/backend" \
      && "${DOCKER_BIN:-docker}" compose up -d --no-build --pull never tusd \
         >>"${LOG_FILE:-/dev/null}" 2>&1 ) || true
    ( cd "${SCRIPT_DIR}/modules/nginx" \
      && "${DOCKER_BIN:-docker}" compose up -d --no-build --pull never --force-recreate \
         >>"${LOG_FILE:-/dev/null}" 2>&1 ) || true
    return 0
}

# One-time cleanup of the state the old in-container engine left behind. The
# upgrade_state table only ever existed so a half-finished upgrade could resume
# across the backend restarting itself; nothing resumes anything now, and a
# stale row would make the old engine (if it is still present) believe an
# upgrade is in flight. Historical automation_runs rows are KEPT -- they are
# the audit trail of past upgrades and the Workflows view still reads them.
_intact_clear_legacy_upgrade_state() {
    local db="${SCRIPT_DIR}/data/intact.db"
    [[ -f "$db" ]] || return 0
    python3 - "$db" <<'PY' >>"${LOG_FILE:-/dev/null}" 2>&1 || true
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
# Each statement committed independently. automation_runs does not exist on
# every box, and sharing one transaction meant its "no such table" rolled the
# upgrade_state DROP back with it -- the cleanup would silently do nothing on
# exactly the boxes that have the simpler schema.
for sql in (
    "DROP TABLE IF EXISTS upgrade_state",
    """UPDATE automation_runs SET status='cancelled'
         WHERE automation_type IN ('upgrade','online_upgrade','prepare_package',
                                   'upgrade_package_upload')
           AND status IN ('running','pending')""",
):
    try:
        c.execute(sql); c.commit()
    except sqlite3.Error as e:
        print("  (skipped: %s)" % e)
c.close()
PY
    rm -f "${SCRIPT_DIR}/data/backend-source.applied.sha256" \
          "${SCRIPT_DIR}"/data/tmp/backend-selfheal-*.attempted 2>/dev/null
    return 0
}
