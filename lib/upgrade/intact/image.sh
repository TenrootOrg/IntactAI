#!/bin/bash
# Intact.AI upgrade — the backend image, the compile gate, and the swap
# itself.

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
# upgrade is in flight. Historical run rows are KEPT -- they are the audit
# trail of past upgrades and the Workflows view still reads them.
#
# THE ROW-CANCELLING SWEEP IS GONE, DELIBERATELY. It used to
# `UPDATE automation_runs SET status='cancelled'` for every running
# upgrade/online_upgrade/prepare_package/upgrade_package_upload row, to clear
# runs the old engine had abandoned when it restarted itself. Two reasons it
# must not come back:
#
#   1. It never worked. The table is `workflows`, not `automation_runs` (see
#      services/storage/base.py) -- so the UPDATE has always raised "no such
#      table" and been swallowed by the except below. Nothing has ever been
#      cancelled by it on any box.
#   2. Now that an upgrade can be STARTED FROM THE UI, the run it would cancel
#      is the run driving this very upgrade. `add_log_to_run` silently drops
#      every log line once a run is `cancelled`
#      (services/workflow_service.py), so "fixing" the table name would make a
#      UI-driven upgrade go dark mid-run and finish as cancelled while the
#      upgrade itself carried on -- the log simply stops, with no error.
#
# A run genuinely orphaned by a crash is reconciled at backend startup from the
# .done.json marker the launcher writes, which knows which run is live. This
# function has no way to tell the two apart and must not guess.
_intact_clear_legacy_upgrade_state() {
    local db="${SCRIPT_DIR}/data/intact.db"
    [[ -f "$db" ]] || return 0
    python3 - "$db" <<'PY' >>"${LOG_FILE:-/dev/null}" 2>&1 || true
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
try:
    c.execute("DROP TABLE IF EXISTS upgrade_state"); c.commit()
except sqlite3.Error as e:
    print("  (skipped: %s)" % e)
c.close()
PY
    rm -f "${SCRIPT_DIR}/data/backend-source.applied.sha256" \
          "${SCRIPT_DIR}"/data/tmp/backend-selfheal-*.attempted 2>/dev/null
    return 0
}
