#!/usr/bin/env python3
"""
Simple backend API for Intact.AI Dashboard
Main Flask application with modular structure
"""

import threading
import time
import os
import sys
import faulthandler
import signal
# Diagnostics: `docker exec intact_backend kill -USR1 1` dumps EVERY thread's
# Python stack to stderr (→ docker logs) — even when the web server is wedged
# by a GIL-holding busy loop. Lets us pinpoint a spin without py-spy/ptrace.
try:
    faulthandler.register(signal.SIGUSR1, all_threads=True)
except Exception:
    pass
from datetime import timedelta

from flask import Flask, jsonify, request, session
from flask_cors import CORS

# Import blueprints
from routes import (
    auth_bp,
    client_bp,
    velociraptor_bp,
    velociraptor_offline_bp,
    timesketch_bp,
    timesketch_llm_bp,
    dashboard_bp,
    system_bp,
    config_bp,
    maintenance_bp,
    versions_bp,
    upgrade_bp,
    blueprint_bp,
    agentic_bp,
    agentic_cli_bp,
    db_bp,
    scheduler_bp,
    upload_bp,
    azure_bp,
    aws_bp,
    support_bundle_bp,
    memory_bp,
    case_bp,
)

# Import initialization services
from services.elasticsearch_service import init_elasticsearch
from services.velociraptor_init_service import initialize_velociraptor_artifacts
from services.offline_collector import init_offline_collector_index
from services.msi_generator_service import generate_all_client_installers
from services import auth_service
from config import ELASTICSEARCH_CONFIG

# Create Flask app
app = Flask(__name__)
# Pre-existing wart, documented so it isn't re-flagged: CORS(app) with no args
# emits Access-Control-Allow-Origin: * and nginx.conf adds it again (duplicate
# header). With a WILDCARD origin the browser refuses to send credentials
# cross-origin, so the session cookie can't be replayed from another site — CSRF
# protection therefore rests on SESSION_COOKIE_SAMESITE='Lax' below, which is an
# acceptable posture for a single-operator internal appliance.
CORS(app)

# --- session cookie policy (see services/auth_service.py) --------------------
app.secret_key = auth_service.session_secret_key()
app.config.update(
    SESSION_COOKIE_NAME='intact_session',
    SESSION_COOKIE_HTTPONLY=True,
    # Port 80/8080 permanently redirect to 443 (modules/nginx/config/nginx.conf),
    # so the cookie is never needed over plaintext. Note this is one reason the
    # loopback exemption in _auth_gate() exists: a test hitting
    # http://localhost:5001 could not authenticate with a Secure cookie.
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=auth_service.SESSION_MAX_AGE_DAYS),
    # We slide the window ourselves in _auth_gate() so we can distinguish an
    # expired session from a missing one; Flask re-signing on every request
    # would just be extra work per tus auth_request subrequest.
    SESSION_REFRESH_EACH_REQUEST=False,
)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(client_bp)
app.register_blueprint(velociraptor_bp)
app.register_blueprint(velociraptor_offline_bp)
app.register_blueprint(timesketch_bp)
app.register_blueprint(timesketch_llm_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(system_bp)
app.register_blueprint(config_bp)
app.register_blueprint(maintenance_bp)
app.register_blueprint(versions_bp)
app.register_blueprint(upgrade_bp)
app.register_blueprint(blueprint_bp)
app.register_blueprint(agentic_bp)
app.register_blueprint(agentic_cli_bp)
app.register_blueprint(db_bp)
app.register_blueprint(scheduler_bp)
app.register_blueprint(upload_bp)
app.register_blueprint(azure_bp)
app.register_blueprint(aws_bp)
app.register_blueprint(support_bundle_bp)
app.register_blueprint(memory_bp)
app.register_blueprint(case_bp)


# =============================================================================
# Authentication gate
# =============================================================================
#
# This is the platform's primary authentication boundary. It replaces the nginx
# server-level HTTP Basic Auth that used to be the only one, and unlike that
# gate it also closes audit finding F-010: nginx could only protect requests
# that came THROUGH nginx, so any peer container on intact_network could reach
# intact_backend:5001 directly and drive the whole API — including case export,
# Velociraptor hunts and /api/maintenance/purge — with zero credentials. A
# before_request hook applies to those requests too.
#
# Two paths cannot be gated here because they never reach Flask:
# /velociraptor/ (proxies to intact_velociraptor:8889) and /api/uploads/
# (proxies to intact_tusd:8080). nginx gates those with `auth_request` against
# /api/auth/verify. The static dashboard shell at `location /` is deliberately
# left open — it is inert HTML/JS holding no case data, and the frontend
# redirects to /login.html on its first 401.

# The allowlist, the loopback exemption and the decision itself all live in
# services/auth_service.gate_decision() — a pure function, so the security
# boundary is unit-testable without standing up a live app. This hook is only the
# Flask plumbing around it.
@app.before_request
def _auth_gate():
    reason = auth_service.gate_decision(
        request.path, request.method, request.remote_addr, session)

    if reason is None:
        # Slide the 7-day window for a genuinely logged-in caller. Guarded on
        # `user` so an exempt/loopback request with no session doesn't get an
        # empty cookie stamped onto it. Only re-stamps hourly, so this is not a
        # cookie re-sign on every request.
        if session.get('user') and auth_service.touch_session(session):
            session.modified = True
        return None

    # `reason` is what lets login.html say "your session expired" or "the
    # password was changed" instead of showing a bare form — the whole point of
    # tracking the timestamp server-side rather than relying on cookie max-age.
    return jsonify({
        'error': 'unauthenticated',
        'reason': reason,
        'message': 'Authentication required.',
    }), 401


# Workspace guard: investigation features targeting the System workspace raise
# WorkspaceError from create_automation_run(). Surface it as a clean 409 JSON
# (instead of a 500 traceback) so the UI can toast the message.
from services.workflow_service import WorkspaceError


@app.errorhandler(WorkspaceError)
def _handle_workspace_error(e):
    from flask import jsonify
    # `code` lets the UI reliably detect "module run blocked in the System
    # workspace" (vs string-matching the message) and show one clear alert.
    return jsonify({"error": str(e), "code": "workspace_system_blocked"}), 409


@app.after_request
def _echo_workspace_redirect(resp):
    """When a module launched from the System workspace is auto-redirected to the
    Default workspace (workflow_service._resolve_case_id), echo the effective
    workspace to the browser so its active workspace follows the run — uniformly,
    regardless of how the module's route reports success/errors."""
    try:
        from flask import g
        rid = getattr(g, "workspace_redirect", None)
        if rid:
            resp.headers["X-Active-Case"] = rid
    except Exception:
        pass
    return resp

# Global flag to track initialization status
initialization_status = {
    "elasticsearch": False,
    "velociraptor_artifacts": False,
    "msi_generation": False,
    "offline_collectors": False,
    "in_progress": False
}


def run_startup_initialization():
    """Run initialization tasks in background thread"""
    global initialization_status
    initialization_status["in_progress"] = True

    print("[STARTUP] Starting background initialization...", flush=True)

    # Subscription-connector runs execute on daemon threads, so any of ours left
    # in pending/running belongs to the process that just died — its worker and
    # its CLI child are gone, and any device code it issued is dead. Nothing can
    # revive them, so close them out now instead of leaving an operator staring
    # at a spinner (or approving a code whose process no longer exists).
    try:
        from services.agentic.subscription_cli import sweep_orphaned_runs
        sweep_orphaned_runs()
    except Exception as e:  # noqa: BLE001 — never block boot on housekeeping
        print(f"[STARTUP] subscription-connector sweep skipped: {e}", flush=True)

    # Boot-time housekeeping that used to live inside the two-phase upgrade
    # resume block. The upgrade engine runs on the host as upgrade.sh now, so
    # there is no pending-upgrade state to resume, no self-heal to arm and no
    # restart to survive -- but these two are ordinary boot work that only
    # ever lived in there because that is where the block happened to be.
    # Images for modules that are switched OFF. A release package
    # carries every module and the loader writes them all into the
    # docker store, so a box with (say) IRIS disabled still carries
    # its four images -- 2.0 GB observed on a dev appliance, for
    # containers that will never exist. install.sh now skips these at
    # load time; this reclaims what earlier installs already wrote,
    # and what an upgrade applied without a module selection leaves.
    #
    # Only touches images NO container references, so anything
    # actually in use is safe regardless of what config.yaml says.
    try:
        import subprocess as _sp
        from services.image_map import module_image_repos
        # load_main_config used to be in scope from further up the (now
        # deleted) pending-upgrade block. Imported explicitly rather than
        # relying on where the block happens to sit.
        from config import load_main_config
        cfg = load_main_config() or {}
        mods = cfg.get('modules') or {}
        disabled = set()
        for _name, _val in mods.items():
            _en = _val.get('enabled', True) if isinstance(_val, dict) else _val
            if not (_en is True or str(_en).lower() in ('true', 'yes', '1')):
                disabled.add(_name)
        if disabled:
            _inuse = set(
                (_sp.run(["docker", "ps", "-a", "--format", "{{.Image}}"],
                         capture_output=True, text=True, timeout=15).stdout or ''
                 ).split())
            _freed = 0
            for _mod in sorted(disabled):
                for _repo in module_image_repos(_mod):
                    _out = _sp.run(
                        ["docker", "images", _repo, "--format",
                         "{{.Repository}}:{{.Tag}}\t{{.Size}}"],
                        capture_output=True, text=True, timeout=15).stdout or ''
                    for _line in _out.splitlines():
                        _ref = _line.split('\t')[0].strip()
                        if not _ref or _ref in _inuse:
                            continue
                        _sp.run(["docker", "rmi", _ref],
                                capture_output=True, timeout=60)
                        _freed += 1
                        print(f"[STARTUP] Pruned {_ref} — module "
                              f"'{_mod}' is disabled", flush=True)
            if _freed:
                print(f"[STARTUP] Reclaimed {_freed} image(s) for "
                      f"disabled module(s): {', '.join(sorted(disabled))}",
                      flush=True)
    except Exception as _de:
        print(f"[STARTUP] disabled-module image prune skipped: {_de}", flush=True)

    # Dangling images: untagged, unreferenced layers left by builds and
    # image swaps. Ten of them (1.26 GB each) accumulated on this
    # appliance from repeated backend rebuilds. `prune` only removes
    # what has no tag and no container, so it cannot take anything
    # reachable -- unlike a tag-based sweep, which needs a keep-set.
    try:
        import subprocess as _sp
        _pr = _sp.run(["docker", "image", "prune", "-f"],
                      capture_output=True, text=True, timeout=300)
        _last = [l for l in (_pr.stdout or '').splitlines() if 'Total reclaimed' in l]
        if _last and 'Total reclaimed space: 0B' not in _last[-1]:
            print(f"[STARTUP] Dangling image sweep — {_last[-1].strip()}", flush=True)
    except Exception as _dpe:
        print(f"[STARTUP] dangling image prune skipped: {_dpe}", flush=True)

    try:
        from services.auth_migrate import migrate_basic_auth_to_app_login
        migrate_basic_auth_to_app_login(
            logger=lambda m, l="info": print(f"[STARTUP][auth-migrate] {m}",
                                             flush=True))
    except Exception as _ame:
        print(f"[STARTUP] Pre-auth login migration skipped: {_ame}", flush=True)

    # Reap orphaned runs: anything left RUNNING/PENDING by the previous process was
    # being driven by an in-backend worker thread that died with the restart and
    # cannot resume — so it would otherwise hang at its last progress % forever.
    # Mark them failed with a clear, actionable message. EXCLUDES online_upgrade
    # (which intentionally survives the two-phase restart and resumes above) and
    # server-side velociraptor_hunt (runs on the Velociraptor server, not here).
    try:
        from services.workflow_service import load_workflows, update_run_status
        _REAP_TYPES = {"velociraptor_upload", "timesketch", "velociraptor_collection",
                       "agentic", "aws_scan", "azure_scan", "memory"}
        _reaped = 0
        for _w in (load_workflows() or []):
            if (_w.get("automation_type") in _REAP_TYPES
                    and _w.get("status") in ("running", "pending")):
                _run_id = _w["run_id"]
                try:
                    update_run_status(_run_id, "failed", error=(
                        "Interrupted by a backend restart — the task's worker did "
                        "not survive. Please re-run/re-upload."))
                    _reaped += 1
                except Exception:
                    pass
                # Memory acquisitions leak real side effects on a crash: a
                # multi-GB .raw dump left on disk and a Velociraptor flow
                # still running on the endpoint. register_cleanup()'s
                # callback is in-memory only and died with the old process,
                # so replay it here from the state the pipeline persisted
                # into details._cleanup_state as it went (see
                # services/memory/pipeline.py's _persist_cleanup_state).
                if _w.get("automation_type") == "memory":
                    try:
                        _state = (_w.get("details") or {}).get("_cleanup_state") or {}
                        if _state:
                            from services.memory.cleanup import cleanup_after_run
                            cleanup_after_run(
                                client_id=_state.get("client_id"),
                                flow_id=_state.get("flow_id"),
                                host_path=_state.get("host_path"),
                                evidence_id=_state.get("evidence_id"),
                                evidence_filename=_state.get("evidence_filename"),
                                volweb_client=None,
                                delete_evidence_row=False,
                                logger=lambda m, level="info": print(
                                    f"[STARTUP] [memory-cleanup {_run_id}] {m}", flush=True),
                            )
                    except Exception as e:
                        print(f"[STARTUP] memory-cleanup replay failed for {_run_id}: {e}", flush=True)
        if _reaped:
            print(f"[STARTUP] Reaped {_reaped} run(s) orphaned by the restart", flush=True)
    except Exception as e:
        print(f"[STARTUP] Orphan-run reaper skipped: {e}", flush=True)

    # Upgrade runs are the exclusion the reaper above calls out: the intact
    # module's own recreate of THIS container is what just restarted us, so
    # a run still 'running' here is expected, not orphaned -- it is driven
    # by a detached sibling container that kept going through the restart.
    # Reattach the tailer, or finalize immediately if the helper already
    # finished while nothing was watching.
    try:
        from services.upgrade_launcher import reconcile_on_boot
        reconcile_on_boot()
    except Exception as e:
        print(f"[STARTUP] Upgrade-run reconciliation skipped: {e}", flush=True)

    # Initialize Elasticsearch — only when the module is actually enabled.
    # Previously this ran unconditionally even on installs with
    # modules.elk.enabled: false (the common case), attempting a network
    # connection (with its own retries/timeout) to a host that was never
    # started, before the per-request hot-path calls did the same thing again
    # on nearly every dashboard load (see workflow_service._elk_enabled).
    try:
        from config import is_module_enabled
        if is_module_enabled('elk'):
            print("[STARTUP] Initializing Elasticsearch...", flush=True)
            es_result = init_elasticsearch(
                host=ELASTICSEARCH_CONFIG['host'],
                port=ELASTICSEARCH_CONFIG['port'],
                user=ELASTICSEARCH_CONFIG['user'],
                password=ELASTICSEARCH_CONFIG['password']
            )
            initialization_status["elasticsearch"] = es_result
            if es_result:
                print("[WORKFLOW] Elasticsearch initialized successfully", flush=True)
        else:
            print("[STARTUP] Elasticsearch skipped (modules.elk.enabled: false)", flush=True)
            initialization_status["elasticsearch"] = False
    except Exception as e:
        print(f"[STARTUP] Elasticsearch initialization failed: {e}", flush=True)

    # Wait for Velociraptor to be ready (smart check instead of hardcoded wait)
    print("[STARTUP] Waiting for Velociraptor to be ready...", flush=True)
    velo_ready = False
    max_wait = 60  # Maximum 60 seconds
    wait_interval = 5
    waited = 0

    while waited < max_wait:
        try:
            from services.velociraptor_service import setup_velociraptor_connection
            channel = setup_velociraptor_connection()
            if channel:
                print(f"[STARTUP] Velociraptor ready after {waited}s", flush=True)
                velo_ready = True
                channel.close()
                break
        except Exception:
            pass
        time.sleep(wait_interval)
        waited += wait_interval
        print(f"[STARTUP] Waiting for Velociraptor... ({waited}s)", flush=True)

    if not velo_ready:
        print("[STARTUP] Velociraptor not responding after 60s, continuing anyway...", flush=True)

    # NOTE: Tool download is NOT done on startup - it runs via:
    # 1) install.sh (calls /api/maintenance/run)
    # 2) Maintenance button in Settings UI
    # This keeps container restarts fast
    initialization_status["tools_download"] = "skipped"
    initialization_status["velociraptor_artifacts"] = "skipped"

    # Generate client installers for all platforms (Windows EXE/MSI, Linux, Mac)
    try:
        print("[STARTUP] Generating client installers (fixes Velociraptor 0.75.x CLI bug)...", flush=True)
        client_result = generate_all_client_installers()
        if client_result.get("success"):
            print("[STARTUP] ✓ Client generation successful", flush=True)
            print(f"[STARTUP] {client_result.get('message', '')}", flush=True)
            initialization_status["msi_generation"] = True
        else:
            print(f"[STARTUP] Client generation failed: {client_result.get('error', 'unknown')}", flush=True)
            initialization_status["msi_generation"] = False
    except Exception as e:
        print(f"[STARTUP] Client generation error: {e}", flush=True)
        initialization_status["msi_generation"] = False

    # Initialize offline collector configurations (runs AFTER client generation)
    try:
        print("[STARTUP] Initializing offline collector configurations...", flush=True)
        init_result = init_offline_collector_index()
        if init_result:
            print("[STARTUP] ✓ Offline collector configurations initialized", flush=True)
            initialization_status["offline_collectors"] = True
        else:
            print("[STARTUP] Offline collector initialization failed", flush=True)
            initialization_status["offline_collectors"] = False
    except Exception as e:
        print(f"[STARTUP] Offline collector initialization error: {e}", flush=True)
        initialization_status["offline_collectors"] = False

    initialization_status["in_progress"] = False
    print("[STARTUP] Background initialization complete", flush=True)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok"})


@app.route('/api/init/status')
def init_status():
    """Get initialization status"""
    return jsonify(initialization_status)


@app.route('/api/init/artifacts', methods=['POST'])
def reinit_artifacts():
    """Manually trigger artifact initialization"""
    if initialization_status["in_progress"]:
        return jsonify({"error": "Initialization already in progress"}), 400

    # Run in background
    thread = threading.Thread(target=lambda: initialize_velociraptor_artifacts())
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Artifact initialization started"})


@app.route('/api/init/msi', methods=['POST'])
def reinit_msi():
    """Manually trigger MSI/client generation"""
    if initialization_status["in_progress"]:
        return jsonify({"error": "Initialization already in progress"}), 400

    # Run MSI generation
    def run_msi_gen():
        result = generate_all_client_installers()
        print(f"[MSI-GEN] Manual trigger result: {result}", flush=True)

    thread = threading.Thread(target=run_msi_gen)
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Client generation started"})


if __name__ == '__main__':
    # Always run without hot-reload for stability
    print("[STARTUP] Starting backend API (production mode)", flush=True)

    # Start initialization in background thread
    init_thread = threading.Thread(target=run_startup_initialization)
    init_thread.daemon = True
    init_thread.start()

    # Run Flask without debug/reloader
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False, threaded=True)
