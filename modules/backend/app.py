#!/usr/bin/env python3
"""
Simple backend API for Intact.AI Dashboard
Main Flask application with modular structure
"""

import threading
import time
import os
import sys
from flask import Flask, jsonify
from flask_cors import CORS

# Import blueprints
from routes import (
    client_bp,
    velociraptor_bp,
    velociraptor_offline_bp,
    timesketch_bp,
    timesketch_llm_bp,
    dashboard_bp,
    system_bp,
    config_bp,
    maintenance_bp,
    upgrade_bp,
    blueprint_bp,
    agentic_bp,
    db_bp,
    scheduler_bp,
    upload_bp,
    azure_bp,
    aws_bp,
    support_bundle_bp,
    engagement_bp,
    cve_bp,
    memory_bp,
)

# Import initialization services
from services.elasticsearch_service import init_elasticsearch
from services.velociraptor_init_service import initialize_velociraptor_artifacts
from services.offline_collector import init_offline_collector_index
from services.msi_generator_service import generate_all_client_installers
from config import ELASTICSEARCH_CONFIG

# Create Flask app
app = Flask(__name__)
CORS(app)

# Register blueprints
app.register_blueprint(client_bp)
app.register_blueprint(velociraptor_bp)
app.register_blueprint(velociraptor_offline_bp)
app.register_blueprint(timesketch_bp)
app.register_blueprint(timesketch_llm_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(system_bp)
app.register_blueprint(config_bp)
app.register_blueprint(maintenance_bp)
app.register_blueprint(upgrade_bp)
app.register_blueprint(blueprint_bp)
app.register_blueprint(agentic_bp)
app.register_blueprint(db_bp)
app.register_blueprint(scheduler_bp)
app.register_blueprint(upload_bp)
app.register_blueprint(azure_bp)
app.register_blueprint(aws_bp)
app.register_blueprint(support_bundle_bp)
app.register_blueprint(engagement_bp)
app.register_blueprint(cve_bp)
app.register_blueprint(memory_bp)

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

    # CHECK FOR PENDING UPGRADES FIRST (Two-Phase Upgrade Support)
    try:
        from services.storage.base import get_pending_upgrade
        from services.upgrade import resume_upgrade_workflow
        from services.workflow_logger import WorkflowLogger

        # A recreate-failed marker means the LAST boot was the recreate helper's
        # ROLLBACK landing back on the OLD image (or, rarer, a manual restore).
        # This MUST run BEFORE the pending read: if the awaiting_restart row is
        # still there, resuming now would run Phase 2 on the OLD (rolled-back)
        # code against NEW-release state. Fail the run + clear state first so the
        # pending read below sees a clean slate.
        try:
            import glob as _glob, json as _json
            from services.storage.base import clear_upgrade_state as _clear_state
            from services.workflow_service import update_run_status as _urs, add_log_to_run as _alr
            for _marker in _glob.glob('/app/data/tmp/recreate-failed-*.json'):
                try:
                    with open(_marker) as _mf:
                        _info = _json.load(_mf)
                    _rid = _info.get('run_id')
                    _reason = _info.get('reason', 'backend recreate failed')
                    _state = get_pending_upgrade()
                    if _rid and _state and _state.get('run_id') == _rid:
                        print(f"[STARTUP] recreate-failed marker for {_rid}: {_reason}", flush=True)
                        _alr(_rid, f"Backend recreate failed: {_reason}", "error")
                        _urs(_rid, "failed", error=_reason)
                        _clear_state(_rid)
                except Exception as _me:
                    print(f"[STARTUP] recreate-failed marker parse error ({_marker}): {_me}", flush=True)
                finally:
                    try:
                        os.remove(_marker)
                    except OSError:
                        pass
        except Exception as _mke:
            print(f"[STARTUP] recreate-failed marker check error: {_mke}", flush=True)

        pending = get_pending_upgrade()
        if pending:
            run_id = pending['run_id']
            print(f"[STARTUP] Found pending upgrade: {run_id}", flush=True)
            print(f"[STARTUP] Phase: {pending['phase']}", flush=True)
            print("[STARTUP] Resuming Phase 2 in background...", flush=True)

            def resume_in_background():
                try:
                    # Small delay to let the backend fully start
                    time.sleep(5)

                    # Create workflow logger to update the workflow record
                    wf_logger = WorkflowLogger(run_id, "UPGRADE-RESUME")
                    wf_logger.info("=== PHASE 2 - RESUMING UPGRADE AFTER RESTART ===")

                    # Create a logger function compatible with upgrade functions
                    def upgrade_logger(msg, level="info"):
                        if level == "success":
                            wf_logger.success(msg)
                        elif level == "error":
                            wf_logger.error(msg)
                        elif level == "warning":
                            wf_logger.warning(msg)
                        else:
                            wf_logger.info(msg)

                    result = resume_upgrade_workflow(run_id, logger=upgrade_logger)
                    if result.get('success'):
                        wf_logger.complete("Upgrade completed successfully")
                        print(f"[STARTUP] Upgrade Phase 2 completed successfully", flush=True)
                    else:
                        wf_logger.fail(f"Upgrade failed: {result.get('error', 'unknown')}")
                        print(f"[STARTUP] Upgrade Phase 2 failed: {result.get('error')}", flush=True)
                except Exception as e:
                    print(f"[STARTUP] Upgrade resume error: {e}", flush=True)
                    # Try to mark workflow as failed
                    try:
                        from services.workflow_service import update_run_status, add_log_to_run
                        add_log_to_run(run_id, f"Phase 2 error: {str(e)}", "error")
                        update_run_status(run_id, "failed")
                    except Exception:
                        pass

            resume_thread = threading.Thread(target=resume_in_background, daemon=True)
            resume_thread.start()
        else:
            # No upgrade in flight — safe to tidy up after past swaps. Sweep any
            # leaked recreate-helper container (it is --rm, but a killed one can
            # linger), and prune intact-backend images beyond the running tag +
            # the recorded previous tag so swap history doesn't fill the disk.
            try:
                import subprocess as _sp
                _lst = _sp.run(
                    ["docker", "ps", "-aq", "--filter", "name=intact-upgrade-helper-"],
                    capture_output=True, text=True, timeout=15)
                for _cid in (_lst.stdout or '').split():
                    _sp.run(["docker", "rm", "-f", _cid], capture_output=True, timeout=15)
                    print(f"[STARTUP] Removed stale recreate-helper container {_cid}", flush=True)
            except Exception as _hse:
                print(f"[STARTUP] recreate-helper sweep skipped: {_hse}", flush=True)

            try:
                import subprocess as _sp
                _running = _sp.run(
                    ["docker", "inspect", "-f", "{{.Config.Image}}", "intact_backend"],
                    capture_output=True, text=True, timeout=15)
                running_tag = (_running.stdout or '').strip()
                keep = {running_tag} if running_tag else set()
                try:
                    with open('/app/data/backend-image.previous') as _pf:
                        prev = _pf.read().strip()
                    if prev:
                        keep.add(prev)
                except FileNotFoundError:
                    pass
                _tags = _sp.run(
                    ["docker", "images", "intact-backend", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, timeout=15)
                for _img in (_tags.stdout or '').splitlines():
                    _img = _img.strip()
                    if _img and _img not in keep:
                        _sp.run(["docker", "rmi", _img], capture_output=True, timeout=60)
                        print(f"[STARTUP] Pruned old backend image {_img}", flush=True)
            except Exception as _pe:
                print(f"[STARTUP] backend-image retention prune skipped: {_pe}", flush=True)
    except Exception as e:
        print(f"[STARTUP] Could not check for pending upgrades: {e}", flush=True)

    # Initialize Elasticsearch
    try:
        print("[STARTUP] Initializing Elasticsearch...", flush=True)
        es_result = init_elasticsearch(
            host=ELASTICSEARCH_CONFIG['host'],
            port=ELASTICSEARCH_CONFIG['port']
        )
        initialization_status["elasticsearch"] = es_result
        if es_result:
            print("[WORKFLOW] Elasticsearch initialized successfully", flush=True)
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

    # CVE Scan local DB bootstrap. Schema is created cheaply on import,
    # but the actual ~50 MB NVD-feed download runs in a separate
    # background thread so the API can serve traffic immediately. On
    # fresh installs this populates the DB the first time the backend
    # comes up — covers the install.sh path without install.sh needing
    # to know about it. Subsequent restarts skip the download (DB is
    # already populated; operator uses the Maintenance button for
    # incremental refresh).
    try:
        print("[STARTUP] Bootstrapping CVE Scan local DB...", flush=True)
        from services.cve_scan import local_db as _cve_local_db
        _cve_local_db.init_db()
        if _cve_local_db.is_populated():
            stats = _cve_local_db.db_stats()
            print(
                f"[STARTUP] ✓ CVE Scan local DB already populated "
                f"({stats['cve_count']} CVEs, {stats['db_size_mb']:.0f} MB)",
                flush=True,
            )
            initialization_status["cve_local_db"] = True
        else:
            print(
                "[STARTUP] CVE Scan local DB empty — kicking off bulk_load "
                "in background (~10-30 min). Scans before it completes "
                "will fall back to NVD REST.",
                flush=True,
            )

            def _bg_bulk_load():
                try:
                    res = _cve_local_db.bulk_load(logger=lambda m, lvl="info": print(f"[CVE-DB] {m}", flush=True))
                    print(f"[CVE-DB] Bootstrap complete: {res.get('cve_count')} CVEs indexed in {res.get('elapsed_seconds', 0):.0f}s", flush=True)
                except Exception as e:
                    print(f"[CVE-DB] Bootstrap failed (REST fallback still works): {e}", flush=True)

            threading.Thread(target=_bg_bulk_load, daemon=True, name="cve-local-db-bootstrap").start()
            initialization_status["cve_local_db"] = "loading"
    except Exception as e:
        print(f"[STARTUP] CVE Scan local DB bootstrap error: {e}", flush=True)
        initialization_status["cve_local_db"] = False

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
