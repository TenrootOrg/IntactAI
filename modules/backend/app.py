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
    cve_bp,
    memory_bp,
    case_bp,
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
app.register_blueprint(cve_bp)
app.register_blueprint(memory_bp)
app.register_blueprint(case_bp)


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

    # CHECK FOR PENDING UPGRADES FIRST (Two-Phase Upgrade Support)
    try:
        from services.storage.base import get_pending_upgrade

        # Wave F: a recreate-failed marker means the LAST boot was the recreate
        # helper's ROLLBACK landing on the OLD image (or, rarer, a manual restore) —
        # BEFORE we even look at pending state. If the awaiting_restart/phase2 row
        # is still there, resuming now would run Phase 2 on the OLD (rolled-back)
        # code against NEW-release state. Fail the run + clear state FIRST so the
        # pending read below sees a clean slate.
        try:
            import glob as _glob, json as _json
            from services.storage.base import get_active_upgrade_state, clear_upgrade_state
            from services.workflow_service import update_run_status, add_log_to_run
            for _marker in _glob.glob('/app/data/tmp/recreate-failed-*.json'):
                try:
                    with open(_marker) as _mf:
                        _info = _json.load(_mf)
                    _rid = _info.get('run_id')
                    _reason = _info.get('reason', 'backend recreate failed')
                    _state = get_active_upgrade_state()
                    if _rid and _state and _state.get('run_id') == _rid:
                        print(f"[STARTUP] recreate-failed marker for {_rid}: {_reason}", flush=True)
                        add_log_to_run(_rid, f"Backend recreate failed: {_reason}", "error")
                        update_run_status(_rid, "failed", error=_reason)
                        clear_upgrade_state(_rid)
                except Exception as _me:
                    print(f"[STARTUP] recreate-failed marker parse error ({_marker}): {_me}", flush=True)
                finally:
                    try:
                        os.remove(_marker)
                    except OSError:
                        pass
        except Exception as _mke:
            print(f"[STARTUP] recreate-failed marker check error: {_mke}", flush=True)

        from services.upgrade import resume_upgrade_workflow
        from services.workflow_logger import WorkflowLogger

        # Self-heal run finalizer — MUST run before the generic upgrade
        # watchdog below, which would otherwise reap a successful self-heal's
        # tracked run as "orphaned by restart". self_heal_backend_swap()
        # can't mark its own run completed synchronously: the actual image
        # swap happens asynchronously via a detached helper AFTER the
        # function returns and this container gets recreated. If the
        # marker's run_id is still "running" and the backend is now actually
        # on the target image, the swap worked — mark it completed and clear
        # the marker so a future genuine drift gets its own fresh attempt.
        try:
            import glob as _sfglob
            from services.upgrade.intact import backend_target_tag, backend_full_mode, running_backend_image
            from services.workflow_service import get_automation_run, update_run_status as _sf_urs
            _sf_compose = os.path.join(
                os.environ.get('INTACT_PATH', '/app/workdir'), 'modules', 'backend', 'docker-compose.yaml')
            if backend_full_mode(_sf_compose):
                _sf_target = backend_target_tag()
                _sf_running = running_backend_image() or ''
                for _sf_marker in _sfglob.glob('/app/data/tmp/backend-selfheal-*.attempted'):
                    try:
                        _sf_info = {}
                        with open(_sf_marker) as _sf_mf:
                            for _sf_line in _sf_mf:
                                if '=' in _sf_line:
                                    _sk, _sv = _sf_line.strip().split('=', 1)
                                    _sf_info[_sk] = _sv
                        _sf_run_id = _sf_info.get('run_id')
                        _sf_marker_tag = _sf_info.get('target_tag')
                        if (_sf_run_id and _sf_marker_tag == _sf_target
                                and _sf_running == f"intact-backend:{_sf_target}"):
                            _sf_run = get_automation_run(_sf_run_id)
                            if _sf_run:
                                # Always add the confirmation line, even when the
                                # run's status is already terminal (the common
                                # case now that self-heal reuses the parent
                                # "Online Upgrade" run: that run is marked
                                # completed the moment Phase 2 returns, well
                                # before this detached recreate actually lands —
                                # so its log used to just stop at "triggered",
                                # never confirming the swap really happened).
                                from services.workflow_service import add_log_to_run as _sf_alog
                                _sf_alog(_sf_run_id,
                                         f"Backend confirmed running intact-backend:"
                                         f"{_sf_target} — self-heal converged.",
                                         "success")
                                if _sf_run.get('status') in ('pending', 'running'):
                                    print(f"[STARTUP] Self-heal for {_sf_target} confirmed "
                                          f"successful (run {_sf_run_id}) — marking completed",
                                          flush=True)
                                    _sf_urs(_sf_run_id, "completed", progress=100, force=True)
                            try:
                                os.remove(_sf_marker)
                            except OSError:
                                pass
                    except Exception as _sf_me:
                        print(f"[STARTUP] Self-heal marker check error ({_sf_marker}): {_sf_me}",
                              flush=True)
        except Exception as _sfe:
            print(f"[STARTUP] Self-heal run finalizer skipped: {_sfe}", flush=True)

        pending = get_pending_upgrade()
        protected_run_id = pending['run_id'] if pending else None

        # 1) UPGRADE WATCHDOG — runs SYNCHRONOUSLY before the resume spawn so
        # it can never race a legit resume (the pending run is excluded by
        # run_id). Reaps:
        #   - upgrade/online_upgrade/prepare_package runs stuck running/pending
        #     with no resumable state (crashed Phase-1 thread, dead prepare,
        #     leaked run) -> failed "orphaned by restart";
        #   - upgrade_state rows whose run isn't the protected one (duplicate/
        #     leaked rows — e.g. the phase2 row of a long-cancelled run found
        #     on this very system).
        try:
            from services.storage.base import get_active_upgrade_state, clear_upgrade_state
            from services.workflow_service import get_all_automation_runs, update_run_status
            _UPG_TYPES = ("upgrade", "online_upgrade", "prepare_package")
            for _run in (get_all_automation_runs() or []):
                if (_run.get('automation_type') in _UPG_TYPES
                        and _run.get('status') in ('running', 'pending')
                        and _run.get('run_id') != protected_run_id):
                    print(f"[STARTUP] Watchdog: reaping orphaned {_run.get('automation_type')} "
                          f"run {_run.get('run_id')}", flush=True)
                    update_run_status(_run.get('run_id'), "failed",
                                      error="Orphaned by a backend restart — no "
                                            "resumable upgrade state was found.")
                    clear_upgrade_state(_run.get('run_id'))
            _leak = get_active_upgrade_state()
            if _leak and _leak.get('run_id') != protected_run_id:
                print(f"[STARTUP] Watchdog: clearing leaked upgrade_state row "
                      f"{_leak.get('run_id')} (phase={_leak.get('phase')})", flush=True)
                clear_upgrade_state(_leak.get('run_id'))
        except Exception as _we:
            print(f"[STARTUP] Upgrade watchdog error: {_we}", flush=True)

        # 2) RESUME GUARD — bounded retries. awaiting_restart boot = attempt 1
        # (the expected handoff); one unexpected mid-Phase-2 crash = attempt 2;
        # a second crash = abandoned (run failed with a per-module summary,
        # state cleared) so a crash-looping upgrade can't restart-storm and
        # the single-writer lock is freed.
        MAX_PHASE2_RESUMES = 2
        if pending:
            try:
                from services.storage.base import increment_upgrade_resume_count, clear_upgrade_state
                from services.workflow_service import update_run_status, add_log_to_run
                _n = increment_upgrade_resume_count(pending['run_id'])
                if _n > MAX_PHASE2_RESUMES:
                    _done = ', '.join(pending.get('completed_modules') or []) or 'none'
                    print(f"[STARTUP] Resume abandoned for {pending['run_id']} "
                          f"(attempt {_n} > {MAX_PHASE2_RESUMES})", flush=True)
                    add_log_to_run(pending['run_id'],
                                   f"Upgrade resume abandoned after {MAX_PHASE2_RESUMES} attempts — "
                                   f"the backend restarted repeatedly during Phase 2. "
                                   f"Completed modules: {_done}. Re-run the upgrade for "
                                   f"the remaining modules.", "error")
                    update_run_status(pending['run_id'], "failed",
                                      error=f"resume abandoned after {MAX_PHASE2_RESUMES} attempts")
                    clear_upgrade_state(pending['run_id'])
                    pending = None
            except Exception as _ge:
                print(f"[STARTUP] Resume guard error: {_ge}", flush=True)

        # Reclaim multi-GB staging orphaned by a crashed/killed upgrade.
        # Previously swept only when a NEW upgrade started — if none was ever
        # run again, orphans sat forever. Skipped while an upgrade is pending:
        # its extract dir must survive the restart for Phase 2.
        if not pending:
            try:
                from services.upgrade.base import sweep_stale_upgrade_staging
                sweep_stale_upgrade_staging()
            except Exception as _se:
                print(f"[STARTUP] staging sweep skipped: {_se}", flush=True)

            # Wave F: sweep any leaked recreate-helper container from a run that
            # never cleaned up (the helper is --rm, but a killed/orphaned one can
            # linger), and prune old intact-backend images beyond the running tag
            # + the recorded previous tag — so a swap history doesn't fill disk.
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

            # Self-heal a backend stranded on the wrong image for a Full-mode
            # release (e.g. an 'intact'-alone upgrade run by OLD, pre-Wave-F
            # code — that code mirrors files + restarts the SAME container
            # since it has no concept of image swapping; VERSION/config.yaml
            # end up correct but the running image never changes, and nothing
            # else ever re-checks since that code path never persists Phase-2
            # resume state). Runs on every boot with no pending upgrade; a
            # no-op unless a real mismatch is found.
            try:
                from services.upgrade import self_heal_backend_swap
                _heal = self_heal_backend_swap(
                    logger=lambda m, l="info": print(f"[STARTUP][self-heal] {m}", flush=True))
                if _heal.get("healed"):
                    print(f"[STARTUP] Backend self-heal triggered "
                          f"(run {_heal.get('run_id')}) — recreating onto the "
                          f"correct image", flush=True)
            except Exception as _she:
                print(f"[STARTUP] Backend self-heal check skipped: {_she}", flush=True)
        if pending:
            run_id = pending['run_id']
            print(f"[STARTUP] Found pending upgrade: {run_id}", flush=True)
            print(f"[STARTUP] Phase: {pending['phase']}", flush=True)
            print("[STARTUP] Resuming Phase 2 in background...", flush=True)

            def resume_in_background():
                try:
                    # Small delay to let the backend fully start
                    time.sleep(5)

                    # Register a cancel event so Stop actually interrupts
                    # Phase-2 run_commands. Without this, request_stop()
                    # found no event: the UI showed "cancelled" while Phase 2
                    # kept running to completion in the background.
                    try:
                        from services.workflow_service import register_cancel_event
                        register_cancel_event(run_id)
                    except Exception as _e:
                        print(f"[STARTUP] Could not register cancel event: {_e}", flush=True)

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
                    from services.workflow_service import update_run_status as _urs
                    _results = result.get('results') or {}
                    # Underscore keys are run METADATA, not modules (_health from
                    # the post-upgrade gate, _workflow_error). Counting them reported
                    # a perfectly healthy upgrade as "completed with failed
                    # module(s): _health", because the health result carries
                    # `healthy`, not `success`. The gate already signals trouble by
                    # demoting overall_status to completed_with_warnings.
                    _failed = [m for m, r in _results.items()
                               if isinstance(r, dict) and not r.get('success')
                               and not m.startswith('_')]
                    if result.get('success'):
                        # force=True: per-module results are authoritative — an
                        # error-level line from a step that recovered must not
                        # auto-demote a fully-successful Phase 2 (G8).
                        wf_logger.success("Upgrade completed successfully")
                        _urs(run_id, "completed", progress=100, force=True)
                        print(f"[STARTUP] Upgrade Phase 2 completed successfully", flush=True)
                    elif _failed and len(_failed) < len(_results):
                        # Partial success: surface the failed modules in the
                        # error field instead of flat-failing a 5/6 success.
                        wf_logger.warning(
                            f"Phase 2 completed with failed module(s): {', '.join(_failed)}")
                        _urs(run_id, "completed", progress=100, force=True,
                             error=f"completed with failed module(s): {', '.join(_failed)}")
                        print(f"[STARTUP] Upgrade Phase 2 partial: failed={_failed}", flush=True)
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
                finally:
                    # Mirror the routes' cleanup so the cancel-event registry
                    # doesn't leak entries across resumes.
                    try:
                        from services.workflow_service import unregister_cancel
                        unregister_cancel(run_id)
                    except Exception:
                        pass

            resume_thread = threading.Thread(target=resume_in_background, daemon=True)
            resume_thread.start()
    except Exception as e:
        print(f"[STARTUP] Could not check for pending upgrades: {e}", flush=True)

    # Reap orphaned runs: anything left RUNNING/PENDING by the previous process was
    # being driven by an in-backend worker thread that died with the restart and
    # cannot resume — so it would otherwise hang at its last progress % forever.
    # Mark them failed with a clear, actionable message. EXCLUDES online_upgrade
    # (which intentionally survives the two-phase restart and resumes above) and
    # server-side velociraptor_hunt (runs on the Velociraptor server, not here).
    try:
        from services.workflow_service import load_workflows, update_run_status
        _REAP_TYPES = {"velociraptor_upload", "timesketch", "velociraptor_collection",
                       "agentic", "cve_scan", "aws_scan", "azure_scan", "memory"}
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
                port=ELASTICSEARCH_CONFIG['port']
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

    # CVE Scan local DB bootstrap. Schema is created cheaply on import,
    # but the actual ~50 MB NVD-feed download runs in a separate
    # background thread so the API can serve traffic immediately. On
    # fresh installs this populates the DB the first time the backend
    # comes up — covers the install.sh path without install.sh needing
    # to know about it. Subsequent restarts skip the download (DB is
    # already populated; operator uses the Maintenance button for
    # incremental refresh).
    # Gate on modules.cve_scan.enabled — a disabled CVE module must NOT download
    # the CVE feed (same as every other module: disabled => no data, no pages).
    from config import is_module_enabled as _is_mod_enabled
    if not _is_mod_enabled('cve_scan'):
        print("[STARTUP] CVE Scan disabled (modules.cve_scan.enabled=false) — "
              "skipping CVE DB bootstrap/download.", flush=True)
        initialization_status["cve_local_db"] = "disabled"
    else:
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
