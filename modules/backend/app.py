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
                # ~4 GiB per uploaded package, previously never removed. Now
                # that the apply path refuses to start on low disk, this
                # garbage could make a box refuse to upgrade.
                from services.upgrade.base import sweep_applied_upload_packages
                sweep_applied_upload_packages(
                    logger=lambda m, l="info": print(f"[STARTUP] {m}", flush=True))
            except Exception as _se:
                print(f"[STARTUP] staging sweep skipped: {_se}", flush=True)

            # An `upgrade_package_upload` row is left OPEN at progress=10 on
            # purpose (see routes/upload_routes.py): the apply is meant to adopt
            # it so upload+apply read as ONE workflow. When adoption fails
            # nothing closes it — the watchdog above only reaps upgrade /
            # online_upgrade / prepare_package, and cleanup_orphan_workflows
            # waits for 10 idle HOURS. Observed 2026-08-05: an upload row still
            # `running` at 10% forty minutes after a separate "upgrade_<ts>" run
            # had applied its package, so the operator saw an upload that never
            # finished next to an upgrade that plainly had.
            #
            # Close only what is DEMONSTRABLY over, never merely old — age is
            # the reaper's job and it already does it. tusd is a separate
            # container that does NOT restart with us, so an upload can be
            # genuinely mid-flight right now; the tests below are all positive
            # evidence that this particular row's work has ended. A finished
            # upload whose package is still sitting on disk unapplied is the
            # legitimate "waiting for the operator to press Apply" state and is
            # deliberately left running.
            try:
                import json as _json
                from services.workflow_service import (get_all_automation_runs,
                                                       update_run_status,
                                                       add_log_to_run)
                _runs = get_all_automation_runs() or []
                # tusd keeps <id>.info beside an upload for its whole life, and
                # the browser puts the pre-created run id in the upload
                # metadata. That is the only way back to the file for a row
                # whose details.upload_id was never written — which was every
                # row created by /api/upgrade/upload-run before 2026-08-05.
                _uploads_dir = '/data/uploads'
                _run_to_upload = {}
                try:
                    _names = os.listdir(_uploads_dir)
                except OSError:
                    _names = []
                for _n in _names:
                    if not _n.endswith('.info'):
                        continue
                    try:
                        with open(os.path.join(_uploads_dir, _n)) as _inf:
                            _meta = (_json.load(_inf).get('MetaData') or {})
                    except (OSError, ValueError):
                        continue
                    _mrid = (_meta.get('upload_run_id') or '').strip()
                    if _mrid:
                        _run_to_upload[_mrid] = _n[:-len('.info')]
                # Packages some OTHER run applied. A second run holding this
                # package in details.package_path is proof the apply happened
                # without this row — the exact split this sweep exists to clean
                # up after, and what separates it from an upload nobody has
                # applied yet.
                _applied_paths = set()
                for _r in _runs:
                    if _r.get('automation_type') == 'upgrade_package_upload':
                        continue
                    _rd = _r.get('details') or {}
                    if _rd.get('package_path'):
                        _applied_paths.add(_rd['package_path'])
                    for _pp in (_rd.get('package_paths') or []):
                        if _pp:
                            _applied_paths.add(_pp)

                for _r in _runs:
                    if _r.get('automation_type') != 'upgrade_package_upload':
                        continue
                    if _r.get('status') not in ('running', 'pending'):
                        continue
                    _rid = _r.get('run_id') or _r.get('id')
                    if not _rid:
                        continue
                    _det = _r.get('details') or {}
                    _uid = (_det.get('upload_id') or '').strip() or _run_to_upload.get(_rid)
                    _payload = os.path.join(_uploads_dir, _uid) if _uid else None

                    if _det.get('applied'):
                        # This row was carrying the APPLY too (it was adopted),
                        # and no Phase-2 resume is pending, so that apply died
                        # with the restart. Same verdict and wording as the
                        # upgrade watchdog above — calling it "completed" would
                        # dress a dead upgrade up as a successful one.
                        _why = ("the apply that adopted this row was orphaned by "
                                "a backend restart")
                        print(f"[STARTUP] Failing orphaned upload run {_rid}: {_why}",
                              flush=True)
                        add_log_to_run(_rid, f"Closed on startup — {_why}.", "error")
                        update_run_status(_rid, "failed",
                                          error="Orphaned by a backend restart — the "
                                                "apply this upload continued into did "
                                                "not survive it.")
                        continue

                    if _uid and not os.path.exists(_payload):
                        _why = f"its uploaded file {_payload} no longer exists"
                    elif _uid and _payload in _applied_paths:
                        _why = ("its package was applied by a separate upgrade run")
                    else:
                        # Either the package is still on disk (in flight, or
                        # uploaded and waiting to be applied) or nothing on disk
                        # refers to this row at all. Neither proves the work is
                        # over, so leave it to cleanup_orphan_workflows.
                        continue
                    print(f"[STARTUP] Closing orphaned upload run {_rid}: {_why}",
                          flush=True)
                    add_log_to_run(_rid,
                                   f"Closing this upload row on startup — {_why}, "
                                   f"so it stops reading as still-running.", "info")
                    update_run_status(_rid, "completed", progress=100)
            except Exception as _ou:
                print(f"[STARTUP] orphaned upload-run sweep skipped: {_ou}", flush=True)

            # Wave F: sweep any leaked recreate-helper container from a run that
            # never cleaned up (the helper is --rm, but a killed/orphaned one can
            # linger), and prune old intact-backend images beyond the running tag
            # + the recorded previous tag — so a swap history doesn't fill disk.
            try:
                import subprocess as _sp
                # Only sweep helpers that are NOT running. This used to
                # `docker rm -f` every match, which is safe for a leaked
                # helper and actively harmful for a live one: the backend
                # reaches this code moments after a helper recreated it, so a
                # helper still finishing its work (health-gate, rollback) was
                # being force-killed by the very container it had just
                # started — removing the one thing able to roll the box back.
                _lst = _sp.run(
                    ["docker", "ps", "-aq", "--filter",
                     "name=intact-upgrade-helper-", "--filter", "status=exited",
                     "--filter", "status=created", "--filter", "status=dead"],
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
                from services.upgrade.package import module_image_repos
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
        # Migrate a pre-auth box onto the app login. Runs on EVERY boot, outside
        # the pending/not-pending split, because the one call site that used to
        # cover this cannot reach the case it was written for.
        #
        # migrate_basic_auth_to_app_login() lives in upgrade_intact_offline(),
        # which executes in PHASE 1 — and Phase 1 runs on the OLD backend's
        # code, because the image swap happens at the END of it. A box on a
        # genuinely pre-auth release (intact-20260615 and earlier) has no
        # auth_service.py and zero occurrences of that function, so the
        # migration never fires on the only upgrade that needs it. It runs
        # exclusively when the source box ALREADY has the new auth code, i.e.
        # when it is a no-op.
        #
        # Observed 2026-08-02 upgrading 20260615 -> 20260802: the box landed
        # with first_login absent, no stored credential, and auth_mode()
        # mapping ABSENT -> MODE_LOGIN. That is a locked-out appliance whose
        # only route back in is hand-editing config.yaml on the host — and the
        # recovery hint explaining that is rendered on the login page the
        # operator cannot reach.
        #
        # Doing it at boot rather than in Phase 2 is deliberate: Phase 2 is not
        # guaranteed to run. That same upgrade had Phase 2 refused by the disk
        # preflight, so a Phase-2-only fix would still have left the box locked
        # out. Boot always happens.
        #
        # Idempotent by construction — the trigger is the ABSENCE of the
        # first_login key and the migration always writes that key, so this is
        # a cheap early return on every subsequent boot.
        try:
            from services.upgrade.intact import migrate_basic_auth_to_app_login
            migrate_basic_auth_to_app_login(
                logger=lambda m, l="info": print(f"[STARTUP][auth-migrate] {m}",
                                                 flush=True))
        except Exception as _ame:
            print(f"[STARTUP] Pre-auth login migration skipped: {_ame}", flush=True)

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
                        # Re-baseline the backend source fingerprint NOW that
                        # every source mutation is done.
                        #
                        # It is already recorded during Phase 1's swap prep, but
                        # Phase 2 then re-copies the intact source (the intact
                        # module always refreshes, even same-ref), so the tree on
                        # disk no longer matches what was recorded. The next boot
                        # read that as content drift and "healed" a backend image
                        # that was already correct — a full rebuild from source
                        # which recreated, and killed, the container it was
                        # running in (observed 2026-07-23: backend exit 137, box
                        # left down until an operator started it by hand).
                        try:
                            from services.upgrade.intact import (
                                record_backend_source_fingerprint)
                            record_backend_source_fingerprint(
                                logger=lambda m, l="info": wf_logger.info(m))
                        except Exception as _fe:
                            wf_logger.warning(
                                f"Could not re-baseline the backend source "
                                f"fingerprint ({_fe}) — the next boot may run a "
                                f"self-heal rebuild it does not actually need.")
                        # The browser is still running the PREVIOUS release's
                        # JS bundle — the backend swapped underneath it. Without
                        # a hard reload the operator sees the old UI and
                        # reasonably concludes the upgrade didn't take.
                        wf_logger.info(
                            "Refresh your browser with Ctrl+Shift+R (Cmd+Shift+R on Mac) "
                            "to load the new interface — until you do, you are still "
                            "viewing the previous version's UI.")
                        wf_logger.info(
                            "This run is kept under Workflows → System workspace, "
                            "so you can reopen these logs at any time.")
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
