#!/usr/bin/env python3
"""
Upgrade Routes - System upgrade endpoints (online and offline)
"""

from flask import Blueprint, jsonify, request, send_file
import threading
import os
import time
import json

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)

upgrade_bp = Blueprint('upgrade', __name__)


# Allowlist for operator-supplied `package_path` (Mythos finding #7).
# Both `/api/upgrade/package-info` and `/api/upgrade/offline` accept
# `package_path` from the request body, and `/api/upgrade/offline`
# applies its contents over the running install (Phase 1 copies
# `source/intact/*` over WORKDIR/*) — so a tarball at an attacker-
# controlled path means persistent RCE in one POST. The two allowed
# prefixes are the LEGIT landing points: `/data/uploads/` for files
# the operator uploaded through the Import UI card, and
# `/data/upgrade_packages/` for the prepare-side output of the
# Online Upgrade flow. Any path outside these is by definition not
# a legitimate workflow. `os.path.realpath` strips `..` traversal
# before the prefix check, so an input like
# `/data/uploads/foo/../../tmp/evil.tar.gz` resolves outside the
# allowlist and is rejected.
ALLOWED_PACKAGE_DIRS = ('/data/uploads/', '/data/upgrade_packages/')


def _reject_package_path(package_path):
    """Return a (jsonify_response, 400_status) tuple if `package_path`
    is outside the allowlist; otherwise return None.

    Callers use the idiom:
        err = _reject_package_path(package_path)
        if err: return err
    """
    if not isinstance(package_path, str) or not package_path:
        return jsonify({"error": "package_path must be a non-empty string"}), 400
    try:
        real = os.path.realpath(package_path)
    except (OSError, ValueError):
        return jsonify({"error": "invalid package_path"}), 400
    if not any(real.startswith(p) for p in ALLOWED_PACKAGE_DIRS):
        return jsonify({
            "error": f"package_path must be under one of: {', '.join(ALLOWED_PACKAGE_DIRS)}"
        }), 400
    return None


# Fixed package path (only keep one package, overwrite each time)
PACKAGE_PATH = "/data/upgrade_packages/intact-upgrade-latest.tar.gz"
PACKAGE_INFO_FILE = "/data/db/prepared_package.json"


def _get_package_info():
    """Get current prepared package info."""
    if os.path.exists(PACKAGE_INFO_FILE):
        try:
            with open(PACKAGE_INFO_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_package_info(info):
    """Save prepared package info."""
    try:
        os.makedirs(os.path.dirname(PACKAGE_INFO_FILE), exist_ok=True)
        with open(PACKAGE_INFO_FILE, 'w') as f:
            json.dump(info, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save package info: {e}")


def _read_package_manifest(package_path):
    """Read manifest.json from a prepared package to get version info."""
    import tarfile
    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            # Find manifest.json in the archive
            for member in tar.getmembers():
                if member.name.endswith('manifest.json'):
                    f = tar.extractfile(member)
                    if f:
                        return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to read package manifest: {e}")
    return {}


@upgrade_bp.route('/api/upgrade/status', methods=['GET'])
def get_upgrade_status():
    """Get latest versions for all modules (used by Prepare Package modal)."""
    try:
        from services.upgrade import get_latest_versions

        latest = get_latest_versions()

        versions = {}
        for module in ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'aws', 'azure', 'volweb', 'intact']:
            versions[module] = {
                'latest': latest.get(module, 'unknown')
            }

        return jsonify({
            "success": True,
            "versions": versions
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 200  # Return 200 so frontend can use fallbacks


@upgrade_bp.route('/api/upgrade/package-info', methods=['POST'])
def get_upgrade_package_info():
    """Get manifest info from an uploaded upgrade package.

    Body: { "package_path": "/data/uploads/..." }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        package_path = data.get('package_path')
        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

        err = _reject_package_path(package_path)
        if err:
            return err

        from services.upgrade import get_package_info
        result = get_package_info(package_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/offline', methods=['POST'])
def start_offline_upgrade():
    """Start offline upgrade from an uploaded package.

    Body: {
        "package_path": "/data/uploads/...",
        "db_overwrite": {"timesketch": true, "iris": false}  // optional: fresh install per module
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        package_path = data.get('package_path')
        db_overwrite = data.get('db_overwrite', {})  # Per-module fresh install flags

        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

        err = _reject_package_path(package_path)
        if err:
            return err

        if not os.path.exists(package_path):
            return jsonify({"error": f"Package not found: {package_path}"}), 400

        # Create workflow run
        run_id = create_automation_run(
            automation_type="upgrade",
            name="System Upgrade (Offline)",
            details={
                "trigger": "manual",
                "mode": "offline",
                "package_path": package_path
            }
        )
        add_log_to_run(run_id, "Starting offline upgrade from package", "info")
        add_log_to_run(run_id, f"Package: {package_path}", "info")
        update_run_status(run_id, "running", progress=5)

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event = register_cancel_event(run_id)

        # Track completed modules for progress
        completed_modules = [0]

        # Run upgrade in background
        def run_offline_upgrade():
            try:
                from services.upgrade import run_offline_upgrade_workflow

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                    # Track progress based on module completion messages
                    if level == "success" and " upgrade completed" in msg:
                        first_word = msg.split()[0] if msg else ""
                        if first_word.isupper() and first_word in ["ELK", "TIMESKETCH", "PLASO", "IRIS", "VELOCIRAPTOR", "AWS", "AZURE", "Intact.AI"]:
                            completed_modules[0] += 1
                            # Estimate 6 modules max, progress from 5% to 95%
                            progress = 5 + min(completed_modules[0] * 15, 90)
                            update_run_status(run_id, "running", progress=progress)

                result = run_offline_upgrade_workflow(package_path, run_id=run_id, logger=logger,
                                                      db_overwrite=db_overwrite)

                # Handle two-phase upgrade (backend restart pending)
                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.", "info")
                    update_run_status(run_id, "running", progress=50)
                    # Don't mark complete - Phase 2 will continue after restart
                elif result.get('success'):
                    add_log_to_run(run_id, f"Offline upgrade completed: {result.get('completed', 0)}/{result.get('total', 0)} modules", "success")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    failed = [m for m, r in result.get('results', {}).items() if not r.get('success')]
                    if failed:
                        add_log_to_run(run_id, f"Offline upgrade completed with failures: {', '.join(failed)}", "warning")
                    update_run_status(run_id, "completed", progress=100)

            except Exception as e:
                add_log_to_run(run_id, f"Offline upgrade failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        # Start background thread
        thread = threading.Thread(target=run_offline_upgrade, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": "Offline upgrade started"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare', methods=['POST'])
def prepare_upgrade_package():
    """Prepare an upgrade package for offline/air-gapped transfer.

    Body: {
        "modules": {"elk": "9.3.1", "velociraptor": "0.75.6", ...}
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        modules = data.get('modules', {})
        if not modules:
            return jsonify({"error": "No modules selected for package"}), 400

        # NOTE: no downgrade check here on purpose. The prepare-side
        # machine is often DIFFERENT from the target — a build server
        # at 0.76.5 may legitimately prepare a 0.75.6 package destined
        # for a customer who's still on 0.74.0. The downgrade guard
        # lives in services/upgrade/velociraptor.py where it checks
        # the TARGET's .env at apply time, which is the only point
        # where "current vs requested" has a meaningful answer.

        # Create workflow run
        run_id = create_automation_run(
            automation_type="prepare_package",
            name="Prepare Upgrade Package",
            details={
                "trigger": "manual",
                "modules": modules
            }
        )
        add_log_to_run(run_id, "Starting package preparation", "info")
        add_log_to_run(run_id, f"Modules: {', '.join(modules.keys())}", "info")
        update_run_status(run_id, "running", progress=5)

        # Calculate total steps for progress tracking
        # Each module has different number of operations:
        # - ELK: 3 images (elasticsearch, kibana, logstash)
        # - Timesketch: 1 image
        # - Plaso: 1 image
        # - IRIS: 2 images (app, nginx)
        # - Velociraptor: 1 binary download
        # - AWS (Prowler): 1 image
        # - Azure (DFIR-O365RC): 1 image
        # - Intact.AI: 2 source copies (backend, frontend)
        # Plus: manifest (1) + archive (1)
        steps_per_module = {
            'elk': 3,
            'timesketch': 1,
            'plaso': 1,
            'iris': 2,
            'velociraptor': 1,
            'aws': 1,
            'azure': 1,
            'intact': 2
        }
        total_steps = sum(steps_per_module.get(m, 1) for m in modules.keys()) + 2  # +2 for manifest and archive
        completed_steps = [0]

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event_prep = register_cancel_event(run_id)

        # Run package preparation in background
        def run_prepare():
            try:
                from services.upgrade.package import prepare_upgrade_package as do_prepare

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                    # Track progress based on completion messages
                    if level == "success":
                        # Image saved or binary downloaded
                        if msg.strip().startswith("Done (") or msg.strip().startswith("Downloaded ("):
                            completed_steps[0] += 1
                        # Intact.AI source copies
                        elif "source copied" in msg:
                            completed_steps[0] += 1
                        # Manifest created
                        elif "Created manifest.json" in msg:
                            completed_steps[0] += 1
                        # Package archive created
                        elif "Package created:" in msg:
                            completed_steps[0] += 1

                        # Calculate progress (5% start, 95% for work, 100% at end)
                        progress = 5 + int((completed_steps[0] / total_steps) * 90)
                        update_run_status(run_id, "running", progress=min(progress, 95))

                result = do_prepare(modules, run_id, logger)

                if result.get('success'):
                    # Store package info (only one package at a time, overwrites previous)
                    _save_package_info({
                        'run_id': run_id,
                        'path': result['package_path'],
                        'name': result['package_name'],
                        'size': result['package_size'],
                        'created_at': time.time()
                    })
                    add_log_to_run(run_id, f"Package ready for download: {result['package_name']}", "success")
                    add_log_to_run(run_id, "Note: Preparing a new package will replace this one", "info")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    add_log_to_run(run_id, f"Package preparation failed: {result.get('error', 'Unknown error')}", "error")
                    update_run_status(run_id, "failed", progress=0, error=result.get('error'))

            except Exception as e:
                # If the user clicked Stop, the killed subprocess raised
                # on its way out — that's not a real failure. Let the
                # 'cancelled' state (already set by request_stop()) stand.
                from services.workflow_service import is_cancelled, get_automation_run
                wf = get_automation_run(run_id) or {}
                if is_cancelled(run_id) or wf.get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"Package preparation failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        # Start background thread
        thread = threading.Thread(target=run_prepare, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Package preparation started for {len(modules)} module(s)"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/online', methods=['POST'])
def start_online_upgrade():
    """Combined prepare + apply in one workflow — no intermediate tar.gz.

    Same JSON body shape as /api/upgrade/prepare:
        {"modules": {"elk": "9.3.1", "intact": "development", ...}}

    For internet-connected machines. Visible in the same Workflows
    tab as prepare-package and offline-apply.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        modules = data.get('modules', {})
        if not modules:
            return jsonify({"error": "No modules selected for online upgrade"}), 400

        db_overwrite = data.get('db_overwrite') or {}

        run_id = create_automation_run(
            automation_type="online_upgrade",
            name="Online Upgrade",
            details={
                "trigger": "manual",
                "modules": modules,
                "db_overwrite": db_overwrite,
            },
        )
        add_log_to_run(run_id, "Starting online upgrade (prepare + apply in one run)", "info")
        add_log_to_run(run_id, f"Modules: {', '.join(modules.keys())}", "info")
        update_run_status(run_id, "running", progress=2)

        # Progress estimation: split the visible 2-95% band between
        # prepare-side image saves + apply-side per-module completions.
        steps_per_module_prepare = {
            'elk': 3, 'timesketch': 1, 'plaso': 1, 'iris': 2,
            'velociraptor': 1, 'aws': 1, 'azure': 1,
            'volweb': 2, 'intact': 2,
        }
        prepare_steps_total = sum(steps_per_module_prepare.get(m, 1) for m in modules) + 1
        apply_steps_total = len(modules)
        total_steps = max(prepare_steps_total + apply_steps_total, 1)
        completed_steps = [0]

        def bump_progress_from_log(msg, level):
            if level == "success":
                if msg.strip().startswith("Done (") or msg.strip().startswith("Downloaded ("):
                    completed_steps[0] += 1
                elif "source copied" in msg:
                    completed_steps[0] += 1
                elif "Created manifest.json" in msg:
                    completed_steps[0] += 1
                elif "upgrade completed" in msg:
                    completed_steps[0] += 1
            elif level == "error" and msg.startswith("MODULE_FAILED:"):
                completed_steps[0] += 1
            progress = 2 + int((completed_steps[0] / total_steps) * 93)
            update_run_status(run_id, "running", progress=min(progress, 95))

        from services.workflow_service import register_cancel_event, unregister_cancel
        register_cancel_event(run_id)

        def run_online():
            try:
                from services.upgrade import run_online_upgrade_workflow

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)
                    try:
                        bump_progress_from_log(msg, level)
                    except Exception:
                        pass

                result = run_online_upgrade_workflow(
                    modules=modules,
                    run_id=run_id,
                    logger=logger,
                    db_overwrite=db_overwrite,
                )

                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting to resume Phase 2.", "info")
                    return

                if result.get('success'):
                    update_run_status(run_id, "completed", progress=100)
                else:
                    from services.workflow_service import get_automation_run
                    wf = get_automation_run(run_id) or {}
                    if wf.get('status') in ('running', None):
                        update_run_status(run_id, "failed", progress=0,
                                          error=result.get('error', 'unknown'))

            except Exception as e:
                from services.workflow_service import is_cancelled, get_automation_run
                wf = get_automation_run(run_id) or {}
                if is_cancelled(run_id) or wf.get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"Online upgrade failed: {str(e)}", "error")
                import traceback
                add_log_to_run(run_id, f"Traceback: {traceback.format_exc()[:800]}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        thread = threading.Thread(target=run_online, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Online upgrade started for {len(modules)} module(s)",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/status', methods=['GET'])
def get_prepare_status(run_id):
    """Check if a prepared package is ready for download."""
    try:
        pkg = _get_package_info()

        # Check if package exists and matches this run_id
        if pkg and pkg.get('run_id') == run_id and os.path.exists(pkg.get('path', '')):
            # Read manifest to get versions for user confirmation
            manifest = _read_package_manifest(pkg['path'])
            return jsonify({
                "success": True,
                "ready": True,
                "package_name": pkg['name'],
                "package_size": pkg['size'],
                "versions": manifest.get('versions', {})
            })
        else:
            return jsonify({
                "success": True,
                "ready": False,
                "message": "Package was replaced by a newer preparation"
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/download', methods=['GET'])
def download_prepared_package(run_id):
    """Download a prepared upgrade package."""
    try:
        pkg = _get_package_info()

        # Check if package exists and matches this run_id
        if not pkg or pkg.get('run_id') != run_id:
            return jsonify({"error": "Package was replaced by a newer preparation. Please prepare again."}), 410

        package_path = pkg['path']
        package_name = pkg['name']

        if not os.path.exists(package_path):
            return jsonify({"error": "Package file not found on server"}), 404

        return send_file(
            package_path,
            as_attachment=True,
            download_name=package_name,
            mimetype='application/gzip'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
