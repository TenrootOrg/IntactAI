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

# Fixed package path (only keep one package, overwrite each time)
PACKAGE_PATH = "/data/upgrade_packages/mssp-upgrade-latest.tar.gz"
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


@upgrade_bp.route('/api/upgrade/status', methods=['GET'])
def get_upgrade_status():
    """Get current and latest versions for all modules."""
    try:
        from services.upgrade import get_current_versions, get_latest_versions

        current = get_current_versions()
        latest = get_latest_versions()

        versions = {}
        for module in ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'risx']:
            versions[module] = {
                'current': current.get(module, {}).get('current', 'unknown'),
                'latest': latest.get(module, 'unknown')
            }

        return jsonify({
            "success": True,
            "versions": versions
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/start', methods=['POST'])
def start_upgrade():
    """Start upgrade workflow for selected modules.

    Body: {
        "modules": {"elk": "8.19.0", "iris": "v2.5.0", ...},
        "mode": "online"
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        modules = data.get('modules', {})
        mode = data.get('mode', 'online')

        if not modules:
            return jsonify({"error": "No modules selected for upgrade"}), 400

        if mode != 'online':
            return jsonify({"error": "Only 'online' mode is currently supported"}), 400

        # Create workflow run
        run_id = create_automation_run(
            automation_type="upgrade",
            name="System Upgrade",
            details={
                "trigger": "manual",
                "mode": mode,
                "modules": modules
            }
        )
        add_log_to_run(run_id, f"Starting system upgrade ({mode} mode)", "info")
        add_log_to_run(run_id, f"Modules to upgrade: {', '.join(modules.keys())}", "info")
        update_run_status(run_id, "running", progress=5)

        # Run upgrade in background
        def run_upgrade():
            try:
                from services.upgrade import run_upgrade_workflow

                # Calculate progress per module
                total_modules = len(modules)
                progress_per_module = 90 // total_modules if total_modules > 0 else 90
                completed_modules = [0]  # Use list to allow modification in nested function

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)
                    # Update progress when a module upgrade starts
                    if msg.startswith("UPGRADING:"):
                        progress = 5 + (completed_modules[0] * progress_per_module)
                        update_run_status(run_id, "running", progress=progress)
                    # Update progress only on wrapper completion message (from __init__.py)
                    # Format: "MODULE_NAME upgrade completed: X -> Y" where MODULE_NAME is uppercase
                    # Avoid double-counting from module-level messages or health checks
                    elif level == "success" and " upgrade completed:" in msg:
                        # Only count if message starts with uppercase module name (wrapper message)
                        first_word = msg.split()[0] if msg else ""
                        if first_word.isupper() and first_word in ["ELK", "TIMESKETCH", "PLASO", "IRIS", "VELOCIRAPTOR", "RISX"]:
                            completed_modules[0] += 1
                            progress = 5 + (completed_modules[0] * progress_per_module)
                            update_run_status(run_id, "running", progress=min(progress, 95))

                add_log_to_run(run_id, f"Modules to upgrade: {', '.join(modules.keys())}", "info")
                update_run_status(run_id, "running", progress=5)

                result = run_upgrade_workflow(modules, run_id=run_id, mode=mode, logger=logger)

                # Handle two-phase upgrade (backend restart pending)
                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.", "info")
                    update_run_status(run_id, "running", progress=50)
                    # Don't mark complete - Phase 2 will continue after restart
                elif result.get('success'):
                    add_log_to_run(run_id, f"Upgrade completed: {result['completed']}/{result['total']} modules", "success")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    failed = [m for m, r in result.get('results', {}).items() if not r.get('success')]
                    add_log_to_run(run_id, f"Upgrade completed with failures: {', '.join(failed)}", "warning")
                    update_run_status(run_id, "completed", progress=100)

            except Exception as e:
                add_log_to_run(run_id, f"Upgrade failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()

        # Start background thread
        thread = threading.Thread(target=run_upgrade, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Upgrade started for {len(modules)} module(s)"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

        from services.upgrade import get_package_info
        result = get_package_info(package_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/offline', methods=['POST'])
def start_offline_upgrade():
    """Start offline upgrade from an uploaded package.

    Body: { "package_path": "/data/uploads/..." }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        package_path = data.get('package_path')
        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

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
                        if first_word.isupper() and first_word in ["ELK", "TIMESKETCH", "PLASO", "IRIS", "VELOCIRAPTOR", "RISX"]:
                            completed_modules[0] += 1
                            # Estimate 6 modules max, progress from 5% to 95%
                            progress = 5 + min(completed_modules[0] * 15, 90)
                            update_run_status(run_id, "running", progress=progress)

                result = run_offline_upgrade_workflow(package_path, run_id=run_id, logger=logger)

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
        # - RISX: 2 source copies (backend, frontend)
        # Plus: manifest (1) + archive (1)
        steps_per_module = {
            'elk': 3,
            'timesketch': 1,
            'plaso': 1,
            'iris': 2,
            'velociraptor': 1,
            'risx': 2
        }
        total_steps = sum(steps_per_module.get(m, 1) for m in modules.keys()) + 2  # +2 for manifest and archive
        completed_steps = [0]

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
                        # RISX source copies
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
                add_log_to_run(run_id, f"Package preparation failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()

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


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/status', methods=['GET'])
def get_prepare_status(run_id):
    """Check if a prepared package is ready for download."""
    try:
        pkg = _get_package_info()

        # Check if package exists and matches this run_id
        if pkg and pkg.get('run_id') == run_id and os.path.exists(pkg.get('path', '')):
            return jsonify({
                "success": True,
                "ready": True,
                "package_name": pkg['name'],
                "package_size": pkg['size']
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
