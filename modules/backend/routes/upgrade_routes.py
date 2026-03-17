#!/usr/bin/env python3
"""
Upgrade Routes - System upgrade endpoints (online and offline)
"""

from flask import Blueprint, jsonify, request
import threading
import os

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)

upgrade_bp = Blueprint('upgrade', __name__)


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

        # Run upgrade in background
        def run_offline_upgrade():
            try:
                from services.upgrade import run_offline_upgrade_workflow

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                result = run_offline_upgrade_workflow(package_path, logger=logger)

                if result.get('success'):
                    add_log_to_run(run_id, f"Offline upgrade completed: {result['completed']}/{result['total']} modules", "success")
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
