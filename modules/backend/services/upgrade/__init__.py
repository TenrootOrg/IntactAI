#!/usr/bin/env python3
"""
Upgrade Service Package - Module upgrade functions for Intact.AI platform.
Supports upgrading: ELK, Timesketch, IRIS, Velociraptor, Backend, Frontend

Two-Phase Upgrade Support:
- Phase 1: Upgrades Intact.AI (backend code), saves state, triggers restart
- Phase 2: Resumes after restart, upgrades remaining modules
"""

import json
import os
import subprocess
from typing import Dict, Callable, Optional

# Base utilities
from .base import (
    WORKDIR,
    HOST_PATH,
    run_command,
    read_env_file,
    update_env_file,
    compare_versions,
    get_current_versions,
    get_latest_versions,
    load_docker_image,
    verify_upgrade_package,
    get_package_info,
)

# Module-specific upgrade functions
from .elk import upgrade_elk, upgrade_elk_offline
from .timesketch import upgrade_timesketch, upgrade_timesketch_offline
from .iris import upgrade_iris, upgrade_iris_offline
from .velociraptor import upgrade_velociraptor, upgrade_velociraptor_offline
from .intact import upgrade_intact, upgrade_intact_offline
from .plaso import upgrade_plaso, upgrade_plaso_offline

# Storage functions for two-phase upgrade state
from services.storage.base import (
    save_upgrade_state,
    get_pending_upgrade,
    get_upgrade_state,
    update_upgrade_phase,
    clear_upgrade_state,
)

# Database volumes that can be reset for fresh install (schema compatibility)
RESET_VOLUMES = {
    'timesketch': ['timesketch_timesketch_postgres_data', 'timesketch_timesketch_opensearch_data'],
    'iris': ['iris_iris_db_data'],
    'elk': ['elk_elasticsearch_data'],
}


def reset_module_database(module_name: str, logger: Callable = None) -> bool:
    """Remove database volumes for fresh install (new schema).

    This is needed when upgrading between versions with incompatible
    database schemas (e.g., Timesketch 2024 -> 2026 with DFIQ columns).

    Args:
        module_name: Name of the module (timesketch, iris, elk)
        logger: Logging function

    Returns:
        True if successful, False otherwise
    """
    if module_name not in RESET_VOLUMES:
        return True

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log(f"Fresh install: removing {module_name} database for new schema...", "warning")

    # Get module directory
    module_dir = os.path.join(HOST_PATH, 'modules', module_name)

    # Stop containers first
    log(f"Stopping {module_name} containers...", "info")
    run_command("docker compose down", cwd=module_dir, logger=log)

    # Remove volumes
    for volume in RESET_VOLUMES[module_name]:
        log(f"Removing volume: {volume}", "info")
        run_command(f"docker volume rm {volume} 2>/dev/null || true", logger=log)

    log(f"Database volumes removed for {module_name}", "success")
    return True


def recreate_timesketch_user(logger: Callable = None) -> bool:
    """Recreate Timesketch user after database reset.

    Reads credentials from config.yaml and creates the user.

    Args:
        logger: Logging function

    Returns:
        True if successful, False otherwise
    """
    import time
    import yaml

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log("Recreating Timesketch user after database reset...", "info")

    # Load config.yaml
    config_path = os.path.join(HOST_PATH, 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "error")
        return False

    ts_user = config.get('modules', {}).get('timesketch', {}).get('id')
    ts_pass = config.get('modules', {}).get('timesketch', {}).get('password')

    if not ts_user or not ts_pass:
        log("Timesketch credentials not found in config.yaml", "error")
        return False

    # Wait for Timesketch to be ready
    log("Waiting for Timesketch to be ready...", "info")
    time.sleep(15)

    # Create user
    result = run_command(
        f'docker exec intact_timesketch_web tsctl create-user "{ts_user}" --password "{ts_pass}"',
        logger=log
    )
    if not result.get('success'):
        log(f"Failed to create user: {result.get('error')}", "error")
        return False

    # Make admin
    result = run_command(
        f'docker exec intact_timesketch_web tsctl make-admin "{ts_user}"',
        logger=log
    )
    if not result.get('success'):
        log(f"Warning: Could not make user admin: {result.get('error')}", "warning")

    log(f"Timesketch user '{ts_user}' created successfully", "success")
    return True


def schedule_backend_restart():
    """Schedule backend restart after short delay using detached process."""
    subprocess.Popen(
        ['sh', '-c', 'sleep 3 && docker restart intact_backend intact_tusd'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )


def restart_nginx(log: Callable) -> bool:
    """Restart nginx container."""
    log("Restarting nginx to refresh DNS resolution...", "info")
    try:
        nginx_result = run_command("docker restart intact_nginx", logger=log)
        if nginx_result.get('success'):
            log("Nginx restarted successfully", "success")
            return True
        else:
            log(f"WARNING: Nginx restart failed: {nginx_result.get('error', 'unknown')}", "warning")
            return False
    except Exception as nginx_error:
        log(f"WARNING: Could not restart Nginx: {nginx_error}", "warning")
        return False


def run_upgrade_workflow(modules: Dict[str, str], run_id: str = None, mode: str = 'online',
                         logger: Callable = None, db_overwrite: Dict = None) -> Dict:
    """Run upgrade workflow for selected modules with two-phase support.

    Two-Phase Upgrade:
    - If Intact.AI is in modules, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules

    Args:
        modules: Dict of module_name -> target_version (e.g., {"elk": "8.19.0", "iris": "v2.5.0"})
        run_id: Workflow run ID for state tracking
        mode: 'online' or 'offline'
        logger: Logging function
        db_overwrite: Dict of module -> bool for fresh install (e.g., {"timesketch": True})

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    db_overwrite = db_overwrite or {}

    # Intact.AI must be first so backend code is updated before modules
    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']
    upgrade_functions = {
        'elk': upgrade_elk,
        'timesketch': upgrade_timesketch,
        'plaso': upgrade_plaso,
        'iris': upgrade_iris,
        'velociraptor': upgrade_velociraptor,
        'intact': upgrade_intact,
    }

    results = {}
    total = len(modules)
    completed = 0
    completed_modules = []
    overall_status = "success"

    current_versions = get_current_versions()

    log(f"Starting upgrade workflow for {total} module(s)", "info")
    log(f"Mode: {mode}", "info")
    log("=" * 50, "info")

    for module_name, target_version in modules.items():
        current = current_versions.get(module_name, {}).get('current', 'unknown')
        log(f"  {module_name.upper()}: {current} -> {target_version}", "info")
    log("=" * 50, "info")

    # Save initial state if we have a run_id
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules, [], mode, db_overwrite=db_overwrite)

    try:
        for module_name in upgrade_order:
            if module_name not in modules:
                continue

            target_version = modules[module_name]
            current = current_versions.get(module_name, {}).get('current', 'unknown')
            log("", "info")
            log(f"{'='*50}", "info")
            log(f"UPGRADING: {module_name.upper()}", "info")
            log(f"  Current version: {current}", "info")
            log(f"  Target version:  {target_version}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            upgrade_fn = upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'intact':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed += 1
                    completed_modules.append(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    # Special handling for Intact.AI - trigger Phase 2
                    if module_name == 'intact' and run_id:
                        # Check if there are more modules to upgrade
                        remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume (include db_overwrite)
                            save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode,
                                               db_overwrite=db_overwrite)

                            # Schedule backend restart (nginx will restart at Phase 2 start)
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart()

                            return {
                                "success": True,
                                "phase": "awaiting_restart",
                                "status": "awaiting_restart",
                                "message": "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.",
                                "results": results,
                                "completed": completed,
                                "total": total
                            }

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"{module_name.upper()} upgrade failed: {result.get('error', 'unknown')}", "error")
                    overall_status = "completed_with_errors"

            except Exception as e:
                log(f"{module_name.upper()} upgrade error: {str(e)}", "error")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"

    except Exception as unexpected_error:
        # Catch any unexpected error in the workflow itself
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        # ==============================================================
        # THIS BLOCK RUNS NO MATTER WHAT - SUCCESS, FAILURE, OR EXCEPTION
        # ==============================================================
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING UPGRADE WORKFLOW", "info")
        log(f"{'='*50}", "info")

        # CRITICAL: Always restart Nginx to pick up new container IPs
        restart_nginx(log)

        # Clear upgrade state on completion (if not awaiting restart)
        if run_id:
            clear_upgrade_state(run_id)

        # Print summary
        log("", "info")
        log(f"{'='*50}", "info")
        log(f"UPGRADE COMPLETE - Status: {overall_status}", "info")
        log(f"{'='*50}", "info")

        for module_name, result in results.items():
            if module_name.startswith("_"):
                continue
            icon = "OK" if result.get('success') else "FAILED"
            log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")
            if result.get('rolled_back'):
                log(f"       -> Rolled back to {result.get('restored_version')}", "warning")

        log(f"{'='*50}", "info")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "results": results,
        "completed": completed,
        "total": total
    }


def resume_upgrade_workflow(run_id: str, logger: Callable = None) -> Dict:
    """Resume upgrade after backend restart (Phase 2).

    Called automatically on startup when a pending upgrade is detected.

    Args:
        run_id: The workflow run ID to resume
        logger: Logging function

    Returns:
        Dict with success status and results
    """
    log = logger or (lambda msg, level="info": print(f"[UPGRADE-RESUME] [{level}] {msg}"))

    # Get saved state
    state = get_upgrade_state(run_id)
    if not state:
        return {"success": False, "error": f"No upgrade state found for {run_id}"}

    if state['phase'] != 'awaiting_restart':
        return {"success": False, "error": f"Upgrade not in awaiting_restart phase: {state['phase']}"}

    log("", "info")
    log(f"{'='*50}", "info")
    log("PHASE 2 - RESUMING UPGRADE AFTER RESTART", "info")
    log(f"Run ID: {run_id}", "info")
    log(f"{'='*50}", "info")

    # Restart nginx first (for new UI code)
    restart_nginx(log)

    # Mark as phase 2 in progress
    update_upgrade_phase(run_id, 'phase2')

    modules = state['target_modules']
    completed_modules = set(state['completed_modules'])
    mode = state.get('mode', 'online')
    db_overwrite = state.get('db_overwrite', {})  # Per-module fresh install flags

    # Parse package paths from state (stored as JSON with extract_dir and package_path)
    package_dir_raw = state.get('package_dir')
    extract_dir = None
    package_path = None
    package_dir = None

    if package_dir_raw:
        try:
            paths = json.loads(package_dir_raw)
            extract_dir = paths.get('extract_dir')
            package_path = paths.get('package_path')
            # Find the actual package subdir inside extract_dir
            if extract_dir and os.path.exists(extract_dir):
                subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
                if subdirs:
                    package_dir = os.path.join(extract_dir, subdirs[0])
                else:
                    package_dir = extract_dir
        except (json.JSONDecodeError, TypeError):
            # Backwards compatibility: old format was just a path string
            package_dir = package_dir_raw
            extract_dir = package_dir_raw

    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']

    # Use online or offline functions based on mode
    if mode == 'offline':
        upgrade_functions = {
            'elk': lambda v, **kw: upgrade_elk_offline(package_dir, v, **kw),
            'timesketch': lambda v, **kw: upgrade_timesketch_offline(package_dir, v, **kw),
            'plaso': lambda v, **kw: upgrade_plaso_offline(package_dir, v, **kw),
            'iris': lambda v, **kw: upgrade_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: upgrade_velociraptor_offline(package_dir, v, **kw),
            'intact': lambda **kw: upgrade_intact_offline(package_dir, **kw),
        }
    else:
        upgrade_functions = {
            'elk': upgrade_elk,
            'timesketch': upgrade_timesketch,
            'plaso': upgrade_plaso,
            'iris': upgrade_iris,
            'velociraptor': upgrade_velociraptor,
            'intact': upgrade_intact,
        }

    results = {}
    overall_status = "success"
    current_versions = get_current_versions()

    # Show what's remaining
    remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
    log(f"Modules to upgrade: {', '.join(remaining)}", "info")
    log("=" * 50, "info")

    try:
        for module_name in upgrade_order:
            if module_name not in modules or module_name in completed_modules:
                continue

            target_version = modules[module_name]
            current = current_versions.get(module_name, {}).get('current', 'unknown')

            log("", "info")
            log(f"{'='*50}", "info")
            log(f"UPGRADING: {module_name.upper()}", "info")
            log(f"  Current version: {current}", "info")
            log(f"  Target version:  {target_version}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            upgrade_fn = upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'intact':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed_modules.add(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    update_upgrade_phase(run_id, 'phase2', list(completed_modules))
                else:
                    log(f"{module_name.upper()} upgrade failed: {result.get('error', 'unknown')}", "error")
                    overall_status = "completed_with_errors"

            except Exception as e:
                log(f"{module_name.upper()} upgrade error: {str(e)}", "error")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"

    except Exception as unexpected_error:
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING PHASE 2", "info")
        log(f"{'='*50}", "info")

        # Cleanup extracted package directory
        if extract_dir and os.path.exists(extract_dir):
            log("Cleaning up extracted package...", "info")
            run_command(f"rm -rf {extract_dir}", logger=log)

        # Cleanup uploaded package file
        if package_path and os.path.exists(package_path):
            try:
                os.remove(package_path)
                log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
            except Exception as e:
                log(f"Warning: Could not remove package file: {e}", "warning")

        # Final nginx restart
        restart_nginx(log)

        # Mark complete and clear state
        update_upgrade_phase(run_id, 'completed')
        clear_upgrade_state(run_id)

        # Print summary
        log("", "info")
        log(f"{'='*50}", "info")
        log(f"PHASE 2 COMPLETE - Status: {overall_status}", "info")
        log(f"{'='*50}", "info")

        for module_name, result in results.items():
            if module_name.startswith("_"):
                continue
            icon = "OK" if result.get('success') else "FAILED"
            log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")

        log(f"{'='*50}", "info")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "phase": "completed",
        "results": results
    }


def run_offline_upgrade_workflow(package_path: str, run_id: str = None, logger: Callable = None,
                                  db_overwrite: Dict = None) -> Dict:
    """Run offline upgrade workflow from an uploaded package with two-phase support.

    Two-Phase Upgrade:
    - If Intact.AI source is in package, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules

    Args:
        package_path: Path to the uploaded .tar.gz package
        run_id: Workflow run ID for state tracking
        logger: Logging function
        db_overwrite: Dict of module -> bool for fresh install (e.g., {"timesketch": True})

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    db_overwrite = db_overwrite or {}

    log("=" * 50, "info")
    log("OFFLINE UPGRADE WORKFLOW", "info")
    log("=" * 50, "info")

    # Cleanup any previous installation remnants
    import glob
    old_dirs = glob.glob('/app/data/tmp/intact-upgrade-*') + glob.glob('/data/tmp/intact-upgrade-*') + glob.glob('/tmp/intact-upgrade-*')
    if old_dirs:
        log("Cleaning up previous installation remnants...", "info")
        for old_dir in old_dirs:
            log(f"  Removing: {old_dir}", "info")
            run_command(f"rm -rf {old_dir}", logger=log)

    # Verify and extract package
    verify_result = verify_upgrade_package(package_path, logger=log)
    if not verify_result['success']:
        # Cleanup uploaded package on failure
        if package_path and os.path.exists(package_path):
            try:
                os.remove(package_path)
                log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
            except Exception:
                pass
        return {"success": False, "error": verify_result.get('error', 'Package verification failed')}

    package_dir = verify_result['package_dir']
    manifest = verify_result['manifest']
    versions = manifest.get('versions', {})

    # Get current versions for comparison
    current_versions = get_current_versions()

    # Log current vs target versions
    log("", "info")
    log("VERSION SUMMARY:", "info")
    log("-" * 40, "info")
    for module, target_ver in versions.items():
        current_ver = current_versions.get(module, {}).get('current', 'unknown')
        log(f"  {module.upper()}: {current_ver} -> {target_ver}", "info")
    log("-" * 40, "info")
    log("", "info")

    offline_upgrade_functions = {
        'elk': upgrade_elk_offline,
        'timesketch': upgrade_timesketch_offline,
        'plaso': upgrade_plaso_offline,
        'iris': upgrade_iris_offline,
        'velociraptor': upgrade_velociraptor_offline,
        'intact': upgrade_intact_offline,
    }

    # Intact.AI must be first so backend code is updated before modules
    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']

    results = {}
    total = 0
    completed = 0
    completed_modules = []
    overall_status = "success"
    awaiting_restart = False  # Flag to prevent cleanup when Phase 2 pending
    extract_dir = verify_result.get('extract_dir')

    # Build modules dict for state tracking
    modules_dict = {k: v for k, v in versions.items()}
    if 'intact' not in modules_dict:
        # Check if intact source exists in package (not just empty dirs)
        backend_source = os.path.join(package_dir, 'source', 'backend')
        frontend_source = os.path.join(package_dir, 'source', 'frontend')
        has_backend = os.path.exists(backend_source) and os.listdir(backend_source)
        has_frontend = os.path.exists(frontend_source) and os.listdir(frontend_source)
        if has_backend or has_frontend:
            modules_dict['intact'] = 'from_package'

    for module in upgrade_order:
        if module in modules_dict:
            total += 1

    # Save initial state if we have a run_id (include package_path for cleanup after Phase 2)
    extract_dir = verify_result.get('extract_dir')
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules_dict, [], 'offline', extract_dir, package_path,
                           db_overwrite=db_overwrite)

    try:
        for module_name in upgrade_order:
            version = versions.get(module_name)

            # For intact, check if source exists
            if module_name == 'intact':
                backend_source = os.path.join(package_dir, 'source', 'backend')
                frontend_source = os.path.join(package_dir, 'source', 'frontend')
                if not os.path.exists(backend_source) and not os.path.exists(frontend_source):
                    continue
            elif not version:
                continue

            log("", "info")
            log(f"{'='*50}", "info")
            log(f"UPGRADING: {module_name.upper()} -> {version or 'from source'}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            upgrade_fn = offline_upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'intact':
                    result = upgrade_fn(package_dir, logger=log)
                else:
                    # Note: Plaso is handled as its own module, not bundled with Timesketch
                    result = upgrade_fn(package_dir, version, logger=log)

                results[module_name] = result
                if not result.get('skipped'):
                    completed += 1
                    completed_modules.append(module_name)

                if result.get('success'):
                    log(f"{module_name.upper()} upgrade completed", "success")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    # Special handling for Intact.AI - trigger Phase 2
                    if module_name == 'intact' and run_id and not result.get('skipped'):
                        remaining = [m for m in upgrade_order if m in modules_dict and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume (include package_path for cleanup)
                            save_upgrade_state(run_id, 'awaiting_restart', modules_dict, completed_modules, 'offline',
                                               extract_dir, package_path, db_overwrite=db_overwrite)

                            # Schedule backend restart (nginx will restart at Phase 2 start)
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart()

                            # Set flag to prevent cleanup in finally block
                            awaiting_restart = True

                            return {
                                "success": True,
                                "phase": "awaiting_restart",
                                "status": "awaiting_restart",
                                "message": "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.",
                                "results": results,
                                "completed": completed,
                                "total": total,
                                "versions": versions
                            }

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"{module_name.upper()} upgrade failed: {result.get('error', 'unknown')}", "error")
                    overall_status = "completed_with_errors"

            except Exception as e:
                log(f"{module_name.upper()} upgrade error: {str(e)}", "error")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"

    except Exception as unexpected_error:
        # Catch any unexpected error in the workflow itself
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        # ==============================================================
        # THIS BLOCK RUNS NO MATTER WHAT - SUCCESS, FAILURE, OR EXCEPTION
        # ==============================================================

        # Skip cleanup if awaiting restart (Phase 2 needs the extracted files)
        if not awaiting_restart:
            log("", "info")
            log(f"{'='*50}", "info")
            log("FINALIZING OFFLINE UPGRADE WORKFLOW", "info")
            log(f"{'='*50}", "info")

            # Cleanup extracted package
            log("Cleaning up...", "info")
            if extract_dir and os.path.exists(extract_dir):
                run_command(f"rm -rf {extract_dir}", logger=log)

            # Cleanup uploaded package file to free disk space
            if package_path and os.path.exists(package_path):
                try:
                    os.remove(package_path)
                    log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
                except Exception as e:
                    log(f"Warning: Could not remove package file: {e}", "warning")

            # Restart nginx
            restart_nginx(log)

            # Clear upgrade state on completion
            if run_id:
                clear_upgrade_state(run_id)

            # Print summary
            log("", "info")
            log(f"{'='*50}", "info")
            log(f"OFFLINE UPGRADE COMPLETE - Status: {overall_status}", "info")
            log(f"{'='*50}", "info")

            for module_name, result in results.items():
                if module_name.startswith("_"):
                    continue
                icon = "OK" if result.get('success') else "FAILED"
                log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")
                if result.get('rolled_back'):
                    log(f"       -> Rolled back to {result.get('restored_version')}", "warning")

            log(f"{'='*50}", "info")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "results": results,
        "completed": completed,
        "total": total,
        "versions": versions
    }


# Backwards compatibility - expose private names as well
_run_command = run_command
_read_env_file = read_env_file
_update_env_file = update_env_file
_compare_versions = compare_versions


__all__ = [
    # Base utilities
    'WORKDIR',
    'HOST_PATH',
    'run_command',
    'read_env_file',
    'update_env_file',
    'compare_versions',
    'get_current_versions',
    'get_latest_versions',
    'load_docker_image',
    'verify_upgrade_package',
    'get_package_info',
    # Online upgrade functions
    'upgrade_elk',
    'upgrade_timesketch',
    'upgrade_plaso',
    'upgrade_iris',
    'upgrade_velociraptor',
    'upgrade_intact',
    # Offline upgrade functions
    'upgrade_elk_offline',
    'upgrade_timesketch_offline',
    'upgrade_plaso_offline',
    'upgrade_iris_offline',
    'upgrade_velociraptor_offline',
    'upgrade_intact_offline',
    # Workflow functions
    'run_upgrade_workflow',
    'run_offline_upgrade_workflow',
    'resume_upgrade_workflow',
    # State management
    'get_pending_upgrade',
    # Backwards compatibility
    '_run_command',
    '_read_env_file',
    '_update_env_file',
    '_compare_versions',
]
