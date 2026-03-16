#!/usr/bin/env python3
"""
Upgrade Service Package - Module upgrade functions for MSSP platform.
Supports upgrading: ELK, Timesketch, IRIS, Velociraptor, Backend, Frontend

Two-Phase Upgrade Support:
- Phase 1: Upgrades RISX (backend code), saves state, triggers restart
- Phase 2: Resumes after restart, upgrades remaining modules
"""

import json
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
from .risx import upgrade_risx, upgrade_risx_offline
from .plaso import upgrade_plaso, upgrade_plaso_offline

# Storage functions for two-phase upgrade state
from services.storage.base import (
    save_upgrade_state,
    get_pending_upgrade,
    get_upgrade_state,
    update_upgrade_phase,
    clear_upgrade_state,
)


def schedule_backend_restart():
    """Schedule backend restart after short delay using detached process."""
    subprocess.Popen(
        ['sh', '-c', 'sleep 3 && docker restart mssp_backend mssp_tusd'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )


def restart_nginx(log: Callable) -> bool:
    """Restart nginx container."""
    log("Restarting nginx to refresh DNS resolution...", "info")
    try:
        nginx_result = run_command("docker restart mssp_nginx", logger=log)
        if nginx_result.get('success'):
            log("Nginx restarted successfully", "success")
            return True
        else:
            log(f"WARNING: Nginx restart failed: {nginx_result.get('error', 'unknown')}", "warning")
            return False
    except Exception as nginx_error:
        log(f"WARNING: Could not restart Nginx: {nginx_error}", "warning")
        return False


def run_upgrade_workflow(modules: Dict[str, str], run_id: str = None, mode: str = 'online', logger: Callable = None) -> Dict:
    """Run upgrade workflow for selected modules with two-phase support.

    Two-Phase Upgrade:
    - If RISX is in modules, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules

    Args:
        modules: Dict of module_name -> target_version (e.g., {"elk": "8.19.0", "iris": "v2.5.0"})
        run_id: Workflow run ID for state tracking
        mode: 'online' or 'offline'
        logger: Logging function

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # RISX must be first so backend code is updated before modules
    upgrade_order = ['risx', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']
    upgrade_functions = {
        'elk': upgrade_elk,
        'timesketch': upgrade_timesketch,
        'plaso': upgrade_plaso,
        'iris': upgrade_iris,
        'velociraptor': upgrade_velociraptor,
        'risx': upgrade_risx,
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
        save_upgrade_state(run_id, 'phase1', modules, [], mode)

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

            upgrade_fn = upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'risx':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed += 1
                    completed_modules.append(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Special handling for RISX - trigger Phase 2
                    if module_name == 'risx' and run_id:
                        # Check if there are more modules to upgrade
                        remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - RISX upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume
                            save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode)

                            # Restart nginx first (for new UI)
                            restart_nginx(log)

                            # Schedule backend restart
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

    # Mark as phase 2 in progress
    update_upgrade_phase(run_id, 'phase2')

    modules = state['target_modules']
    completed_modules = set(state['completed_modules'])
    mode = state.get('mode', 'online')
    package_dir = state.get('package_dir')

    upgrade_order = ['risx', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']

    # Use online or offline functions based on mode
    if mode == 'offline':
        upgrade_functions = {
            'elk': lambda v, **kw: upgrade_elk_offline(package_dir, v, **kw),
            'timesketch': lambda v, **kw: upgrade_timesketch_offline(package_dir, v, **kw),
            'plaso': lambda v, **kw: upgrade_plaso_offline(package_dir, v, **kw),
            'iris': lambda v, **kw: upgrade_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: upgrade_velociraptor_offline(package_dir, v, **kw),
            'risx': lambda **kw: upgrade_risx_offline(package_dir, **kw),
        }
    else:
        upgrade_functions = {
            'elk': upgrade_elk,
            'timesketch': upgrade_timesketch,
            'plaso': upgrade_plaso,
            'iris': upgrade_iris,
            'velociraptor': upgrade_velociraptor,
            'risx': upgrade_risx,
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

            upgrade_fn = upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'risx':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed_modules.add(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")
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


def run_offline_upgrade_workflow(package_path: str, run_id: str = None, logger: Callable = None) -> Dict:
    """Run offline upgrade workflow from an uploaded package with two-phase support.

    Two-Phase Upgrade:
    - If RISX source is in package, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules

    Args:
        package_path: Path to the uploaded .tar.gz package
        run_id: Workflow run ID for state tracking
        logger: Logging function

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    log("=" * 50, "info")
    log("OFFLINE UPGRADE WORKFLOW", "info")
    log("=" * 50, "info")

    # Verify and extract package
    verify_result = verify_upgrade_package(package_path, logger=log)
    if not verify_result['success']:
        return {"success": False, "error": verify_result.get('error', 'Package verification failed')}

    package_dir = verify_result['package_dir']
    manifest = verify_result['manifest']
    versions = manifest.get('versions', {})

    log("", "info")
    log(f"Package versions: {json.dumps(versions)}", "info")

    offline_upgrade_functions = {
        'elk': upgrade_elk_offline,
        'timesketch': upgrade_timesketch_offline,
        'plaso': upgrade_plaso_offline,
        'iris': upgrade_iris_offline,
        'velociraptor': upgrade_velociraptor_offline,
        'risx': upgrade_risx_offline,
    }

    # RISX must be first so backend code is updated before modules
    upgrade_order = ['risx', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor']

    results = {}
    total = 0
    completed = 0
    completed_modules = []
    overall_status = "success"
    extract_dir = verify_result.get('extract_dir')

    # Build modules dict for state tracking
    modules_dict = {k: v for k, v in versions.items()}
    if 'risx' not in modules_dict:
        # Check if risx source exists in package
        import os
        backend_source = os.path.join(package_dir, 'source', 'backend')
        frontend_source = os.path.join(package_dir, 'source', 'frontend')
        if os.path.exists(backend_source) or os.path.exists(frontend_source):
            modules_dict['risx'] = 'from_package'

    for module in upgrade_order:
        if module in modules_dict:
            total += 1

    # Save initial state if we have a run_id
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules_dict, [], 'offline', package_dir)

    try:
        for module_name in upgrade_order:
            version = versions.get(module_name)

            # For risx, check if source exists
            if module_name == 'risx':
                import os
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

            upgrade_fn = offline_upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'risx':
                    result = upgrade_fn(package_dir, logger=log)
                elif module_name == 'timesketch':
                    plaso_version = versions.get('plaso')
                    result = upgrade_fn(package_dir, version, plaso_version=plaso_version, logger=log)
                else:
                    result = upgrade_fn(package_dir, version, logger=log)

                results[module_name] = result
                if not result.get('skipped'):
                    completed += 1
                    completed_modules.append(module_name)

                if result.get('success'):
                    log(f"{module_name.upper()} upgrade completed", "success")

                    # Special handling for RISX - trigger Phase 2
                    if module_name == 'risx' and run_id and not result.get('skipped'):
                        remaining = [m for m in upgrade_order if m in modules_dict and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - RISX upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume
                            save_upgrade_state(run_id, 'awaiting_restart', modules_dict, completed_modules, 'offline', package_dir)

                            # Restart nginx first (for new UI)
                            restart_nginx(log)

                            # Schedule backend restart
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart()

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
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING OFFLINE UPGRADE WORKFLOW", "info")
        log(f"{'='*50}", "info")

        # Cleanup extracted package
        log("Cleaning up...", "info")
        if extract_dir:
            import os
            if os.path.exists(extract_dir):
                run_command(f"rm -rf {extract_dir}", logger=log)

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
    'upgrade_risx',
    # Offline upgrade functions
    'upgrade_elk_offline',
    'upgrade_timesketch_offline',
    'upgrade_plaso_offline',
    'upgrade_iris_offline',
    'upgrade_velociraptor_offline',
    'upgrade_risx_offline',
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
