#!/usr/bin/env python3
"""
Upgrade Service Package - Module upgrade functions for MSSP platform.
Supports upgrading: ELK, Timesketch, IRIS, Velociraptor, Backend, Frontend
"""

import json
from typing import Dict, Callable

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


def run_upgrade_workflow(modules: Dict[str, str], mode: str = 'online', logger: Callable = None) -> Dict:
    """Run upgrade workflow for selected modules.

    Uses try/finally to ensure Nginx is ALWAYS restarted at the end,
    even if upgrade fails or throws an exception.

    Args:
        modules: Dict of module_name -> target_version (e.g., {"elk": "8.19.0", "iris": "v2.5.0"})
        mode: 'online' or 'offline'
        logger: Logging function

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    upgrade_order = ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'risx']
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
    overall_status = "success"

    current_versions = get_current_versions()

    log(f"Starting upgrade workflow for {total} module(s)", "info")
    log(f"Mode: {mode}", "info")
    log("=" * 50, "info")

    for module_name, target_version in modules.items():
        current = current_versions.get(module_name, {}).get('current', 'unknown')
        log(f"  {module_name.upper()}: {current} -> {target_version}", "info")
    log("=" * 50, "info")

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
                completed += 1

                if result.get('success'):
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")
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
        log("Restarting nginx to refresh DNS resolution...", "info")
        try:
            nginx_result = run_command("docker restart mssp_nginx", logger=log)
            if nginx_result.get('success'):
                log("Nginx restarted successfully", "success")
            else:
                log(f"WARNING: Nginx restart failed: {nginx_result.get('error', 'unknown')}", "warning")
        except Exception as nginx_error:
            log(f"WARNING: Could not restart Nginx: {nginx_error}", "warning")

        # If RISX was upgraded, schedule backend restart with delay
        # (delay allows this response to be sent before container restarts)
        if 'risx' in modules:
            log("Scheduling backend restart in 5 seconds...", "info")
            run_command("nohup sh -c 'sleep 5 && docker restart mssp_backend mssp_tusd' > /dev/null 2>&1 &", logger=log)

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


def run_offline_upgrade_workflow(package_path: str, logger: Callable = None) -> Dict:
    """Run offline upgrade workflow from an uploaded package.

    Uses try/finally to ensure Nginx is ALWAYS restarted at the end,
    even if upgrade fails or throws an exception.

    Args:
        package_path: Path to the uploaded .tar.gz package

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

    upgrade_order = ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'risx']

    results = {}
    total = 0
    completed = 0
    overall_status = "success"
    extract_dir = verify_result.get('extract_dir')

    for module in upgrade_order:
        if module in versions or module == 'risx':
            total += 1

    try:
        for module_name in upgrade_order:
            version = versions.get(module_name)

            if not version and module_name != 'risx':
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

                if result.get('success'):
                    log(f"{module_name.upper()} upgrade completed", "success")
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

        # CRITICAL: Always restart Nginx to pick up new container IPs
        log("Restarting nginx to refresh DNS resolution...", "info")
        try:
            nginx_result = run_command("docker restart mssp_nginx", logger=log)
            if nginx_result.get('success'):
                log("Nginx restarted successfully", "success")
            else:
                log(f"WARNING: Nginx restart failed: {nginx_result.get('error', 'unknown')}", "warning")
        except Exception as nginx_error:
            log(f"WARNING: Could not restart Nginx: {nginx_error}", "warning")

        # If RISX was upgraded, schedule backend restart with delay
        if 'risx' in versions:
            log("Scheduling backend restart in 5 seconds...", "info")
            run_command("nohup sh -c 'sleep 5 && docker restart mssp_backend mssp_tusd' > /dev/null 2>&1 &", logger=log)

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
    # Backwards compatibility
    '_run_command',
    '_read_env_file',
    '_update_env_file',
    '_compare_versions',
]
