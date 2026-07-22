#!/usr/bin/env python3
"""DFIR-O365RC (Microsoft 365 Unified Audit Log) upgrade functions.

DFIR-O365RC runs on demand against M365 tenants — no long-running
container, so "upgrade" means pulling the image and pinning it in the
backend .env (DFIR_O365RC_VERSION). Upstream only publishes ':latest'
(no version tags), so the version is normally 'latest' and an upgrade
re-pulls the newest latest. The scan runner
(services/azure/dfir_o365rc.py) reads the version fresh, so the new
image applies on the next scan without a backend restart. Mirrors the
Plaso upgrader.

Internal function names (`upgrade_azure`, `upgrade_azure_offline`) kept
for backwards compatibility with the dispatcher tables; the public module
key exposed via the API + run logs is now 'o365rc'.
"""

import os
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR,
    run_command, read_env_file, update_env_file, preflight_offline_images,
    backup_env_file, restore_env_file, cleanup_backup,
    set_module_enabled_in_config,
)


def upgrade_azure(version: str, logger: Callable = None) -> Dict:
    """Pull the DFIR-O365RC image at `version` (usually 'latest') and pin it."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting DFIR-O365RC upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('DFIR_O365RC_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        log(f"Pulling DFIR-O365RC {version}...", "info")
        result = run_command(f"docker pull anssi/dfir-o365rc:{version}", logger=log, timeout=1800)
        if not result['success']:
            raise Exception(f"Failed to pull DFIR-O365RC image: {result['error']}")

        log(f"Updating DFIR-O365RC version to {version}...", "info")
        update_env_file(backend_env, 'DFIR_O365RC_VERSION', version, logger=log)

        # Mark o365rc as enabled in config.yaml so the sidebar, dashboard
        # cards and runtime is_module_enabled() gate all see this install.
        set_module_enabled_in_config('o365rc', logger=log)

        # No backend restart needed — DFIR-O365RC runs as a separate container
        # per scan and dfir_o365rc reads DFIR_O365RC_VERSION fresh from .env.

        cleanup_backup(backup_file, logger=log)
        log(f"DFIR-O365RC upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"DFIR-O365RC upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK DFIR-O365RC to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }


def upgrade_azure_offline(package_dir: str, version: str, logger: Callable = None,
                            run_id: Optional[str] = None) -> Dict:
    """Upgrade DFIR-O365RC from an offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting DFIR-O365RC offline upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('DFIR_O365RC_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        # See the twin block in plaso.py for the full rationale. Short version:
        # the orchestrator pre-loads bundled tars and deletes them to reclaim
        # disk, so an absent tar is normal and only proves nothing about the
        # image. Warning-and-continuing let a genuinely missing image report
        # "upgrade completed" while DFIR_O365RC_VERSION was stamped to a tag
        # the host doesn't have. Verify presence instead of assuming it.
        pre = preflight_offline_images('o365rc', version, images_dir,
                                       logger=log, run_id=run_id)
        if not pre['success']:
            raise Exception(
                f"DFIR-O365RC image {', '.join(pre['missing'])} is neither "
                f"bundled in the package nor already loaded on this host")

        log(f"Updating DFIR-O365RC version to {version}...", "info")
        update_env_file(backend_env, 'DFIR_O365RC_VERSION', version, logger=log)
        set_module_enabled_in_config('o365rc', logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"DFIR-O365RC offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"DFIR-O365RC offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK DFIR-O365RC to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }
