#!/usr/bin/env python3
"""Prowler (AWS posture scanner) upgrade functions.

Prowler runs on demand against AWS accounts — there's no long-running
Prowler container, so "upgrade" means pulling a new image tag and pinning
it in the backend .env (PROWLER_VERSION). The scan runner
(services/aws/prowler_runner.py) reads that version fresh, so the new
image is used on the next scan without a backend restart. Mirrors the
Plaso upgrader.

Internal function names (`upgrade_aws`, `upgrade_aws_offline`) kept for
backwards compatibility with the dispatcher tables; the public module key
exposed via the API + run logs is now 'prowler'.
"""

import os
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup,
    set_module_enabled_in_config,
)


def upgrade_aws(version: str, logger: Callable = None) -> Dict:
    """Upgrade the Prowler image to `version` with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting Prowler upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('PROWLER_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        log(f"Pulling Prowler {version}...", "info")
        result = run_command(f"docker pull toniblyx/prowler:{version}", logger=log, timeout=900)
        if not result['success']:
            raise Exception(f"Failed to pull Prowler image: {result['error']}")

        log(f"Updating Prowler version to {version}...", "info")
        update_env_file(backend_env, 'PROWLER_VERSION', version, logger=log)

        # Mark prowler as enabled in config.yaml so the sidebar, dashboard
        # cards and runtime is_module_enabled() gate all see this install.
        # No-op when already enabled.
        set_module_enabled_in_config('prowler', logger=log)

        # No backend restart needed — Prowler runs as a separate container
        # per scan and prowler_runner reads PROWLER_VERSION fresh from .env.

        cleanup_backup(backup_file, logger=log)
        log(f"Prowler upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"Prowler upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK Prowler to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }


def upgrade_aws_offline(package_dir: str, version: str, logger: Callable = None,
                          run_id: Optional[str] = None) -> Dict:
    """Upgrade Prowler from an offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Prowler offline upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('PROWLER_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        prowler_tar = os.path.join(images_dir, f"prowler-{version}.tar")
        if os.path.exists(prowler_tar):
            log("Loading Prowler image from package...", "info")
            result = load_docker_image(prowler_tar, logger=log, run_id=run_id)
            if not result['success']:
                raise Exception(f"Failed to load Prowler image: {result.get('error', 'unknown')}")
        else:
            log(f"Prowler image not found in package: {prowler_tar}", "warning")

        log(f"Updating Prowler version to {version}...", "info")
        update_env_file(backend_env, 'PROWLER_VERSION', version, logger=log)
        set_module_enabled_in_config('prowler', logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"Prowler offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"Prowler offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK Prowler to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }
