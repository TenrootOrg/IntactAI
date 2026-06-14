#!/usr/bin/env python3
"""Plaso upgrade functions."""

import os
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup,
    remove_old_module_image,
)


def upgrade_plaso(version: str, logger: Callable = None) -> Dict:
    """Upgrade Plaso to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')

    log("Starting Plaso upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('PLASO_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        # Pull new Plaso image
        log(f"Pulling Plaso {version}...", "info")
        result = run_command(f"docker pull log2timeline/plaso:{version}", logger=log, timeout=1800)
        if not result['success']:
            raise Exception(f"Failed to pull Plaso image: {result['error']}")

        # Update version in backend .env
        log(f"Updating Plaso version to {version}...", "info")
        update_env_file(backend_env, 'PLASO_VERSION', version, logger=log)

        # NOTE: No backend restart needed - Plaso runs as a separate Docker container
        # The new image will be used when a Plaso job is triggered

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"Plaso upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('plaso', current_version, version, logger=log)
        return {"success": True, "version": version}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Plaso upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK Plaso to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_plaso_offline(package_dir: str, version: str, logger: Callable = None,
                            run_id: Optional[str] = None) -> Dict:
    """Upgrade Plaso from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Plaso offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('PLASO_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        # Load Plaso image from package
        plaso_tar = os.path.join(images_dir, f"plaso-{version}.tar")
        if os.path.exists(plaso_tar):
            log(f"Loading Plaso image from package...", "info")
            result = load_docker_image(plaso_tar, logger=log, run_id=run_id)
            if not result['success']:
                raise Exception(f"Failed to load Plaso image: {result.get('error', 'unknown')}")
        else:
            log(f"Plaso image not found in package: {plaso_tar}", "warning")

        # Update version in backend .env
        log(f"Updating Plaso version to {version}...", "info")
        update_env_file(backend_env, 'PLASO_VERSION', version, logger=log)

        # NOTE: No backend restart needed - Plaso runs as a separate Docker container
        # The new image will be used when a Plaso job is triggered

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"Plaso offline upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('plaso', current_version, version, logger=log)
        return {"success": True, "version": version}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Plaso offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK Plaso to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }
