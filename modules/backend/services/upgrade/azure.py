#!/usr/bin/env python3
"""Azure (DFIR-O365RC) upgrade functions.

Azure Unified Audit Log collection runs the DFIR-O365RC image
(anssi/dfir-o365rc) on demand — no long-running Azure container, so
"upgrade" means pulling the image and pinning it in the backend .env
(DFIR_O365RC_VERSION). Upstream only publishes ':latest' (no version
tags), so the version is normally 'latest' and an upgrade re-pulls the
newest latest. The scan runner (services/azure/dfir_o365rc.py) reads the
version fresh, so the new image applies on the next scan without a
backend restart. Mirrors the Plaso upgrader.
"""

import os
from typing import Dict, Callable

from .base import (
    WORKDIR,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup
)


def upgrade_azure(version: str, logger: Callable = None) -> Dict:
    """Pull the DFIR-O365RC image at `version` (usually 'latest') and pin it."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting Azure (DFIR-O365RC) upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('DFIR_O365RC_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        log(f"Pulling DFIR-O365RC {version}...", "info")
        result = run_command(f"docker pull anssi/dfir-o365rc:{version}", logger=log, timeout=900)
        if not result['success']:
            raise Exception(f"Failed to pull DFIR-O365RC image: {result['error']}")

        log(f"Updating DFIR-O365RC version to {version}...", "info")
        update_env_file(backend_env, 'DFIR_O365RC_VERSION', version, logger=log)

        # No backend restart needed — DFIR-O365RC runs as a separate container
        # per scan and dfir_o365rc reads DFIR_O365RC_VERSION fresh from .env.

        cleanup_backup(backup_file, logger=log)
        log(f"Azure (DFIR-O365RC) upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"Azure upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK DFIR-O365RC to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }


def upgrade_azure_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade DFIR-O365RC from an offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Azure (DFIR-O365RC) offline upgrade...", "info")

    current_vars = read_env_file(backend_env)
    current_version = current_vars.get('DFIR_O365RC_VERSION', 'unknown')

    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        o365rc_tar = os.path.join(images_dir, f"dfir-o365rc-{version}.tar")
        if os.path.exists(o365rc_tar):
            log("Loading DFIR-O365RC image from package...", "info")
            result = load_docker_image(o365rc_tar, logger=log)
            if not result['success']:
                raise Exception(f"Failed to load DFIR-O365RC image: {result.get('error', 'unknown')}")
        else:
            log(f"DFIR-O365RC image not found in package: {o365rc_tar}", "warning")

        log(f"Updating DFIR-O365RC version to {version}...", "info")
        update_env_file(backend_env, 'DFIR_O365RC_VERSION', version, logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"Azure (DFIR-O365RC) offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"Azure offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK DFIR-O365RC to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
        }
