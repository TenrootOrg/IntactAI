#!/usr/bin/env python3
"""Plaso upgrade functions."""

import os
from typing import Dict, Callable

from .base import (
    WORKDIR, HOST_PATH,
    run_command, update_env_file, load_docker_image
)


def upgrade_plaso(version: str, logger: Callable = None) -> Dict:
    """Upgrade Plaso to specified version (online)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting Plaso upgrade...", "info")

    # Pull new Plaso image
    log(f"Pulling Plaso {version}...", "info")
    result = run_command(f"docker pull log2timeline/plaso:{version}", logger=log, timeout=600)
    if not result['success']:
        return {"success": False, "error": f"Failed to pull Plaso image: {result['error']}"}

    # Update version in backend .env
    log(f"Updating Plaso version to {version}...", "info")
    update_env_file(backend_env, 'PLASO_VERSION', version, logger=log)

    # Restart backend to pick up new Plaso version
    log("Restarting backend...", "info")
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    run_command("docker compose restart", cwd=backend_dir, logger=log)

    log(f"Plaso upgrade completed: {version}", "success")
    return {"success": True, "version": version}


def upgrade_plaso_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade Plaso from offline package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Plaso offline upgrade...", "info")

    # Load Plaso image from package
    plaso_tar = os.path.join(images_dir, f"plaso-{version}.tar")
    if os.path.exists(plaso_tar):
        log(f"Loading Plaso image from package...", "info")
        load_docker_image(plaso_tar, logger=log)
    else:
        log(f"Plaso image not found in package: {plaso_tar}", "warning")

    # Update version in backend .env
    log(f"Updating Plaso version to {version}...", "info")
    update_env_file(backend_env, 'PLASO_VERSION', version, logger=log)

    # Restart backend
    log("Restarting backend...", "info")
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    run_command("docker compose restart", cwd=backend_dir, logger=log)

    log(f"Plaso offline upgrade completed: {version}", "success")
    return {"success": True, "version": version}
