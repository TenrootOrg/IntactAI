#!/usr/bin/env python3
"""Frontend upgrade functions."""

import os
from typing import Dict, Callable

from .base import WORKDIR, run_command


def upgrade_frontend(logger: Callable = None) -> Dict:
    """Upgrade frontend by copying updated files and restarting nginx."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    repo_dir = WORKDIR

    log("Starting Frontend upgrade...", "info")

    # Git pull (if not already done by backend upgrade)
    log("Pulling latest code...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        run_command("git pull origin development", cwd=repo_dir, logger=log)

    # Files are already updated by git pull
    log("Frontend files updated via git pull", "info")

    # Restart nginx container
    log("Restarting nginx...", "info")
    result = run_command("docker restart mssp_nginx", logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to restart nginx: {result['error']}"}

    log("Frontend upgraded successfully", "success")
    return {"success": True}


def upgrade_frontend_offline(package_dir: str, logger: Callable = None) -> Dict:
    """Upgrade frontend from offline package source files."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')
    source_dir = os.path.join(package_dir, 'source', 'frontend')

    log("Starting Frontend offline upgrade...", "info")

    if not os.path.exists(source_dir):
        log("Frontend source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Copy frontend files
    log("Copying frontend files...", "info")
    run_command(f"cp -a {source_dir}/* {nginx_html}/", logger=log)
    log("  Frontend files updated", "info")

    # Restart nginx container
    log("Restarting nginx...", "info")
    result = run_command("docker restart mssp_nginx", logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to restart nginx: {result['error']}"}

    log("Frontend upgraded successfully", "success")
    return {"success": True}
