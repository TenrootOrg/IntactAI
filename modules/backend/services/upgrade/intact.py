#!/usr/bin/env python3
"""Intact.AI Platform upgrade functions - combines backend and frontend."""

import os
from typing import Dict, Callable, Optional

from .base import WORKDIR, run_command


def upgrade_intact(version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Intact.AI Platform (backend + frontend) by pulling latest code.

    NOTE: This runs INSIDE the backend container. The upgrade orchestrator
    handles nginx restart and backend restart scheduling. This function
    just updates the code files.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    repo_dir = WORKDIR

    log("Starting Intact.AI Platform upgrade...", "info")

    # Git pull latest code
    log("Pulling latest code from repository...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)
        if not result['success']:
            log("Warning: Could not pull latest code", "warning")

    # Fix file permissions (files pulled by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform code updated", "success")

    return {"success": True, "message": "Code updated"}


def upgrade_intact_offline(package_dir: str, version: str = None, logger: Callable = None,
                            run_id: Optional[str] = None) -> Dict:
    """Upgrade Intact.AI Platform from offline package source files.

    NOTE: This runs INSIDE the backend container. The upgrade orchestrator
    handles nginx restart and backend restart scheduling. This function
    just updates the code files.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')
    backend_source = os.path.join(package_dir, 'source', 'backend')
    frontend_source = os.path.join(package_dir, 'source', 'frontend')

    log("Starting Intact.AI Platform offline upgrade...", "info")

    # Check if directories exist AND have files (empty dirs are created even when Intact.AI not selected)
    has_backend = os.path.exists(backend_source) and os.listdir(backend_source)
    has_frontend = os.path.exists(frontend_source) and os.listdir(frontend_source)

    if not has_backend and not has_frontend:
        log("Intact.AI source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Copy backend source files
    if has_backend:
        log("Copying backend source files...", "info")
        run_command(f"cp -a {backend_source}/* {backend_dir}/", logger=log, run_id=run_id)

    # Copy frontend files
    if has_frontend:
        log("Copying frontend files...", "info")
        run_command(f"cp -a {frontend_source}/* {nginx_html}/", logger=log, run_id=run_id)

    # Fix file permissions (files copied by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform files updated", "success")

    return {"success": True, "message": "Files updated"}
