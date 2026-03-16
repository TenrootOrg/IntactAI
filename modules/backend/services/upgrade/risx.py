#!/usr/bin/env python3
"""RISX Platform upgrade functions - combines backend and frontend."""

import os
from typing import Dict, Callable

from .base import WORKDIR, run_command


def upgrade_risx(version: str = None, logger: Callable = None) -> Dict:
    """Upgrade RISX Platform (backend + frontend) by pulling latest code.

    NOTE: This runs INSIDE the backend container, so we cannot restart the backend
    during the upgrade - it would kill this process. The upgrade workflow will
    restart nginx at the end, and the backend should be manually restarted after
    the workflow completes if code changes require it.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    repo_dir = WORKDIR

    log("Starting RISX Platform upgrade...", "info")

    # Git pull latest code
    log("Pulling latest code from repository...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)
        if not result['success']:
            log("Warning: Could not pull latest code", "warning")

    # Frontend files are updated by git pull - just restart nginx
    log("Restarting nginx for frontend updates...", "info")
    run_command("docker restart mssp_nginx", logger=log)

    log("RISX Platform code updated", "success")
    log("NOTE: Restart the backend container manually if backend code changed", "warning")
    log("  Run: docker compose restart (in modules/backend/)", "info")

    return {"success": True, "message": "Code updated - restart backend if needed"}


def upgrade_risx_offline(package_dir: str, version: str = None, logger: Callable = None) -> Dict:
    """Upgrade RISX Platform from offline package source files.

    NOTE: This runs INSIDE the backend container, so we cannot restart the backend
    during the upgrade. We copy the source files, but the backend restart must be
    done manually after the workflow completes.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')
    backend_source = os.path.join(package_dir, 'source', 'backend')
    frontend_source = os.path.join(package_dir, 'source', 'frontend')

    log("Starting RISX Platform offline upgrade...", "info")

    has_backend = os.path.exists(backend_source)
    has_frontend = os.path.exists(frontend_source)

    if not has_backend and not has_frontend:
        log("RISX source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Copy backend source files (don't restart - we're running inside it)
    if has_backend:
        log("Copying backend source files...", "info")
        run_command(f"cp -a {backend_source}/* {backend_dir}/", logger=log)
        log("Backend files updated - restart required after upgrade completes", "warning")

    # Copy frontend files
    if has_frontend:
        log("Copying frontend files...", "info")
        run_command(f"cp -a {frontend_source}/* {nginx_html}/", logger=log)

    # Restart nginx for frontend changes
    log("Restarting nginx...", "info")
    run_command("docker restart mssp_nginx", logger=log)

    log("RISX Platform files updated", "success")
    if has_backend:
        log("NOTE: Restart the backend container after upgrade completes", "warning")
        log("  Run: docker compose restart (in modules/backend/)", "info")

    return {"success": True, "message": "Files updated - restart backend if needed"}
