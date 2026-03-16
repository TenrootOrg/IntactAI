#!/usr/bin/env python3
"""RISX Platform upgrade functions - combines backend and frontend."""

import os
import time
import requests
from typing import Dict, Callable

from .base import WORKDIR, run_command


def upgrade_risx(version: str = None, logger: Callable = None) -> Dict:
    """Upgrade RISX Platform (backend + frontend) by pulling latest code."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    repo_dir = WORKDIR

    log("Starting RISX Platform upgrade...", "info")

    # Git pull latest code
    log("Pulling latest code from repository...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)

    # Stop backend container
    log("Stopping backend container...", "info")
    run_command("docker compose down", cwd=backend_dir, logger=log)

    # Rebuild backend
    log("Rebuilding backend container...", "info")
    run_command("docker compose build --no-cache", cwd=backend_dir, timeout=600, logger=log)

    # Start backend container
    log("Starting backend container...", "info")
    result = run_command("docker compose up -d", cwd=backend_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Restart nginx for frontend changes
    log("Restarting nginx for frontend updates...", "info")
    run_command("docker restart mssp_nginx", logger=log)

    # Health check
    log("Waiting for platform to be ready...", "info")
    for i in range(20):
        try:
            response = requests.get("http://localhost:5001/api/health", timeout=5)
            if response.status_code == 200:
                log("RISX Platform is ready", "success")
                return {"success": True}
        except:
            pass
        time.sleep(3)

    log("Health check timed out", "warning")
    return {"success": True, "health": "pending"}


def upgrade_risx_offline(package_dir: str, version: str = None, logger: Callable = None) -> Dict:
    """Upgrade RISX Platform from offline package source files."""
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

    # Stop backend container
    if has_backend:
        log("Stopping backend container...", "info")
        run_command("docker compose down", cwd=backend_dir, logger=log)

        # Copy backend source files
        log("Copying backend source files...", "info")
        run_command(f"cp -a {backend_source}/* {backend_dir}/", logger=log)

        # Rebuild backend
        log("Rebuilding backend container...", "info")
        run_command("docker compose build --no-cache", cwd=backend_dir, timeout=600, logger=log)

        # Start backend container
        log("Starting backend container...", "info")
        result = run_command("docker compose up -d", cwd=backend_dir, logger=log)
        if not result['success']:
            return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Copy frontend files
    if has_frontend:
        log("Copying frontend files...", "info")
        run_command(f"cp -a {frontend_source}/* {nginx_html}/", logger=log)

    # Restart nginx
    log("Restarting nginx...", "info")
    run_command("docker restart mssp_nginx", logger=log)

    # Health check
    log("Waiting for platform to be ready...", "info")
    for i in range(20):
        try:
            response = requests.get("http://localhost:5001/api/health", timeout=5)
            if response.status_code == 200:
                log("RISX Platform is ready", "success")
                return {"success": True}
        except:
            pass
        time.sleep(3)

    log("Health check timed out", "warning")
    return {"success": True, "health": "pending"}
