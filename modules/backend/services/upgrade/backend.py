#!/usr/bin/env python3
"""Backend upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable

from .base import WORKDIR, run_command


def upgrade_backend(logger: Callable = None) -> Dict:
    """Upgrade backend by pulling latest code and rebuilding."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'backend')
    repo_dir = WORKDIR

    log("Starting Backend upgrade...", "info")

    # Git pull latest code
    log("Pulling latest code...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)

    # Stop container
    log("Stopping backend container...", "info")
    run_command("docker compose down", cwd=work_dir, logger=log)

    # Rebuild
    log("Rebuilding backend container...", "info")
    run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Start container
    log("Starting backend container...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Health check
    log("Waiting for backend to be ready...", "info")
    for i in range(20):
        try:
            response = requests.get("http://localhost:5001/api/health", timeout=5)
            if response.status_code == 200:
                log("Backend is ready", "success")
                return {"success": True}
        except:
            pass
        time.sleep(3)

    log("Health check timed out", "warning")
    return {"success": True, "health": "pending"}


def upgrade_backend_offline(package_dir: str, logger: Callable = None) -> Dict:
    """Upgrade backend from offline package source files."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'backend')
    source_dir = os.path.join(package_dir, 'source', 'backend')

    log("Starting Backend offline upgrade...", "info")

    if not os.path.exists(source_dir):
        log("Backend source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Stop container
    log("Stopping backend container...", "info")
    run_command("docker compose down", cwd=work_dir, logger=log)

    # Copy source files
    log("Copying backend source files...", "info")
    run_command(f"cp -a {source_dir}/* {work_dir}/", logger=log)

    # Rebuild
    log("Rebuilding backend container...", "info")
    run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Start container
    log("Starting backend container...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Health check
    log("Waiting for backend to be ready...", "info")
    for i in range(20):
        try:
            response = requests.get("http://localhost:5001/api/health", timeout=5)
            if response.status_code == 200:
                log("Backend is ready", "success")
                return {"success": True}
        except:
            pass
        time.sleep(3)

    log("Health check timed out", "warning")
    return {"success": True, "health": "pending"}
