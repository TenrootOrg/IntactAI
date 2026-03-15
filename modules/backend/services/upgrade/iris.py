#!/usr/bin/env python3
"""IRIS upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable

from .base import (
    WORKDIR, HOST_PATH,
    run_command, update_env_file, load_docker_image
)


def upgrade_iris(version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS to specified version."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')

    log("Starting IRIS upgrade...", "info")

    # Stop containers
    log("Stopping IRIS containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop IRIS: {result['error']}"}

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    # Pull new images
    log("Pulling new images...", "info")
    run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

    # Start containers
    log("Starting IRIS containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start IRIS: {result['error']}"}

    # Health check
    log("Waiting for IRIS to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("https://localhost:8443/api/ping", timeout=5, verify=False)
            if response.status_code in [200, 401]:
                log("IRIS is ready", "success")
                return {"success": True, "version": version}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_iris_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS from offline package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting IRIS offline upgrade...", "info")

    # Stop containers
    log("Stopping IRIS containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop IRIS: {result['error']}"}

    # Load docker images
    log("Loading docker images from package...", "info")
    for img_name in ['iris-app', 'iris-worker', 'iris-nginx']:
        tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
        if os.path.exists(tar_path):
            load_docker_image(tar_path, logger=log)

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    # Start containers
    log("Starting IRIS containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start IRIS: {result['error']}"}

    # Health check
    log("Waiting for IRIS to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("https://localhost:8443/api/ping", timeout=5, verify=False)
            if response.status_code in [200, 401]:
                log("IRIS is ready", "success")
                return {"success": True, "version": version}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}
