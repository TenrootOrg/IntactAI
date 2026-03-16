#!/usr/bin/env python3
"""Timesketch upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable

from .base import (
    WORKDIR, HOST_PATH,
    run_command, update_env_file, load_docker_image
)


def _clear_timesketch_pip_cache(logger: Callable = None):
    """Clear stale pip packages from Timesketch volume to prevent version conflicts.

    LLM packages (google-generativeai, anthropic, etc.) installed by Timesketch
    persist in the volume and can conflict when Timesketch is upgraded.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # List of LLM-related packages that can cause conflicts
    conflicting_packages = [
        'google-generativeai',
        'google-ai-generativelanguage',
        'google-api-core',
        'google-api-python-client',
        'googleapis-common-protos',
        'grpcio',
        'grpcio-status',
        'proto-plus',
        'protobuf',
    ]

    # Run pip uninstall in a temporary container with the volume mounted
    for package in conflicting_packages:
        result = run_command(
            f"docker run --rm -v mssp_timesketch_venv:/opt/venv "
            f"us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:latest "
            f"pip uninstall -y {package} 2>/dev/null || true",
            logger=lambda msg, level="info": None  # Silent
        )

    log("Cleared potentially conflicting pip packages", "info")


def upgrade_timesketch(version: str, logger: Callable = None, plaso_version: str = None) -> Dict:
    """Upgrade Timesketch to specified version."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')

    log("Starting Timesketch upgrade...", "info")

    # Stop containers
    log("Stopping Timesketch containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Timesketch: {result['error']}"}

    # Clear stale pip packages from persistent volume to prevent version conflicts
    # LLM packages (google-generativeai, etc.) can conflict between Timesketch versions
    log("Clearing stale pip packages from volume...", "info")
    _clear_timesketch_pip_cache(log)

    # Update version in .env
    log(f"Updating Timesketch version to {version}...", "info")
    update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

    # Pull new images
    log("Pulling new Timesketch images...", "info")
    run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

    # Pull and update Plaso image if specified
    if plaso_version:
        log(f"Pulling Plaso {plaso_version}...", "info")
        run_command(f"docker pull log2timeline/plaso:{plaso_version}", logger=log, timeout=600)

        # Update Plaso version in backend .env so the backend uses the new version
        backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
        log(f"Updating Plaso version to {plaso_version}...", "info")
        update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

        # Restart backend to pick up new Plaso version
        log("Restarting backend to apply Plaso version...", "info")
        run_command("docker compose restart", cwd=os.path.join(WORKDIR, 'modules', 'backend'), logger=log)

    # Start containers
    log("Starting Timesketch containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Timesketch: {result['error']}"}

    # Health check
    log("Waiting for Timesketch to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("http://localhost:5666/login", timeout=5)
            if response.status_code == 200:
                log("Timesketch is ready", "success")
                result = {"success": True, "version": version}
                if plaso_version:
                    result["plaso_version"] = plaso_version
                return result
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    result = {"success": True, "version": version, "health": "pending"}
    if plaso_version:
        result["plaso_version"] = plaso_version
    return result


def upgrade_timesketch_offline(package_dir: str, version: str, plaso_version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Timesketch from offline package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Timesketch offline upgrade...", "info")

    # Stop containers
    log("Stopping Timesketch containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Timesketch: {result['error']}"}

    # Clear stale pip packages from persistent volume to prevent version conflicts
    log("Clearing stale pip packages from volume...", "info")
    _clear_timesketch_pip_cache(log)

    # Load docker images
    log("Loading docker images from package...", "info")
    ts_tar = os.path.join(images_dir, f"timesketch-{version}.tar")
    if os.path.exists(ts_tar):
        load_docker_image(ts_tar, logger=log)

    if plaso_version:
        plaso_tar = os.path.join(images_dir, f"plaso-{plaso_version}.tar")
        if os.path.exists(plaso_tar):
            load_docker_image(plaso_tar, logger=log)

        # Update Plaso version in backend .env so the backend uses the new version
        backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
        log(f"Updating Plaso version to {plaso_version}...", "info")
        update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

    # Update version in .env
    log(f"Updating Timesketch version to {version}...", "info")
    update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

    # Start containers
    log("Starting Timesketch containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Timesketch: {result['error']}"}

    # Restart backend if Plaso was updated
    if plaso_version:
        log("Restarting backend to apply Plaso version...", "info")
        run_command("docker compose restart", cwd=os.path.join(WORKDIR, 'modules', 'backend'), logger=log)

    # Health check
    log("Waiting for Timesketch to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("http://localhost:5666/login", timeout=5)
            if response.status_code == 200:
                log("Timesketch is ready", "success")
                result = {"success": True, "version": version}
                if plaso_version:
                    result["plaso_version"] = plaso_version
                return result
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    result = {"success": True, "version": version, "health": "pending"}
    if plaso_version:
        result["plaso_version"] = plaso_version
    return result
