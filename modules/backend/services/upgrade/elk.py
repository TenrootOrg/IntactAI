#!/usr/bin/env python3
"""ELK Stack upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, compare_versions, load_docker_image
)


def upgrade_elk(version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK stack to specified version.

    NOTE: Elasticsearch does NOT support downgrades. Only upgrades to newer versions are allowed.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')

    log("Starting ELK upgrade...", "info")

    # Check current version and prevent downgrades
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('ELASTIC_VERSION', '0.0.0')

    if compare_versions(version, current_version) < 0:
        error_msg = f"ELK downgrade not supported: {current_version} -> {version}. Elasticsearch only supports forward upgrades."
        log(error_msg, "error")
        log("To change to an older version, you must first remove ELK data volumes (docker compose down -v)", "warning")
        return {"success": False, "error": error_msg}

    if compare_versions(version, current_version) == 0:
        log(f"ELK is already at version {version}", "info")
        return {"success": True, "version": version, "message": "Already at target version"}

    # Stop containers
    log("Stopping ELK containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop ELK: {result['error']}"}

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'ELASTIC_VERSION', version, logger=log)
    update_env_file(env_file, 'KIBANA_VERSION', version, logger=log)

    # Pull new images
    log("Pulling new images...", "info")
    result = run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)
    if not result['success']:
        log(f"Pull warning: {result.get('error', '')[:100]}", "warning")

    # Build
    log("Building containers...", "info")
    run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Start containers
    log("Starting ELK containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start ELK: {result['error']}"}

    # Health check
    log("Waiting for Elasticsearch to be ready...", "info")
    for i in range(40):
        try:
            response = requests.get("http://localhost:9200/_cluster/health", timeout=5)
            if response.status_code == 200:
                health = response.json()
                status = health.get('status', 'unknown')
                log(f"Elasticsearch health: {status}", "success")
                return {"success": True, "version": version, "health": status}
        except:
            pass
        time.sleep(5)

    log("Health check timed out, but containers may still be starting", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_elk_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK from offline package (pre-saved docker images)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting ELK offline upgrade...", "info")

    # Stop containers
    log("Stopping ELK containers...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop ELK: {result['error']}"}

    # Load docker images
    log("Loading docker images from package...", "info")
    for img_name in ['elasticsearch', 'kibana', 'logstash']:
        tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
        if os.path.exists(tar_path):
            result = load_docker_image(tar_path, logger=log)
            if not result['success']:
                log(f"  Warning: Failed to load {img_name}", "warning")
        else:
            log(f"  Image not found: {tar_path}", "warning")

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'ELASTIC_VERSION', version, logger=log)
    update_env_file(env_file, 'KIBANA_VERSION', version, logger=log)

    # Start containers
    log("Starting ELK containers...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start ELK: {result['error']}"}

    # Health check
    log("Waiting for Elasticsearch to be ready...", "info")
    for i in range(40):
        try:
            response = requests.get("http://localhost:9200/_cluster/health", timeout=5)
            if response.status_code == 200:
                health = response.json()
                status = health.get('status', 'unknown')
                log(f"Elasticsearch health: {status}", "success")
                return {"success": True, "version": version, "health": status}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}
