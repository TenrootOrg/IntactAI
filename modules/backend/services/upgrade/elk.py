#!/usr/bin/env python3
"""ELK Stack upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, compare_versions, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup
)


def upgrade_elk(version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK stack to specified version with automatic rollback on failure.

    NOTE: Elasticsearch does NOT support downgrades. Only upgrades to newer versions are allowed.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')

    # Strip 'v' prefix - Docker images use '9.3.0' not 'v9.3.0'
    version = version.lstrip('v')

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

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping ELK containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop ELK: {result['error']}")

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
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start ELK: {result['error']}")

        # Health check - wait for Elasticsearch to respond
        # Use docker exec since we're inside a container and can't reach localhost:9200
        log("Waiting for Elasticsearch container to be up...", "info")
        healthy = False
        for i in range(24):  # 24 * 5s = 120s max
            log(f"  Checking Elasticsearch container... ({i*5}s)", "info")
            check_result = run_command(
                "docker exec intact_elasticsearch curl -sf --max-time 5 http://localhost:9200/_cluster/health",
                logger=None
            )
            if check_result['success']:
                health_info = check_result.get('stdout', '').strip()[:100]
                log(f"  Container healthy - API responding: {health_info}", "success")
                healthy = True
                break
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("Elasticsearch health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_elasticsearch --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Elasticsearch failed to start - container status: {container_status}")
            log("Elasticsearch health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"ELK upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"ELK upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore the backup .env file
        if restore_env_file(env_file, backup_file, logger=log):
            # Stop failed containers and restart with old version
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_elk_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK from offline package (pre-saved docker images) with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting ELK offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('ELASTIC_VERSION', '0.0.0')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping ELK containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop ELK: {result['error']}")

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
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start ELK: {result['error']}")

        # Health check - wait for Elasticsearch to respond
        # Use docker exec since we're inside a container and can't reach localhost:9200
        log("Waiting for Elasticsearch container to be up...", "info")
        healthy = False
        for i in range(24):  # 24 * 5s = 120s max
            log(f"  Checking Elasticsearch container... ({i*5}s)", "info")
            check_result = run_command(
                "docker exec intact_elasticsearch curl -sf --max-time 5 http://localhost:9200/_cluster/health",
                logger=None
            )
            if check_result['success']:
                health_info = check_result.get('stdout', '').strip()[:100]
                log(f"  Container healthy - API responding: {health_info}", "success")
                healthy = True
                break
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("Elasticsearch health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_elasticsearch --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Elasticsearch failed to start - container status: {container_status}")
            log("Elasticsearch health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"ELK offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"ELK offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore the backup .env file
        if restore_env_file(env_file, backup_file, logger=log):
            # Stop failed containers and restart with old version
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }
