#!/usr/bin/env python3
"""ELK Stack upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, compare_versions, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup,
    remove_old_module_image,
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
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
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

        # Re-ensure the Kibana 'artifact_*' data view — it can be lost when
        # Kibana migrates/recreates saved objects across an upgrade. Idempotent;
        # same helper install.sh's post-install maintenance uses. Best-effort.
        log("Re-ensuring Kibana data view (post-upgrade init)...", "info")
        try:
            from services.kibana_init import ensure_kibana_data_view
            ensure_kibana_data_view(log, wait=True)
        except Exception as _e:
            log(f"  Kibana data view re-init skipped: {str(_e)[:80]}", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"ELK upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('elk', current_version, version, logger=log)
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"ELK upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore the backup .env file
        if restore_env_file(env_file, backup_file, logger=log):
            # Stop failed containers and restart with old version
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_elk_offline(package_dir: str, version: str, logger: Callable = None,
                         run_id: Optional[str] = None) -> Dict:
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
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop ELK: {result['error']}")

        # Load docker images
        log("Loading docker images from package...", "info")
        for img_name in ['elasticsearch', 'kibana', 'logstash']:
            tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
            if os.path.exists(tar_path):
                result = load_docker_image(tar_path, logger=log, run_id=run_id)
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
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
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

        # Re-ensure the Kibana 'artifact_*' data view (see online path).
        log("Re-ensuring Kibana data view (post-upgrade init)...", "info")
        try:
            from services.kibana_init import ensure_kibana_data_view
            ensure_kibana_data_view(log, wait=True)
        except Exception as _e:
            log(f"  Kibana data view re-init skipped: {str(_e)[:80]}", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"ELK offline upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('elk', current_version, version, logger=log)
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"ELK offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore the backup .env file
        if restore_env_file(env_file, backup_file, logger=log):
            # Stop failed containers and restart with old version
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def install_elk_offline(package_dir: str, version: str, logger=None, run_id=None) -> Dict:
    """Fresh-install ELK from an offline package — picked by the apply
    orchestrator when intact_elasticsearch is not present on the host.

    Reuses the existing tracked `.env` (which ships with the platform's
    default ELASTIC_PASSWORD / KIBANA_PASSWORD) and bumps the version
    pins. Then loads bundled images if present and compose-ups the stack.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')
    version = (version or '').lstrip('v')
    log(f"Installing ELK (first-time) -> {version or 'tracked default'}...", "info")
    if os.path.exists(env_file) and version:
        update_env_file(env_file, 'ELASTIC_VERSION', version, logger=log)
        update_env_file(env_file, 'KIBANA_VERSION', version, logger=log)
    compose_result = install_module_compose_up(
        'elk', package_dir, version,
        image_tar_prefixes=['elasticsearch', 'kibana'],
        logger=log, run_id=run_id,
    )
    if not compose_result.get('success'):
        return compose_result

    # Post-install bootstrap. Without this, the install reports success
    # but Kibana has no data view for the `artifact_*` indices the
    # IntactAI backend writes to — Velociraptor artifacts uploaded by
    # the platform exist in Elasticsearch but Kibana can't surface
    # them in Discover / Dashboards until the data view exists. The
    # upgrade path already does this (line ~108); the install path
    # was missing the equivalent.
    log("ELK containers up. Waiting for Elasticsearch + Kibana data view...", "info")

    # Stage 1: wait for Elasticsearch to be ready. Probe its cluster
    # health endpoint via the backend container's shell (the backend
    # is on the same docker network and can reach intact_elasticsearch
    # directly by name). 300s budget — fresh-install ES boot is slower
    # than upgrade because the security indices haven't been
    # bootstrapped yet. Bumped from 180s on 2026-06-11 to match the
    # other module timeouts and survive slow-disk machines that hit
    # the same shape of failure Timesketch did (install reports
    # "completed" but downstream bootstrap times out).
    import subprocess as _sub
    es_ready = False
    waited = 0
    _ES_READY_WAIT_SECS = 300
    while waited < _ES_READY_WAIT_SECS:
        try:
            probe = _sub.run(
                ["docker", "exec", "intact_elasticsearch",
                 "curl", "-sf", "--max-time", "5",
                 "http://localhost:9200/_cluster/health"],
                capture_output=True, text=True, timeout=10,
            )
            if probe.returncode == 0:
                es_ready = True
                log(f"  Elasticsearch ready ({waited}s)", "success")
                break
        except _sub.TimeoutExpired:
            pass
        except Exception:
            pass
        time.sleep(5)
        waited += 5

    if not es_ready:
        log(
            f"Elasticsearch did not become ready after {_ES_READY_WAIT_SECS}s. "
            "Containers ARE running but the Kibana data view bootstrap has been SKIPPED — "
            "operator can re-trigger it later via Maintenance, or run "
            "manually: `from services.kibana_init import "
            "ensure_kibana_data_view; ensure_kibana_data_view(print)`. "
            "Continuing.",
            "warning",
        )
        return compose_result

    # Stage 2: ensure the Kibana data view for the artifact_* indices.
    # ensure_kibana_data_view() internally waits for Kibana to be
    # ready and is idempotent.
    log("Ensuring Kibana data view for artifact_* indices...", "info")
    try:
        from services.kibana_init import ensure_kibana_data_view
        ensure_kibana_data_view(log, wait=True)
        log("  Kibana data view ready — backend can render dashboards", "success")
    except Exception as e:
        log(
            f"  Kibana data view init failed: {str(e)[:160]}. "
            "Containers up; re-trigger via Settings → Maintenance "
            "→ 'Refresh Kibana Data View' or run ensure_kibana_data_view "
            "manually. Continuing.",
            "warning",
        )

    return compose_result
