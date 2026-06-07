#!/usr/bin/env python3
"""IRIS upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup
)


def upgrade_iris(version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')

    log("Starting IRIS upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('IRIS_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping IRIS containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop IRIS: {result['error']}")

        # Update version in .env
        log(f"Updating version to {version}...", "info")
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

        # Pull new images
        log("Pulling new images...", "info")
        run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

        # Start containers
        log("Starting IRIS containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start IRIS: {result['error']}")

        # Health check - wait for IRIS to respond
        # Use docker exec since we're inside a container and can't reach localhost:8443
        log("Waiting for IRIS container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking IRIS container... ({i*5}s)", "info")
            # Check IRIS nginx container - it proxies to the app
            check_result = run_command(
                "docker exec intact_iris_nginx curl -sk --max-time 5 https://localhost:8443/ -o /dev/null -w '%{http_code}'",
                logger=None
            )
            if check_result['success']:
                http_code = check_result.get('stdout', '').strip()
                # Accept 200, redirects, or 401 (auth required = service is up)
                if http_code in ['200', '301', '302', '303', '307', '308', '401']:
                    log(f"  Container healthy - HTTP {http_code}", "success")
                    healthy = True
                    break
                else:
                    log(f"  Container not ready yet (HTTP {http_code})...", "info")
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("IRIS health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_iris --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"IRIS failed to start - container status: {container_status}")
            log("IRIS health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"IRIS upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"IRIS upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK IRIS to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_iris_offline(package_dir: str, version: str, logger: Callable = None,
                          run_id: Optional[str] = None) -> Dict:
    """Upgrade IRIS from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting IRIS offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('IRIS_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping IRIS containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop IRIS: {result['error']}")

        # Load docker images (including DB for air-gap support - data is in volumes)
        log("Loading docker images from package...", "info")
        for img_name in ['iris-app', 'iris-nginx', 'iris-db']:
            tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
            if os.path.exists(tar_path):
                load_docker_image(tar_path, logger=log, run_id=run_id)
            else:
                log(f"  Image not found: {tar_path}", "warning")

        # Update version in .env
        log(f"Updating version to {version}...", "info")
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

        # Start containers
        log("Starting IRIS containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start IRIS: {result['error']}")

        # Health check - wait for IRIS to respond
        # Use docker exec since we're inside a container and can't reach localhost:8443
        log("Waiting for IRIS container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking IRIS container... ({i*5}s)", "info")
            # Check IRIS nginx container - it proxies to the app
            check_result = run_command(
                "docker exec intact_iris_nginx curl -sk --max-time 5 https://localhost:8443/ -o /dev/null -w '%{http_code}'",
                logger=None
            )
            if check_result['success']:
                http_code = check_result.get('stdout', '').strip()
                # Accept 200, redirects, or 401 (auth required = service is up)
                if http_code in ['200', '301', '302', '303', '307', '308', '401']:
                    log(f"  Container healthy - HTTP {http_code}", "success")
                    healthy = True
                    break
                else:
                    log(f"  Container not ready yet (HTTP {http_code})...", "info")
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("IRIS health check: PASSED", "success")
        else:
            check_result = run_command("docker ps -a --filter name=intact_iris --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"IRIS failed to start - container status: {container_status}")
            log("IRIS health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"IRIS offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"IRIS offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK IRIS to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def install_iris_offline(package_dir: str, version: str, logger=None, run_id=None) -> Dict:
    """Fresh-install IRIS — picked when intact_iris_app absent.

    Generates the secret files lib/modules.sh:generate_iris_secrets
    would otherwise create (IRIS_ADM_PASSWORD from config.yaml,
    IRIS_SECRET_KEY + IRIS_SECURITY_PASSWORD_SALT as `openssl rand -hex 32`
    equivalents, POSTGRES_* passwords).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    import secrets as _secrets

    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    secrets_dir = os.path.join(work_dir, 'secrets')
    os.makedirs(secrets_dir, exist_ok=True)

    log(f"Installing IRIS (first-time) -> {version or 'tracked default'}...", "info")
    if os.path.exists(env_file) and version:
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    iris_admin_pw = '123123'
    try:
        from config import load_main_config
        cfg = load_main_config() or {}
        v = (cfg.get('modules', {}) or {}).get('iris', {}).get('password')
        if v:
            iris_admin_pw = str(v)
    except Exception:
        pass

    secret_specs = [
        ('IRIS_ADM_PASSWORD', iris_admin_pw),
        ('IRIS_SECRET_KEY', _secrets.token_hex(32)),
        ('IRIS_SECURITY_PASSWORD_SALT', _secrets.token_hex(32)),
        ('POSTGRES_ADMIN_PASSWORD', _secrets.token_hex(32)),
        ('POSTGRES_PASSWORD', _secrets.token_hex(32)),
    ]
    for name, val in secret_specs:
        path = os.path.join(secrets_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            log(f"  {name}: already present, keeping existing", "info")
            continue
        with open(path, 'w') as f:
            f.write(val or '')
        os.chmod(path, 0o600)
        log(f"  Generated {name}", "info")

    return install_module_compose_up(
        'iris', package_dir, version,
        image_tar_prefixes=['iris', 'rabbitmq', 'postgres'],
        logger=log, run_id=run_id,
    )
