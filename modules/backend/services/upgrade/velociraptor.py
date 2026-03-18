#!/usr/bin/env python3
"""Velociraptor upgrade functions."""

import os
import time
import json
from typing import Dict, Callable, Optional, Tuple

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file,
    backup_env_file, restore_env_file, cleanup_backup
)


def get_velociraptor_download_url(version: str, logger: Callable = None) -> Tuple[Optional[str], Optional[str]]:
    """Build Velociraptor binary download URL from version string.

    No GitHub API calls - constructs URL directly from version.

    Velociraptor URL pattern:
    https://github.com/Velocidex/velociraptor/releases/download/v{major}.{minor}/velociraptor-v{version}-linux-amd64

    Args:
        version: Version string like "0.75.6" or "v0.75.6" (full version required)

    Returns:
        Tuple of (download_url, clean_version) or (None, None) if invalid
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Normalize version - strip 'v' prefix
    clean_version = version.lstrip('v')
    parts = clean_version.split('.')

    # Require full version (major.minor.patch)
    if len(parts) < 3:
        log(f"  Full version required (e.g., 0.75.6), got: {version}", "warning")
        log(f"  Check https://github.com/Velocidex/velociraptor/releases for available versions", "info")
        return None, None

    # Build release tag (major.minor)
    release_tag = f"v{parts[0]}.{parts[1]}"

    # Build download URL
    binary_name = f"velociraptor-v{clean_version}-linux-amd64"
    download_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/{binary_name}"

    log(f"  Version: {clean_version}", "info")
    log(f"  Release tag: {release_tag}", "info")
    log(f"  Binary: {binary_name}", "info")

    return download_url, clean_version


def upgrade_velociraptor(version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'mssp_velociraptor'

    log("Starting Velociraptor upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('VELOCIRAPTOR_VERSION', 'unknown')

    # Export artifacts to disk (before stopping)
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        result = run_command(export_cmd, logger=log, timeout=60)
        if result['success'] and result.get('stdout'):
            exported = 0
            for line in result['stdout'].strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        name = data.get('name', '')
                        raw = data.get('raw', '')
                        if name and raw:
                            filename = name.replace('.', '__').replace('/', '__') + '.yaml'
                            with open(os.path.join(export_dir, filename), 'w') as f:
                                f.write(raw)
                            exported += 1
                    except:
                        pass
            log(f"  Exported {exported} custom artifacts", "info")
    except Exception as e:
        log(f"  Export warning: {str(e)[:50]}", "warning")

    # Create backups
    log(f"Backing up current config (version {current_version})...", "info")
    env_backup = backup_env_file(env_file, logger=log)

    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    velo_bin = os.path.join(velo_data, 'velociraptor')
    if os.path.exists(velo_bin):
        run_command(f"cp {velo_bin} {backup_dir}/velociraptor.backup", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    try:
        # Stop container
        log("Stopping Velociraptor container...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Velociraptor: {result['error']}")

        # Query GitHub to find the correct binary URL
        log(f"Finding Velociraptor binary for version {version}...", "info")
        download_url, actual_version = get_velociraptor_download_url(version, logger=log)

        if not download_url:
            raise Exception(f"Could not find Velociraptor release for version {version}. Check https://github.com/Velocidex/velociraptor/releases for available versions.")

        # Update version in .env with the actual version from GitHub
        log(f"Updating version to {actual_version}...", "info")
        update_env_file(env_file, 'VELOCIRAPTOR_VERSION', actual_version, logger=log)
        version_parts = actual_version.split('.')
        if len(version_parts) >= 2:
            velo_tag = f"{version_parts[0]}.{version_parts[1]}"
            update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

        # Download new binary
        log(f"Downloading Velociraptor {actual_version}...", "info")
        log(f"  URL: {download_url}", "info")

        result = run_command(f"curl -L -o {velo_bin} {download_url}", logger=log, timeout=300)
        if not result['success']:
            raise Exception("Failed to download new binary")

        run_command(f"chmod +x {velo_bin}", logger=log)

        # Rebuild container
        log("Rebuilding container...", "info")
        run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

        # Restore config/artifact backups (we want to keep these)
        log("Restoring config and artifacts...", "info")
        if os.path.exists(f"{backup_dir}/config"):
            os.makedirs(config_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

        if os.path.exists(f"{backup_dir}/artifact_definitions"):
            os.makedirs(artifact_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")

        # Health check
        log("Waiting for Velociraptor container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 2s = 60s max
            log(f"  Checking Velociraptor container... ({i*2}s)", "info")
            result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=None, timeout=10)
            if result['success']:
                pids = result.get('stdout', '').strip().replace('\n', ', ')
                log(f"  Container healthy - velociraptor running (PIDs: {pids})", "success")
                log("Velociraptor health check: PASSED", "success")
                healthy = True
                break
            else:
                log("  Container not ready yet...", "info")
            time.sleep(2)

        if not healthy:
            check_result = run_command("docker ps -a --filter name=mssp_velociraptor --format '{{.Status}}'", logger=None)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Velociraptor failed to start - container status: {container_status}")
            log("Velociraptor health check: TIMEOUT (container may still be starting)", "warning")

        # Success - cleanup backups
        time.sleep(15)  # Wait for full startup
        run_command(f"rm -rf {backup_dir}", logger=log)
        cleanup_backup(env_backup, logger=log)
        log(f"Velociraptor upgrade completed: {current_version} -> {actual_version}", "success")
        return {"success": True, "version": actual_version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Velociraptor upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore .env backup
        restore_env_file(env_file, env_backup, logger=log)

        # Restore binary backup
        if os.path.exists(f"{backup_dir}/velociraptor.backup"):
            run_command(f"cp {backup_dir}/velociraptor.backup {velo_bin}", logger=log)
            run_command(f"chmod +x {velo_bin}", logger=log)

        # Rebuild and restart with old version
        run_command("docker compose down", cwd=work_dir, logger=log)
        run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)
        run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)

        # Cleanup backup dir
        run_command(f"rm -rf {backup_dir}", logger=log)

        log(f"ROLLED BACK Velociraptor to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_velociraptor_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'mssp_velociraptor'
    binaries_dir = os.path.join(package_dir, 'binaries')

    log("Starting Velociraptor offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('VELOCIRAPTOR_VERSION', 'unknown')

    # Export artifacts
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        result = run_command(export_cmd, logger=log, timeout=60)
        if result['success'] and result.get('stdout'):
            exported = 0
            for line in result['stdout'].strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        name = data.get('name', '')
                        raw = data.get('raw', '')
                        if name and raw:
                            filename = name.replace('.', '__').replace('/', '__') + '.yaml'
                            with open(os.path.join(export_dir, filename), 'w') as f:
                                f.write(raw)
                            exported += 1
                    except:
                        pass
            log(f"  Exported {exported} custom artifacts", "info")
    except Exception as e:
        log(f"  Export warning: {str(e)[:50]}", "warning")

    # Create backups
    log(f"Backing up current config (version {current_version})...", "info")
    env_backup = backup_env_file(env_file, logger=log)

    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    velo_bin = os.path.join(velo_data, 'velociraptor')
    if os.path.exists(velo_bin):
        run_command(f"cp {velo_bin} {backup_dir}/velociraptor.backup", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    try:
        # Stop container
        log("Stopping Velociraptor container...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Velociraptor: {result['error']}")

        # Find Velociraptor binary in package (search for matching patterns)
        log("Finding Velociraptor binary in package...", "info")
        clean_ver = version.lstrip('v')
        source_binary = None
        actual_version = clean_ver

        # Try different naming patterns
        patterns = [
            f"velociraptor-v{clean_ver}-linux-amd64",
            f"velociraptor-{clean_ver}-linux-amd64",
        ]

        # Also search for any velociraptor binary matching major.minor version
        if os.path.exists(binaries_dir):
            for fname in os.listdir(binaries_dir):
                if fname.startswith('velociraptor-') and 'linux-amd64' in fname and 'musl' not in fname:
                    # Extract version from filename
                    # velociraptor-v0.75.1-linux-amd64 -> 0.75.1
                    ver_part = fname.replace('velociraptor-v', '').replace('velociraptor-', '').replace('-linux-amd64', '')
                    if ver_part.startswith(clean_ver.rsplit('.', 1)[0]):  # Match major.minor
                        patterns.insert(0, fname)  # Prioritize exact match from package

        for pattern in patterns:
            candidate = os.path.join(binaries_dir, pattern)
            if os.path.exists(candidate):
                source_binary = candidate
                # Extract actual version from filename
                fname = os.path.basename(candidate)
                actual_version = fname.replace('velociraptor-v', '').replace('velociraptor-', '').replace('-linux-amd64', '')
                log(f"  Found binary: {fname}", "info")
                break

        if not source_binary:
            raise Exception(f"Velociraptor binary not found in package for version {version}")

        # Update version in .env with actual version from binary
        log(f"Updating version to {actual_version}...", "info")
        update_env_file(env_file, 'VELOCIRAPTOR_VERSION', actual_version, logger=log)
        version_parts = actual_version.split('.')
        if len(version_parts) >= 2:
            velo_tag = f"{version_parts[0]}.{version_parts[1]}"
            update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

        # Copy binary from package
        log("Copying Velociraptor binary from package...", "info")
        run_command(f"cp {source_binary} {velo_bin}", logger=log)
        run_command(f"chmod +x {velo_bin}", logger=log)
        log("  Binary copied successfully", "info")

        # Rebuild container
        log("Rebuilding container...", "info")
        run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

        # Restore config/artifact backups
        log("Restoring config and artifacts...", "info")
        if os.path.exists(f"{backup_dir}/config"):
            os.makedirs(config_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

        if os.path.exists(f"{backup_dir}/artifact_definitions"):
            os.makedirs(artifact_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")

        # Health check
        log("Waiting for Velociraptor container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 2s = 60s max
            log(f"  Checking Velociraptor container... ({i*2}s)", "info")
            result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=None, timeout=10)
            if result['success']:
                pids = result.get('stdout', '').strip().replace('\n', ', ')
                log(f"  Container healthy - velociraptor running (PIDs: {pids})", "success")
                log("Velociraptor health check: PASSED", "success")
                healthy = True
                break
            else:
                log("  Container not ready yet...", "info")
            time.sleep(2)

        if not healthy:
            check_result = run_command("docker ps -a --filter name=mssp_velociraptor --format '{{.Status}}'", logger=None)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Velociraptor failed to start - container status: {container_status}")
            log("Velociraptor health check: TIMEOUT (container may still be starting)", "warning")

        # Success - cleanup backups
        time.sleep(15)
        run_command(f"rm -rf {backup_dir}", logger=log)
        cleanup_backup(env_backup, logger=log)
        log(f"Velociraptor offline upgrade completed: {current_version} -> {actual_version}", "success")
        return {"success": True, "version": actual_version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Velociraptor offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore .env backup
        restore_env_file(env_file, env_backup, logger=log)

        # Restore binary backup
        if os.path.exists(f"{backup_dir}/velociraptor.backup"):
            run_command(f"cp {backup_dir}/velociraptor.backup {velo_bin}", logger=log)
            run_command(f"chmod +x {velo_bin}", logger=log)

        # Rebuild and restart with old version
        run_command("docker compose down", cwd=work_dir, logger=log)
        run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)
        run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)

        run_command(f"rm -rf {backup_dir}", logger=log)

        log(f"ROLLED BACK Velociraptor to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }
