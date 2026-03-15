#!/usr/bin/env python3
"""Velociraptor upgrade functions."""

import os
import time
import json
from typing import Dict, Callable

from .base import WORKDIR, HOST_PATH, run_command, update_env_file


def upgrade_velociraptor(version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor to specified version (handles artifacts and binary download)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'mssp_velociraptor'

    log("Starting Velociraptor upgrade...", "info")

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
    log("Creating backups...", "info")
    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    # Stop container
    log("Stopping Velociraptor container...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Velociraptor: {result['error']}"}

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'VELOCIRAPTOR_VERSION', version, logger=log)
    version_parts = version.split('.')
    if len(version_parts) >= 2:
        velo_tag = f"{version_parts[0]}.{version_parts[1]}"
        update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

    # Download new binary
    log(f"Downloading Velociraptor {version}...", "info")
    velo_bin = os.path.join(velo_data, 'velociraptor')
    version_parts = version.split('.')
    if len(version_parts) >= 2:
        release_tag = f"v{version_parts[0]}.{version_parts[1]}"
    else:
        release_tag = f"v{version}"
    download_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/velociraptor-v{version}-linux-amd64"

    # Backup old binary
    if os.path.exists(velo_bin):
        run_command(f"mv {velo_bin} {velo_bin}.old", logger=log)

    result = run_command(f"curl -L -o {velo_bin} {download_url}", logger=log, timeout=300)
    if not result['success']:
        if os.path.exists(f"{velo_bin}.old"):
            run_command(f"mv {velo_bin}.old {velo_bin}", logger=log)
        return {"success": False, "error": "Failed to download new binary"}

    run_command(f"chmod +x {velo_bin}", logger=log)

    # Rebuild container
    log("Rebuilding container...", "info")
    run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Restore backups
    log("Restoring backups...", "info")
    if os.path.exists(f"{backup_dir}/config"):
        os.makedirs(config_dir, exist_ok=True)
        run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

    if os.path.exists(f"{backup_dir}/artifact_definitions"):
        os.makedirs(artifact_dir, exist_ok=True)
        run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

    # Start container
    log("Starting Velociraptor container...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Velociraptor: {result['error']}"}

    # Health check
    log("Waiting for Velociraptor to be ready...", "info")
    for i in range(30):
        result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=log, timeout=10)
        if result['success']:
            log("Velociraptor is running", "success")
            time.sleep(15)
            run_command(f"rm -rf {backup_dir}", logger=log)
            return {"success": True, "version": version}
        time.sleep(2)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_velociraptor_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor from offline package (uses local binary)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'mssp_velociraptor'
    binaries_dir = os.path.join(package_dir, 'binaries')

    log("Starting Velociraptor offline upgrade...", "info")

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
    log("Creating backups...", "info")
    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    # Stop container
    log("Stopping Velociraptor container...", "info")
    result = run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Velociraptor: {result['error']}"}

    # Update version in .env
    log(f"Updating version to {version}...", "info")
    update_env_file(env_file, 'VELOCIRAPTOR_VERSION', version, logger=log)

    # Copy binary from package
    log("Copying Velociraptor binary from package...", "info")
    velo_bin = os.path.join(velo_data, 'velociraptor')
    source_binary = os.path.join(binaries_dir, f"velociraptor-v{version}-linux-amd64")

    if not os.path.exists(source_binary):
        source_binary = os.path.join(binaries_dir, f"velociraptor-{version}-linux-amd64")

    if os.path.exists(source_binary):
        if os.path.exists(velo_bin):
            run_command(f"mv {velo_bin} {velo_bin}.old", logger=log)
        run_command(f"cp {source_binary} {velo_bin}", logger=log)
        run_command(f"chmod +x {velo_bin}", logger=log)
        log("  Binary copied successfully", "info")
    else:
        log(f"  Binary not found in package: {source_binary}", "warning")

    # Rebuild container
    log("Rebuilding container...", "info")
    run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Restore backups
    log("Restoring backups...", "info")
    if os.path.exists(f"{backup_dir}/config"):
        os.makedirs(config_dir, exist_ok=True)
        run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

    if os.path.exists(f"{backup_dir}/artifact_definitions"):
        os.makedirs(artifact_dir, exist_ok=True)
        run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

    # Start container
    log("Starting Velociraptor container...", "info")
    result = run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Velociraptor: {result['error']}"}

    # Health check
    log("Waiting for Velociraptor to be ready...", "info")
    for i in range(30):
        result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=log, timeout=10)
        if result['success']:
            log("Velociraptor is running", "success")
            time.sleep(15)
            run_command(f"rm -rf {backup_dir}", logger=log)
            return {"success": True, "version": version}
        time.sleep(2)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}
