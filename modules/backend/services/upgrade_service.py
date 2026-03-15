#!/usr/bin/env python3
"""
Upgrade Service - Module upgrade functions for MSSP platform.
Supports upgrading: ELK, Timesketch, IRIS, Velociraptor, Backend, Frontend
"""

import os
import re
import subprocess
import time
import json
import requests
from typing import Dict, Callable, Optional

# Base paths
# WORKDIR is for container-local file access (reading .env files, etc.)
WORKDIR = os.environ.get('MSSP_PATH', '/app/workdir')
# HOST_PATH is for docker compose operations (Docker daemon needs host paths)
HOST_PATH = os.environ.get('MSSP_HOST_PATH', WORKDIR)
MODULES_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run_command(cmd: str, cwd: str = None, timeout: int = 300, logger: Callable = None) -> Dict:
    """Run a shell command and return result.

    For docker compose commands, cwd should be the WORKDIR (container) path.
    The --project-directory flag with HOST_PATH is added automatically for compose commands.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        # For docker compose commands, use --project-directory with host path.
        # The host path is mounted inside container at the same path, so docker compose
        # can read files and Docker daemon can resolve volume mounts correctly.
        if cmd.startswith("docker compose") and cwd:
            if cwd.startswith(WORKDIR):
                host_cwd = cwd.replace(WORKDIR, HOST_PATH, 1)
                # Use host path for everything - it's mounted at same path inside container
                compose_file = os.path.join(host_cwd, 'docker-compose.yaml')
                cmd = cmd.replace("docker compose", f"docker compose -f {compose_file} --project-directory {host_cwd}", 1)
                cwd = None  # Don't need cwd since we specified paths explicitly

        log(f"  Running: {cmd[:80]}...", "info")
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            log(f"  Command failed: {result.stderr[:200]}", "warning")
            return {"success": False, "error": result.stderr, "stdout": result.stdout}
        return {"success": True, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        log(f"  Command timed out after {timeout}s", "error")
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        log(f"  Command error: {str(e)}", "error")
        return {"success": False, "error": str(e)}


def _read_env_file(env_path: str) -> Dict[str, str]:
    """Read .env file and return as dict."""
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


def _update_env_file(env_path: str, key: str, value: str, logger: Callable = None) -> bool:
    """Update a key in .env file."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        lines = []
        found = False
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.strip().startswith(f'{key}='):
                        lines.append(f'{key}={value}\n')
                        found = True
                    else:
                        lines.append(line)
        if not found:
            lines.append(f'{key}={value}\n')

        with open(env_path, 'w') as f:
            f.writelines(lines)
        log(f"  Updated {key}={value} in {env_path}", "info")
        return True
    except Exception as e:
        log(f"  Failed to update {env_path}: {e}", "error")
        return False


def get_current_versions() -> Dict:
    """Get current versions from .env files for all modules."""
    versions = {}

    # ELK
    elk_env = os.path.join(WORKDIR, 'modules', 'elk', '.env')
    elk_vars = _read_env_file(elk_env)
    versions['elk'] = {
        'current': elk_vars.get('ELASTIC_VERSION', 'unknown'),
        'env_file': elk_env
    }

    # Timesketch
    ts_env = os.path.join(WORKDIR, 'modules', 'timesketch', '.env')
    ts_vars = _read_env_file(ts_env)
    versions['timesketch'] = {
        'current': ts_vars.get('TIMESKETCH_VERSION', 'unknown'),
        'env_file': ts_env
    }

    # IRIS
    iris_env = os.path.join(WORKDIR, 'modules', 'iris', '.env')
    iris_vars = _read_env_file(iris_env)
    versions['iris'] = {
        'current': iris_vars.get('IRIS_VERSION', 'unknown'),
        'env_file': iris_env
    }

    # Velociraptor
    velo_env = os.path.join(WORKDIR, 'modules', 'velociraptor', '.env')
    velo_vars = _read_env_file(velo_env)
    versions['velociraptor'] = {
        'current': velo_vars.get('VELOCIRAPTOR_VERSION', 'unknown'),
        'env_file': velo_env
    }

    # Backend - use git describe or fallback
    try:
        result = subprocess.run(
            ['git', 'describe', '--tags', '--always'],
            cwd=MODULES_DIR,
            capture_output=True,
            text=True
        )
        backend_version = result.stdout.strip() if result.returncode == 0 else 'unknown'
    except:
        backend_version = 'unknown'
    versions['backend'] = {'current': backend_version}

    # Frontend - same as backend (same repo)
    versions['frontend'] = {'current': backend_version}

    return versions


def get_latest_versions() -> Dict:
    """Query GitHub API for latest versions of each module."""
    versions = {}

    # GitHub API endpoints for releases
    repos = {
        'elk': 'elastic/elasticsearch',
        'timesketch': 'google/timesketch',
        'iris': 'dfir-iris/iris-web',
        'velociraptor': 'Velocidex/velociraptor',
    }

    for module, repo in repos.items():
        try:
            response = requests.get(
                f'https://api.github.com/repos/{repo}/releases/latest',
                timeout=10,
                headers={'Accept': 'application/vnd.github.v3+json'}
            )
            if response.status_code == 200:
                data = response.json()
                versions[module] = data.get('tag_name', 'unknown')
            else:
                versions[module] = 'unknown'
        except Exception:
            versions[module] = 'unknown'

    # Backend/Frontend - check main repo
    try:
        response = requests.get(
            'https://api.github.com/repos/NofLevi10root/new-mssp/releases/latest',
            timeout=10,
            headers={'Accept': 'application/vnd.github.v3+json'}
        )
        if response.status_code == 200:
            data = response.json()
            versions['backend'] = data.get('tag_name', 'main')
            versions['frontend'] = data.get('tag_name', 'main')
        else:
            versions['backend'] = 'main'
            versions['frontend'] = 'main'
    except:
        versions['backend'] = 'main'
        versions['frontend'] = 'main'

    return versions


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    def parse_version(v):
        # Remove 'v' prefix if present
        v = v.lstrip('v')
        # Split by . and convert to integers
        parts = []
        for p in v.split('.'):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts

    p1, p2 = parse_version(v1), parse_version(v2)
    # Pad shorter version with zeros
    max_len = max(len(p1), len(p2))
    p1.extend([0] * (max_len - len(p1)))
    p2.extend([0] * (max_len - len(p2)))

    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def upgrade_elk(version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK stack to specified version.

    NOTE: Elasticsearch does NOT support downgrades. Only upgrades to newer versions are allowed.
    Attempting to downgrade will fail because Elasticsearch stores version metadata in the data directory.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'elk')

    log("Starting ELK upgrade...", "info")

    # Check current version and prevent downgrades
    current_vars = _read_env_file(env_file)
    current_version = current_vars.get('ELASTIC_VERSION', '0.0.0')

    if _compare_versions(version, current_version) < 0:
        error_msg = f"ELK downgrade not supported: {current_version} → {version}. Elasticsearch only supports forward upgrades."
        log(error_msg, "error")
        log("To change to an older version, you must first remove ELK data volumes (docker compose down -v)", "warning")
        return {"success": False, "error": error_msg}

    if _compare_versions(version, current_version) == 0:
        log(f"ELK is already at version {version}", "info")
        return {"success": True, "version": version, "message": "Already at target version"}

    # Step 1: Stop containers
    log("Stopping ELK containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop ELK: {result['error']}"}

    # Step 2: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'ELASTIC_VERSION', version, logger=log)
    _update_env_file(env_file, 'KIBANA_VERSION', version, logger=log)

    # Step 3: Pull new images
    log("Pulling new images...", "info")
    result = _run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)
    if not result['success']:
        log(f"Pull warning: {result.get('error', '')[:100]}", "warning")

    # Step 4: Build (for custom images)
    log("Building containers...", "info")
    result = _run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Step 5: Start containers
    log("Starting ELK containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start ELK: {result['error']}"}

    # Step 6: Health check
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


def upgrade_timesketch(version: str, logger: Callable = None, plaso_version: str = None) -> Dict:
    """Upgrade Timesketch to specified version."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'timesketch')

    log("Starting Timesketch upgrade...", "info")

    # Step 1: Stop containers
    log("Stopping Timesketch containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Timesketch: {result['error']}"}

    # Step 2: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

    # Step 3: Pull new images
    log("Pulling new images...", "info")
    result = _run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

    # Step 4: Pull Plaso image if specified
    if plaso_version:
        log(f"Pulling Plaso {plaso_version}...", "info")
        _run_command(f"docker pull log2timeline/plaso:{plaso_version}", logger=log, timeout=600)

    # Step 5: Start containers
    log("Starting Timesketch containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Timesketch: {result['error']}"}

    # Step 6: Health check
    log("Waiting for Timesketch to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("http://localhost:5666/login", timeout=5)
            if response.status_code == 200:
                log("Timesketch is ready", "success")
                return {"success": True, "version": version}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_iris(version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS to specified version."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'iris')

    log("Starting IRIS upgrade...", "info")

    # Step 1: Stop containers
    log("Stopping IRIS containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop IRIS: {result['error']}"}

    # Step 2: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    # Step 3: Pull new images
    log("Pulling new images...", "info")
    result = _run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

    # Step 4: Start containers
    log("Starting IRIS containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start IRIS: {result['error']}"}

    # Step 5: Health check
    log("Waiting for IRIS to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("https://localhost:8443/api/ping", timeout=5, verify=False)
            if response.status_code in [200, 401]:  # 401 is expected without auth
                log("IRIS is ready", "success")
                return {"success": True, "version": version}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_velociraptor(version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor to specified version (most complex - handles artifacts)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'velociraptor')
    container_name = 'mssp_velociraptor'

    log("Starting Velociraptor upgrade...", "info")

    # Step 0: Export artifacts to disk (before stopping)
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        # Export non-built-in artifacts using VQL
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        result = _run_command(export_cmd, logger=log, timeout=60)
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

    # Step 1: Create backups
    log("Creating backups...", "info")
    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    # Backup config directory
    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        _run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    # Backup artifact_definitions
    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        _run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    # Step 2: Stop container
    log("Stopping Velociraptor container...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Velociraptor: {result['error']}"}

    # Step 3: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'VELOCIRAPTOR_VERSION', version, logger=log)
    # Also update VELOCIRAPTOR_TAG (major.minor for docker-compose)
    version_parts = version.split('.')
    if len(version_parts) >= 2:
        velo_tag = f"{version_parts[0]}.{version_parts[1]}"
        _update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

    # Step 4: Download new binary
    log(f"Downloading Velociraptor {version}...", "info")
    velo_bin = os.path.join(velo_data, 'velociraptor')
    # Velociraptor uses major.minor for release tags (v0.75) but full version for assets (v0.75.6)
    version_parts = version.split('.')
    if len(version_parts) >= 2:
        release_tag = f"v{version_parts[0]}.{version_parts[1]}"
    else:
        release_tag = f"v{version}"
    download_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/velociraptor-v{version}-linux-amd64"

    # Backup old binary
    if os.path.exists(velo_bin):
        _run_command(f"mv {velo_bin} {velo_bin}.old", logger=log)

    result = _run_command(f"curl -L -o {velo_bin} {download_url}", logger=log, timeout=300)
    if not result['success']:
        # Restore old binary
        if os.path.exists(f"{velo_bin}.old"):
            _run_command(f"mv {velo_bin}.old {velo_bin}", logger=log)
        return {"success": False, "error": "Failed to download new binary"}

    _run_command(f"chmod +x {velo_bin}", logger=log)

    # Step 5: Rebuild container
    log("Rebuilding container...", "info")
    result = _run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Step 6: Restore backups
    log("Restoring backups...", "info")
    if os.path.exists(f"{backup_dir}/config"):
        os.makedirs(config_dir, exist_ok=True)
        _run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

    if os.path.exists(f"{backup_dir}/artifact_definitions"):
        os.makedirs(artifact_dir, exist_ok=True)
        _run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

    # Step 7: Start container
    log("Starting Velociraptor container...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Velociraptor: {result['error']}"}

    # Step 8: Health check
    log("Waiting for Velociraptor to be ready...", "info")
    for i in range(30):
        result = _run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=log, timeout=10)
        if result['success']:
            log("Velociraptor is running", "success")
            # Give time for artifacts to load
            time.sleep(15)

            # Cleanup backup
            _run_command(f"rm -rf {backup_dir}", logger=log)

            return {"success": True, "version": version}
        time.sleep(2)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_backend(logger: Callable = None) -> Dict:
    """Upgrade backend by pulling latest code and rebuilding."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container paths for all operations
    work_dir = os.path.join(WORKDIR, 'modules', 'backend')
    repo_dir = WORKDIR  # Root of MSSP project

    log("Starting Backend upgrade...", "info")

    # Step 1: Git pull latest code
    log("Pulling latest code...", "info")
    result = _run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        # Try development branch
        result = _run_command("git pull origin development", cwd=repo_dir, logger=log)

    # Step 2: Stop container
    log("Stopping backend container...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)

    # Step 3: Rebuild
    log("Rebuilding backend container...", "info")
    result = _run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Step 4: Start container
    log("Starting backend container...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Step 5: Health check
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


def upgrade_frontend(logger: Callable = None) -> Dict:
    """Upgrade frontend by copying updated files and restarting nginx."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for git operations
    repo_dir = WORKDIR  # Root of MSSP project

    log("Starting Frontend upgrade...", "info")

    # Step 1: Git pull (if not already done by backend upgrade)
    log("Pulling latest code...", "info")
    result = _run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = _run_command("git pull origin development", cwd=repo_dir, logger=log)

    # Step 2: Copy updated HTML/JS/CSS files (files are already updated by git pull)
    log("Frontend files updated via git pull", "info")

    # Step 3: Restart nginx container
    log("Restarting nginx...", "info")
    result = _run_command("docker restart mssp_nginx", logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to restart nginx: {result['error']}"}

    log("Frontend upgraded successfully", "success")
    return {"success": True}


def run_upgrade_workflow(modules: Dict[str, str], mode: str = 'online', logger: Callable = None) -> Dict:
    """Run upgrade workflow for selected modules.

    Args:
        modules: Dict of module_name -> target_version (e.g., {"elk": "8.19.0", "iris": "v2.5.0"})
        mode: 'online' or 'offline' (offline not implemented yet)
        logger: Logging function

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Define upgrade order (dependencies first)
    upgrade_order = ['elk', 'timesketch', 'iris', 'velociraptor', 'backend', 'frontend']
    upgrade_functions = {
        'elk': upgrade_elk,
        'timesketch': upgrade_timesketch,
        'iris': upgrade_iris,
        'velociraptor': upgrade_velociraptor,
        'backend': upgrade_backend,
        'frontend': upgrade_frontend,
    }

    results = {}
    total = len(modules)
    completed = 0

    # Get current versions for better logging
    current_versions = get_current_versions()

    log(f"Starting upgrade workflow for {total} module(s)", "info")
    log(f"Mode: {mode}", "info")
    log("=" * 50, "info")

    # Log version summary
    for module_name, target_version in modules.items():
        current = current_versions.get(module_name, {}).get('current', 'unknown')
        log(f"  {module_name.upper()}: {current} → {target_version}", "info")
    log("=" * 50, "info")

    for module_name in upgrade_order:
        if module_name not in modules:
            continue

        target_version = modules[module_name]
        current = current_versions.get(module_name, {}).get('current', 'unknown')
        log("", "info")
        log(f"{'='*50}", "info")
        log(f"UPGRADING: {module_name.upper()}", "info")
        log(f"  Current version: {current}", "info")
        log(f"  Target version:  {target_version}", "info")
        log(f"{'='*50}", "info")

        upgrade_fn = upgrade_functions.get(module_name)
        if not upgrade_fn:
            log(f"Unknown module: {module_name}", "error")
            results[module_name] = {"success": False, "error": "Unknown module"}
            continue

        try:
            if module_name in ['backend', 'frontend']:
                result = upgrade_fn(logger=log)
            else:
                result = upgrade_fn(target_version, logger=log)

            results[module_name] = result
            completed += 1

            if result.get('success'):
                log(f"{module_name.upper()} upgrade completed: {current} → {target_version}", "success")
            else:
                log(f"{module_name.upper()} upgrade failed: {result.get('error', 'unknown')}", "error")
        except Exception as e:
            log(f"{module_name.upper()} upgrade error: {str(e)}", "error")
            results[module_name] = {"success": False, "error": str(e)}

    log("", "info")
    log("=" * 50, "info")
    log(f"Upgrade workflow completed: {completed}/{total} modules", "info")

    # Restart nginx at the end
    log("Restarting nginx proxy...", "info")
    _run_command("docker restart mssp_nginx", logger=log)

    all_success = all(r.get('success', False) for r in results.values())
    return {
        "success": all_success,
        "results": results,
        "completed": completed,
        "total": total
    }


# =============================================================================
# OFFLINE UPGRADE FUNCTIONS
# =============================================================================

def load_docker_image(image_tar: str, logger: Callable = None) -> Dict:
    """Load a docker image from a tar file."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    if not os.path.exists(image_tar):
        log(f"  Image file not found: {image_tar}", "error")
        return {"success": False, "error": f"Image file not found: {image_tar}"}

    log(f"  Loading image: {os.path.basename(image_tar)}...", "info")
    result = _run_command(f"docker load -i {image_tar}", logger=log, timeout=600)

    if result['success']:
        # Parse loaded image name from output
        stdout = result.get('stdout', '')
        log(f"  Loaded: {stdout.strip()[:100]}", "info")

    return result


def verify_upgrade_package(package_path: str, logger: Callable = None) -> Dict:
    """Extract and verify an upgrade package.

    Args:
        package_path: Path to the .tar.gz package file

    Returns:
        Dict with success, extract_dir, and manifest info
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    import tarfile
    import hashlib

    if not os.path.exists(package_path):
        return {"success": False, "error": f"Package not found: {package_path}"}

    log("Extracting upgrade package...", "info")

    # Create extraction directory
    extract_dir = f"/tmp/mssp-upgrade-{int(time.time())}"
    os.makedirs(extract_dir, exist_ok=True)

    try:
        # Extract tar.gz
        with tarfile.open(package_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        log(f"  Extracted to {extract_dir}", "info")

        # Find the actual package directory (tar contains a subdirectory)
        subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
        if subdirs:
            package_dir = os.path.join(extract_dir, subdirs[0])
        else:
            package_dir = extract_dir

        # Read manifest
        manifest_path = os.path.join(package_dir, 'manifest.json')
        if not os.path.exists(manifest_path):
            return {"success": False, "error": "manifest.json not found in package", "extract_dir": extract_dir}

        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        log(f"  Package created: {manifest.get('created', 'unknown')}", "info")
        log(f"  Versions: {json.dumps(manifest.get('versions', {}))}", "info")

        # Verify checksums if present
        checksums_path = os.path.join(package_dir, 'checksums.sha256')
        if os.path.exists(checksums_path):
            log("Verifying checksums...", "info")
            failed_checksums = []

            with open(checksums_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('  ', 1)
                    if len(parts) == 2:
                        expected_hash, rel_path = parts
                        # Remove leading ./ if present
                        rel_path = rel_path.lstrip('./')
                        file_path = os.path.join(package_dir, rel_path)

                        if os.path.exists(file_path):
                            with open(file_path, 'rb') as check_file:
                                actual_hash = hashlib.sha256(check_file.read()).hexdigest()
                            if actual_hash != expected_hash:
                                failed_checksums.append(rel_path)

            if failed_checksums:
                log(f"  WARNING: {len(failed_checksums)} files failed checksum verification", "warning")
            else:
                log("  All checksums verified", "success")

        return {
            "success": True,
            "extract_dir": extract_dir,
            "package_dir": package_dir,
            "manifest": manifest
        }

    except Exception as e:
        log(f"Failed to extract/verify package: {str(e)}", "error")
        return {"success": False, "error": str(e), "extract_dir": extract_dir}


def upgrade_elk_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade ELK from offline package (pre-saved docker images)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'elk')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'elk')

    log("Starting ELK offline upgrade...", "info")

    # Step 1: Stop containers
    log("Stopping ELK containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop ELK: {result['error']}"}

    # Step 2: Load docker images
    log("Loading docker images from package...", "info")
    for img_name in ['elasticsearch', 'kibana', 'logstash']:
        tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
        if os.path.exists(tar_path):
            result = load_docker_image(tar_path, logger=log)
            if not result['success']:
                log(f"  Warning: Failed to load {img_name}", "warning")
        else:
            log(f"  Image not found: {tar_path}", "warning")

    # Step 3: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'ELASTIC_VERSION', version, logger=log)
    _update_env_file(env_file, 'KIBANA_VERSION', version, logger=log)

    # Step 4: Start containers (no pull needed)
    log("Starting ELK containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start ELK: {result['error']}"}

    # Step 5: Health check
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


def upgrade_timesketch_offline(package_dir: str, version: str, plaso_version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Timesketch from offline package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'timesketch')

    log("Starting Timesketch offline upgrade...", "info")

    # Step 1: Stop containers
    log("Stopping Timesketch containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Timesketch: {result['error']}"}

    # Step 2: Load docker images
    log("Loading docker images from package...", "info")
    ts_tar = os.path.join(images_dir, f"timesketch-{version}.tar")
    if os.path.exists(ts_tar):
        load_docker_image(ts_tar, logger=log)

    if plaso_version:
        plaso_tar = os.path.join(images_dir, f"plaso-{plaso_version}.tar")
        if os.path.exists(plaso_tar):
            load_docker_image(plaso_tar, logger=log)

    # Step 3: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

    # Step 4: Start containers
    log("Starting Timesketch containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Timesketch: {result['error']}"}

    # Step 5: Health check
    log("Waiting for Timesketch to be ready...", "info")
    for i in range(30):
        try:
            response = requests.get("http://localhost:5666/login", timeout=5)
            if response.status_code == 200:
                log("Timesketch is ready", "success")
                return {"success": True, "version": version}
        except:
            pass
        time.sleep(5)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_iris_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS from offline package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'iris')

    log("Starting IRIS offline upgrade...", "info")

    # Step 1: Stop containers
    log("Stopping IRIS containers...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop IRIS: {result['error']}"}

    # Step 2: Load docker images
    log("Loading docker images from package...", "info")
    for img_name in ['iris-app', 'iris-worker', 'iris-nginx']:
        tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
        if os.path.exists(tar_path):
            load_docker_image(tar_path, logger=log)

    # Step 3: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    # Step 4: Start containers
    log("Starting IRIS containers...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start IRIS: {result['error']}"}

    # Step 5: Health check
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


def upgrade_velociraptor_offline(package_dir: str, version: str, logger: Callable = None) -> Dict:
    """Upgrade Velociraptor from offline package (uses local binary)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    # Host path for docker compose operations
    host_dir = os.path.join(HOST_PATH, 'modules', 'velociraptor')
    container_name = 'mssp_velociraptor'
    binaries_dir = os.path.join(package_dir, 'binaries')

    log("Starting Velociraptor offline upgrade...", "info")

    # Step 0: Export artifacts (same as online)
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        result = _run_command(export_cmd, logger=log, timeout=60)
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

    # Step 1: Create backups
    log("Creating backups...", "info")
    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        _run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        _run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    # Step 2: Stop container
    log("Stopping Velociraptor container...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to stop Velociraptor: {result['error']}"}

    # Step 3: Update version in .env
    log(f"Updating version to {version}...", "info")
    _update_env_file(env_file, 'VELOCIRAPTOR_VERSION', version, logger=log)

    # Step 4: Copy binary from package (instead of downloading)
    log("Copying Velociraptor binary from package...", "info")
    velo_bin = os.path.join(velo_data, 'velociraptor')
    source_binary = os.path.join(binaries_dir, f"velociraptor-v{version}-linux-amd64")

    if not os.path.exists(source_binary):
        # Try without 'v' prefix
        source_binary = os.path.join(binaries_dir, f"velociraptor-{version}-linux-amd64")

    if os.path.exists(source_binary):
        # Backup old binary
        if os.path.exists(velo_bin):
            _run_command(f"mv {velo_bin} {velo_bin}.old", logger=log)

        _run_command(f"cp {source_binary} {velo_bin}", logger=log)
        _run_command(f"chmod +x {velo_bin}", logger=log)
        log("  Binary copied successfully", "info")
    else:
        log(f"  Binary not found in package: {source_binary}", "warning")

    # Step 5: Rebuild container
    log("Rebuilding container...", "info")
    result = _run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Step 6: Restore backups
    log("Restoring backups...", "info")
    if os.path.exists(f"{backup_dir}/config"):
        os.makedirs(config_dir, exist_ok=True)
        _run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

    if os.path.exists(f"{backup_dir}/artifact_definitions"):
        os.makedirs(artifact_dir, exist_ok=True)
        _run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

    # Step 7: Start container
    log("Starting Velociraptor container...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start Velociraptor: {result['error']}"}

    # Step 8: Health check
    log("Waiting for Velociraptor to be ready...", "info")
    for i in range(30):
        result = _run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=log, timeout=10)
        if result['success']:
            log("Velociraptor is running", "success")
            time.sleep(15)
            _run_command(f"rm -rf {backup_dir}", logger=log)
            return {"success": True, "version": version}
        time.sleep(2)

    log("Health check timed out", "warning")
    return {"success": True, "version": version, "health": "pending"}


def upgrade_backend_offline(package_dir: str, logger: Callable = None) -> Dict:
    """Upgrade backend from offline package source files."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for all operations
    work_dir = os.path.join(WORKDIR, 'modules', 'backend')
    source_dir = os.path.join(package_dir, 'source', 'backend')

    log("Starting Backend offline upgrade...", "info")

    if not os.path.exists(source_dir):
        log("Backend source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Step 1: Stop container
    log("Stopping backend container...", "info")
    result = _run_command("docker compose down", cwd=work_dir, logger=log)

    # Step 2: Copy source files
    log("Copying backend source files...", "info")
    _run_command(f"cp -a {source_dir}/* {work_dir}/", logger=log)

    # Step 3: Rebuild
    log("Rebuilding backend container...", "info")
    result = _run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)

    # Step 4: Start container
    log("Starting backend container...", "info")
    result = _run_command("docker compose up -d", cwd=work_dir, logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to start backend: {result['error']}"}

    # Step 5: Health check
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


def upgrade_frontend_offline(package_dir: str, logger: Callable = None) -> Dict:
    """Upgrade frontend from offline package source files."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Container path for file operations
    nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')
    source_dir = os.path.join(package_dir, 'source', 'frontend')

    log("Starting Frontend offline upgrade...", "info")

    if not os.path.exists(source_dir):
        log("Frontend source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Step 1: Copy frontend files
    log("Copying frontend files...", "info")
    _run_command(f"cp -a {source_dir}/* {nginx_html}/", logger=log)
    log("  Frontend files updated", "info")

    # Step 2: Restart nginx container
    log("Restarting nginx...", "info")
    result = _run_command("docker restart mssp_nginx", logger=log)
    if not result['success']:
        return {"success": False, "error": f"Failed to restart nginx: {result['error']}"}

    log("Frontend upgraded successfully", "success")
    return {"success": True}


def run_offline_upgrade_workflow(package_path: str, logger: Callable = None) -> Dict:
    """Run offline upgrade workflow from an uploaded package.

    Args:
        package_path: Path to the uploaded .tar.gz package

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    log("=" * 50, "info")
    log("OFFLINE UPGRADE WORKFLOW", "info")
    log("=" * 50, "info")

    # Step 1: Verify and extract package
    verify_result = verify_upgrade_package(package_path, logger=log)
    if not verify_result['success']:
        return {"success": False, "error": verify_result.get('error', 'Package verification failed')}

    package_dir = verify_result['package_dir']
    manifest = verify_result['manifest']
    versions = manifest.get('versions', {})

    log("", "info")
    log(f"Package versions: {json.dumps(versions)}", "info")

    # Map offline upgrade functions
    offline_upgrade_functions = {
        'elk': upgrade_elk_offline,
        'timesketch': upgrade_timesketch_offline,
        'iris': upgrade_iris_offline,
        'velociraptor': upgrade_velociraptor_offline,
        'backend': upgrade_backend_offline,
        'frontend': upgrade_frontend_offline,
    }

    # Upgrade order
    upgrade_order = ['elk', 'timesketch', 'iris', 'velociraptor', 'backend', 'frontend']

    results = {}
    total = 0
    completed = 0

    # Count modules to upgrade
    for module in upgrade_order:
        if module in versions or module in ['backend', 'frontend']:
            total += 1

    for module_name in upgrade_order:
        version = versions.get(module_name)

        # Skip if not in manifest (except backend/frontend which check for source)
        if not version and module_name not in ['backend', 'frontend']:
            continue

        log("", "info")
        log(f"{'='*50}", "info")
        log(f"UPGRADING: {module_name.upper()} -> {version or 'from source'}", "info")
        log(f"{'='*50}", "info")

        upgrade_fn = offline_upgrade_functions.get(module_name)
        if not upgrade_fn:
            log(f"Unknown module: {module_name}", "error")
            results[module_name] = {"success": False, "error": "Unknown module"}
            continue

        try:
            if module_name in ['backend', 'frontend']:
                result = upgrade_fn(package_dir, logger=log)
            elif module_name == 'timesketch':
                plaso_version = versions.get('plaso')
                result = upgrade_fn(package_dir, version, plaso_version=plaso_version, logger=log)
            else:
                result = upgrade_fn(package_dir, version, logger=log)

            results[module_name] = result
            if not result.get('skipped'):
                completed += 1

            if result.get('success'):
                log(f"{module_name.upper()} upgrade completed", "success")
            else:
                log(f"{module_name.upper()} upgrade failed: {result.get('error', 'unknown')}", "error")
        except Exception as e:
            log(f"{module_name.upper()} upgrade error: {str(e)}", "error")
            results[module_name] = {"success": False, "error": str(e)}

    # Cleanup
    log("", "info")
    log("Cleaning up...", "info")
    extract_dir = verify_result.get('extract_dir')
    if extract_dir and os.path.exists(extract_dir):
        _run_command(f"rm -rf {extract_dir}", logger=log)

    # Restart nginx at the end
    log("Restarting nginx proxy...", "info")
    _run_command("docker restart mssp_nginx", logger=log)

    log("", "info")
    log("=" * 50, "info")
    log(f"Offline upgrade completed: {completed}/{total} modules", "info")

    all_success = all(r.get('success', False) for r in results.values())
    return {
        "success": all_success,
        "results": results,
        "completed": completed,
        "total": total,
        "versions": versions
    }


def get_package_info(package_path: str) -> Dict:
    """Get manifest info from an upgrade package without fully extracting.

    Args:
        package_path: Path to the .tar.gz package

    Returns:
        Dict with versions and package info
    """
    import tarfile

    if not os.path.exists(package_path):
        return {"success": False, "error": "Package not found"}

    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            # Find manifest.json in the archive
            for member in tar.getmembers():
                if member.name.endswith('manifest.json'):
                    f = tar.extractfile(member)
                    if f:
                        manifest = json.load(f)
                        return {
                            "success": True,
                            "manifest": manifest,
                            "versions": manifest.get('versions', {}),
                            "created": manifest.get('created'),
                            "contents": manifest.get('contents', {})
                        }

        return {"success": False, "error": "manifest.json not found in package"}
    except Exception as e:
        return {"success": False, "error": str(e)}
