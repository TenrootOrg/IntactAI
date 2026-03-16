#!/usr/bin/env python3
"""
Base utilities for upgrade operations.
Shared functions used across all module upgrade files.
"""

import os
import shutil
import subprocess
import time
import json
import hashlib
import tarfile
import requests
from typing import Dict, Callable, Optional

# Base paths
WORKDIR = os.environ.get('MSSP_PATH', '/app/workdir')
HOST_PATH = os.environ.get('MSSP_HOST_PATH', WORKDIR)
MODULES_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_command(cmd: str, cwd: str = None, timeout: int = 300, logger: Callable = None) -> Dict:
    """Run a shell command and return result.

    For docker compose commands, cwd should be the WORKDIR (container) path.
    The --project-directory flag with HOST_PATH is added automatically for compose commands.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        if cmd.startswith("docker compose") and cwd:
            if cwd.startswith(WORKDIR):
                host_cwd = cwd.replace(WORKDIR, HOST_PATH, 1)
                compose_file = os.path.join(host_cwd, 'docker-compose.yaml')
                cmd = cmd.replace("docker compose", f"docker compose -f {compose_file} --project-directory {host_cwd}", 1)
                cwd = None

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


def read_env_file(env_path: str) -> Dict[str, str]:
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


def update_env_file(env_path: str, key: str, value: str, logger: Callable = None) -> bool:
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


def backup_env_file(env_file: str, logger: Callable = None) -> Optional[str]:
    """Create a backup of the .env file before upgrade. Returns backup path or None."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backup_file = f"{env_file}.pre-upgrade-backup"
    try:
        if os.path.exists(env_file):
            shutil.copy2(env_file, backup_file)
            log(f"  Created backup: {backup_file}", "info")
            return backup_file
    except Exception as e:
        log(f"  Warning: Could not create backup: {e}", "warning")
    return None


def restore_env_file(env_file: str, backup_file: str, logger: Callable = None) -> bool:
    """Restore .env file from backup during rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        if backup_file and os.path.exists(backup_file):
            shutil.copy2(backup_file, env_file)
            os.remove(backup_file)
            log(f"  Restored from backup: {backup_file}", "info")
            return True
    except Exception as e:
        log(f"  Warning: Could not restore backup: {e}", "warning")
    return False


def cleanup_backup(backup_file: str, logger: Callable = None):
    """Remove backup file after successful upgrade."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        if backup_file and os.path.exists(backup_file):
            os.remove(backup_file)
            log(f"  Cleaned up backup: {backup_file}", "info")
    except Exception as e:
        log(f"  Warning: Could not remove backup: {e}", "warning")


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    def parse_version(v):
        v = v.lstrip('v')
        parts = []
        for p in v.split('.'):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts

    p1, p2 = parse_version(v1), parse_version(v2)
    max_len = max(len(p1), len(p2))
    p1.extend([0] * (max_len - len(p1)))
    p2.extend([0] * (max_len - len(p2)))

    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def get_current_versions() -> Dict:
    """Get current versions from .env files for all modules."""
    versions = {}

    # ELK
    elk_env = os.path.join(WORKDIR, 'modules', 'elk', '.env')
    elk_vars = read_env_file(elk_env)
    versions['elk'] = {
        'current': elk_vars.get('ELASTIC_VERSION', 'unknown'),
        'env_file': elk_env
    }

    # Timesketch
    ts_env = os.path.join(WORKDIR, 'modules', 'timesketch', '.env')
    ts_vars = read_env_file(ts_env)
    versions['timesketch'] = {
        'current': ts_vars.get('TIMESKETCH_VERSION', 'unknown'),
        'env_file': ts_env
    }

    # Plaso - read from backend .env
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    backend_vars = read_env_file(backend_env)
    versions['plaso'] = {
        'current': backend_vars.get('PLASO_VERSION', 'unknown'),
        'env_file': backend_env
    }

    # IRIS
    iris_env = os.path.join(WORKDIR, 'modules', 'iris', '.env')
    iris_vars = read_env_file(iris_env)
    versions['iris'] = {
        'current': iris_vars.get('IRIS_VERSION', 'unknown'),
        'env_file': iris_env
    }

    # Velociraptor
    velo_env = os.path.join(WORKDIR, 'modules', 'velociraptor', '.env')
    velo_vars = read_env_file(velo_env)
    versions['velociraptor'] = {
        'current': velo_vars.get('VELOCIRAPTOR_VERSION', 'unknown'),
        'env_file': velo_env
    }

    # RISX Platform - use git describe or fallback
    try:
        result = subprocess.run(
            ['git', 'describe', '--tags', '--always'],
            cwd=MODULES_DIR,
            capture_output=True,
            text=True
        )
        risx_version = result.stdout.strip() if result.returncode == 0 else 'unknown'
    except:
        risx_version = 'unknown'
    versions['risx'] = {'current': risx_version}

    return versions


def get_latest_versions() -> Dict:
    """Query GitHub API for latest versions of each module."""
    versions = {}

    repos = {
        'elk': 'elastic/elasticsearch',
        'timesketch': 'google/timesketch',
        'plaso': 'log2timeline/plaso',
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

    # RISX Platform
    try:
        response = requests.get(
            'https://api.github.com/repos/NofLevi10root/new-mssp/releases/latest',
            timeout=10,
            headers={'Accept': 'application/vnd.github.v3+json'}
        )
        if response.status_code == 200:
            data = response.json()
            versions['risx'] = data.get('tag_name', 'main')
        else:
            versions['risx'] = 'main'
    except:
        versions['risx'] = 'main'

    return versions


def load_docker_image(image_tar: str, logger: Callable = None) -> Dict:
    """Load a docker image from a tar file."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    if not os.path.exists(image_tar):
        log(f"  Image file not found: {image_tar}", "error")
        return {"success": False, "error": f"Image file not found: {image_tar}"}

    log(f"  Loading image: {os.path.basename(image_tar)}...", "info")
    result = run_command(f"docker load -i {image_tar}", logger=log, timeout=600)

    if result['success']:
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

    if not os.path.exists(package_path):
        return {"success": False, "error": f"Package not found: {package_path}"}

    log("Extracting upgrade package...", "info")

    extract_dir = f"/tmp/mssp-upgrade-{int(time.time())}"
    os.makedirs(extract_dir, exist_ok=True)

    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        log(f"  Extracted to {extract_dir}", "info")

        subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
        if subdirs:
            package_dir = os.path.join(extract_dir, subdirs[0])
        else:
            package_dir = extract_dir

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


def get_package_info(package_path: str) -> Dict:
    """Get manifest info from an upgrade package without fully extracting."""
    if not os.path.exists(package_path):
        return {"success": False, "error": "Package not found"}

    try:
        with tarfile.open(package_path, 'r:gz') as tar:
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
