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
import tarfile
from typing import Dict, Callable, Optional

# Base paths
WORKDIR = os.environ.get('INTACT_PATH', '/app/workdir')
HOST_PATH = os.environ.get('INTACT_HOST_PATH', WORKDIR)
MODULES_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_command(cmd: str, cwd: str = None, timeout: int = 300, logger: Callable = None,
                run_id: Optional[str] = None) -> Dict:
    """Run a shell command and return result.

    For docker compose commands, cwd should be the WORKDIR (container) path.
    The --project-directory flag with HOST_PATH is added automatically for compose commands.

    When `run_id` is supplied, the subprocess is launched with Popen and
    polled against the workflow's cancel event. If the operator clicks
    Stop, the subprocess is SIGTERM'd (then SIGKILL'd) within ~1 second
    and the call returns with success=False, error='cancelled'. Without
    this, a long-running `docker pull` / `docker save` / `tar` would
    block the workflow thread for minutes and ignore the cancel — which
    is what made the Stop button feel broken on prepare_package and
    download-tools.
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

        # Cancellation-aware path: Popen + poll the cancel event every
        # second so Stop is honoured DURING long-running subprocesses
        # (docker pull, docker save, tar), not just between them.
        if run_id:
            try:
                from services.workflow_service import (
                    get_cancel_event, register_cleanup, terminate_subprocess,
                )
                cancel_event = get_cancel_event(run_id)
            except Exception:
                cancel_event = None
            # Fall through to the blocking path if no event is registered
            # for this run_id — keeps behaviour identical for callers that
            # opt-in but happen to not have a registered run.
            if cancel_event is not None:
                process = subprocess.Popen(
                    cmd, shell=True, cwd=cwd,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                # Register cleanup so request_stop() can SIGTERM us instantly
                # even before our next poll tick — terminate_subprocess is
                # idempotent + safe-on-already-exited.
                try:
                    register_cleanup(run_id, lambda p=process: terminate_subprocess(p))
                except Exception:
                    pass

                # Poll the event every second; check process every iter too.
                # `timeout` still acts as a hard ceiling.
                import time as _time
                start = _time.time()
                while process.poll() is None:
                    if cancel_event.is_set():
                        log("  Command cancelled by user", "warning")
                        terminate_subprocess(process)
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    if _time.time() - start > timeout:
                        log(f"  Command timed out after {timeout}s", "error")
                        terminate_subprocess(process)
                        return {"success": False, "error": f"Command timed out after {timeout}s"}
                    _time.sleep(1.0)
                stdout, stderr = process.communicate()
                if process.returncode != 0:
                    log(f"  Command failed: {(stderr or '')[:200]}", "warning")
                    return {"success": False, "error": stderr or "", "stdout": stdout or ""}
                return {"success": True, "stdout": stdout or "", "stderr": stderr or ""}

        # Legacy blocking path (callers that don't care about cancel).
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
    """Get current versions for all modules.

    Each module reports as:
      - 'Not installed' — primary container is absent (module never
        deployed on this host)
      - actual version string — read from the module's .env
      - 'unknown' — module deployed but version key missing or
        unreadable (most likely a stale install where .env got hand-
        edited)
    """
    versions = {}

    elk_env = os.path.join(WORKDIR, 'modules', 'elk', '.env')
    versions['elk'] = {
        'current': _read_module_version('elk', elk_env, 'ELASTIC_VERSION'),
        'env_file': elk_env,
    }

    ts_env = os.path.join(WORKDIR, 'modules', 'timesketch', '.env')
    versions['timesketch'] = {
        'current': _read_module_version('timesketch', ts_env, 'TIMESKETCH_VERSION'),
        'env_file': ts_env,
    }

    # Plaso pin lives in the backend .env (no standalone container);
    # always shows the configured value.
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    backend_vars = read_env_file(backend_env)
    versions['plaso'] = {
        'current': backend_vars.get('PLASO_VERSION', 'unknown'),
        'env_file': backend_env,
    }

    iris_env = os.path.join(WORKDIR, 'modules', 'iris', '.env')
    versions['iris'] = {
        'current': _read_module_version('iris', iris_env, 'IRIS_VERSION'),
        'env_file': iris_env,
    }

    velo_env = os.path.join(WORKDIR, 'modules', 'velociraptor', '.env')
    versions['velociraptor'] = {
        'current': _read_module_version('velociraptor', velo_env, 'VELOCIRAPTOR_VERSION'),
        'env_file': velo_env,
    }

    # VolWeb — newer module, was missing from the version map before. Reports
    # 'Not installed' when the operator never deployed it.
    volweb_env = os.path.join(WORKDIR, 'modules', 'volweb', '.env')
    versions['volweb'] = {
        'current': _read_module_version('volweb', volweb_env, 'VOLWEB_BACKEND_VERSION'),
        'env_file': volweb_env,
    }

    # Intact.AI Platform — read from VERSION file at repo root (stamped by
    # .github/workflows/stamp-version-on-release.yml on every release, AND
    # re-stamped by services/upgrade/package.py at prepare time as a
    # belt-and-suspenders for non-release refs / pre-Action releases).
    # Falls back to the running container's image tag for installs that
    # predate the VERSION-file mechanism. 'Not installed' when the
    # intact_backend container itself is absent.
    if _module_container_exists('intact') is False:
        intact_version = 'Not installed'
    else:
        intact_version = None
        version_file = os.path.join(WORKDIR, 'VERSION')
        if os.path.exists(version_file):
            try:
                with open(version_file) as f:
                    v = f.read().strip()
                if v:
                    intact_version = v
            except Exception:
                pass
        if not intact_version:
            try:
                result = subprocess.run(
                    ['docker', 'inspect', 'intact_backend',
                     '--format', '{{.Config.Image}}'],
                    capture_output=True, text=True, timeout=5,
                )
                image = (result.stdout or '').strip()
                intact_version = image.split(':', 1)[1] if ':' in image else (image or 'unknown')
            except Exception:
                intact_version = 'unknown'
    versions['intact'] = {'current': intact_version}

    return versions


def get_latest_versions() -> Dict:
    """Return the platform's currently-pinned versions for each module.

    Single source of truth: `config.yaml`'s `versions:` block. The
    function used to hold a parallel hardcoded dict that drifted out
    of sync (e.g. velociraptor stuck at 0.75.6 while the platform was
    actually pinned to 0.76.5) — which silently shipped stale defaults
    in the Prepare Package modal. Reading config.yaml directly keeps
    the modal's pre-fill aligned with whatever the operator pinned.

    Falls back to the last-known good values if config.yaml is missing
    or unparseable, so the modal still works on a half-broken install.
    """
    # config.yaml's `versions:` keys use module-specific names that
    # don't all match the module IDs the prepare-modal speaks. Map
    # them here so the JS gets back the same keys it expects.
    config_key_map = {
        'elk':          'elk',
        'timesketch':   'timesketch',
        'plaso':        'plaso',
        'iris':         'iris',
        'velociraptor': 'velociraptor',
        'aws':          'aws_prowler',
        'azure':        'azure_dfir_o365rc',
        'intact':       'backend',
        # VolWeb backend image (memory-forensics analysis stack).
        # config.yaml ships 4 volweb_* pins (backend, frontend,
        # postgres, redis); the prepare-modal version textbox drives
        # the backend image tag which is the one operators actually
        # bump release-to-release.
        'volweb':       'volweb_backend',
    }
    fallback = {
        'elk': '9.3.3',
        'timesketch': '20260326',
        'plaso': '20260119',
        'iris': 'v2.4.27',
        'velociraptor': '0.76.5',
        'aws': '5.28.1',
        'azure': 'latest',
        'intact': '1.0.0',
        'volweb': 'latest',
    }

    # config.yaml lives at the repo root, which is mounted at WORKDIR
    # inside the backend container.
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        return fallback

    try:
        import yaml  # local import — yaml isn't used elsewhere in base.py
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        versions = cfg.get('versions') or {}
        result = {}
        for module_id, config_key in config_key_map.items():
            val = versions.get(config_key)
            result[module_id] = str(val) if val is not None else fallback[module_id]
        return result
    except Exception:
        return fallback


def load_docker_image(image_tar: str, logger: Callable = None,
                      run_id: Optional[str] = None) -> Dict:
    """Load a docker image from a tar file.

    `run_id` makes the docker load interruptible — clicking Stop on
    an offline upgrade now SIGTERMs the docker CLI immediately instead
    of waiting for a multi-GB image to finish loading.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    if not os.path.exists(image_tar):
        log(f"  Image file not found: {image_tar}", "error")
        return {"success": False, "error": f"Image file not found: {image_tar}"}

    log(f"  Loading image: {os.path.basename(image_tar)}...", "info")
    result = run_command(f"docker load -i {image_tar}", logger=log, timeout=600, run_id=run_id)

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

    # Use /app/data/tmp/ (mounted from host's data/) for persistence across container restarts
    # This is critical for Phase 2 to find the extracted files after backend restarts
    os.makedirs("/app/data/tmp", exist_ok=True)
    extract_dir = f"/app/data/tmp/intact-upgrade-{int(time.time())}"
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
            # Cleanup on failure
            shutil.rmtree(extract_dir, ignore_errors=True)
            return {"success": False, "error": "manifest.json not found in package"}

        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        log(f"  Package created: {manifest.get('created', 'unknown')}", "info")
        log(f"  Versions: {json.dumps(manifest.get('versions', {}))}", "info")

        return {
            "success": True,
            "extract_dir": extract_dir,
            "package_dir": package_dir,
            "manifest": manifest
        }

    except Exception as e:
        log(f"Failed to extract/verify package: {str(e)}", "error")
        # Cleanup on failure
        shutil.rmtree(extract_dir, ignore_errors=True)
        return {"success": False, "error": str(e)}


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


# ---------------------------------------------------------------------------
# Module install/upgrade routing — used by services/upgrade/__init__.py
# to detect whether the orchestrator should run the install or upgrade
# path per module, and by get_current_versions() to distinguish "module
# is installed but version unreadable" from "module never installed".
# ---------------------------------------------------------------------------

_MODULE_PRIMARY_CONTAINERS = {
    'elk':          'intact_elasticsearch',
    'iris':         'intact_iris_app',
    'portainer':    'intact_portainer',
    'timesketch':   'intact_timesketch_web',
    'velociraptor': 'intact_velociraptor',
    'volweb':       'intact_volweb_backend',
    'intact':       'intact_backend',
}


def _module_container_exists(module_id: str) -> Optional[bool]:
    """True iff the module's primary container exists (running or stopped).
    Returns None for modules with no container concept (aws/azure/plaso).
    Callers should treat None as 'always installed' since those modules
    don't deploy a standalone container stack."""
    name = _MODULE_PRIMARY_CONTAINERS.get(module_id)
    if not name:
        return None
    try:
        result = subprocess.run(
            ['docker', 'ps', '-a', '--filter', f'name=^{name}$',
             '--format', '{{.Names}}'],
            capture_output=True, text=True, timeout=5,
        )
        return name in (result.stdout or '')
    except Exception:
        return None


def _read_module_version(module_id: str, env_path: str, version_key: str) -> str:
    """Resolve a single module's current version:
       - 'Not installed': module has a primary container concept + the
         container is absent (operator skipped this module at install time)
       - actual version string: container exists + .env has the key
       - 'unknown': container exists / no detection logic but .env key
         missing or unreadable"""
    present = _module_container_exists(module_id)
    if present is False:
        return 'Not installed'
    if os.path.exists(env_path):
        v = read_env_file(env_path).get(version_key)
        if v:
            return v
    return 'unknown'


def install_module_compose_up(
    module_id: str,
    package_dir: str,
    version: str,
    image_tar_prefixes: list = None,
    logger: Callable = None,
    run_id: str = None,
) -> Dict:
    """Generic fresh-install helper for modules whose first-time setup
    is just "load bundled images + docker compose up -d". Modules with
    extra first-time setup (volweb's .env render + shared volume; iris's
    secret generation) layer that BEFORE calling this helper."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', module_id)
    if not os.path.exists(work_dir):
        return {
            "success": False,
            "error": (
                f"module directory missing at {work_dir} — upgrade the "
                "Intact.AI source first so the new module's compose file "
                "lands on disk"
            ),
        }

    # Load any bundled images from the offline package
    images_dir = os.path.join(package_dir, 'images')
    if image_tar_prefixes and os.path.isdir(images_dir):
        for prefix in image_tar_prefixes:
            for fn in os.listdir(images_dir):
                if fn.startswith(prefix) and fn.endswith('.tar'):
                    image_tar = os.path.join(images_dir, fn)
                    log(f"  Loading bundled image: {fn}", "info")
                    loaded = load_docker_image(image_tar, logger=log, run_id=run_id)
                    if not loaded.get('success'):
                        log(
                            f"  Image load failed (continuing — compose will "
                            f"try to pull): {loaded.get('error')}",
                            "warning",
                        )

    # The docker CLI we exec'd against /var/run/docker.sock sees the host
    # filesystem, not the container's — translate WORKDIR → HOST_PATH.
    host_work_dir = work_dir.replace(WORKDIR, HOST_PATH, 1)
    log(f"  docker compose up -d on {module_id}...", "info")
    r = run_command(
        f"docker compose -f {host_work_dir}/docker-compose.yaml "
        f"--project-directory {host_work_dir} up -d",
        timeout=300, logger=log, run_id=run_id,
    )
    if not r.get('success'):
        return {"success": False, "error": f"compose up failed: {r.get('error')}"}

    log(f"{module_id} first-time install complete", "success")
    return {"success": True, "version": version, "first_install": True}
