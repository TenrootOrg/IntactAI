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


# Per-module image repos used by remove_old_module_image() below.
# When a module's upgrade succeeds, the helper removes
# `<repo>:<old_version>` for each repo listed here. Add an entry
# when introducing a new module so its post-upgrade cleanup runs
# automatically.
_MODULE_IMAGE_REPOS = {
    'iris': [
        'ghcr.io/dfir-iris/iriswebapp_app',
        'ghcr.io/dfir-iris/iriswebapp_db',
        'ghcr.io/dfir-iris/iriswebapp_nginx',
    ],
    'timesketch': [
        'us-docker.pkg.dev/osdfir-registry/timesketch/timesketch',
    ],
    'plaso': [
        'log2timeline/plaso',
    ],
    'velociraptor': [
        # Locally-built image; tag follows the version pin.
        'velociraptor-server',
    ],
    'volweb': [
        'forensicxlab/volweb-backend',
        'forensicxlab/volweb-frontend',
    ],
    'elk': [
        'docker.elastic.co/elasticsearch/elasticsearch',
        'docker.elastic.co/kibana/kibana',
        'docker.elastic.co/logstash/logstash',
    ],
    'prowler': [
        'toniblyx/prowler',
    ],
    'o365rc': [
        'anssi/dfir-o365rc',
    ],
}


def remove_old_module_image(module_id: str, old_version: str,
                              new_version: str, logger: Callable = None) -> None:
    """Remove `<repo>:<old_version>` for every repo associated with the
    module — called AT THE END of a successful upgrade_*_offline run.

    Safety guarantees:
      * Noop when old_version == new_version (no-op upgrade).
      * Noop when old_version is empty / 'unknown' (first install,
        nothing prior to clean).
      * `docker image rm` itself refuses to remove an image that's
        attached to a running container — so even if our orchestration
        somehow called this in the wrong order, Docker's own protection
        prevents disaster.
      * Errors are swallowed and logged at info level — a failure to
        clean up is never reason to fail the upgrade.

    The user requested this on 2026-06-09 after seeing several GB of
    obsolete module images pile up on the host post-upgrade. Earlier
    iteration shipped a manual Maintenance UI card; user preferred
    fully-automatic cleanup of OLD versions on successful upgrade and
    asked for the manual card to be removed.
    """
    log = logger or (lambda msg, level="info": None)
    if not old_version:
        return
    if old_version.lower() in ('unknown', 'none', ''):
        return
    if new_version and old_version == new_version:
        return
    repos = _MODULE_IMAGE_REPOS.get(module_id)
    if not repos:
        return
    for repo in repos:
        old_ref = f"{repo}:{old_version}"
        result = run_command(
            f"docker image rm {old_ref}",
            logger=None, timeout=60,
        )
        if result.get('success'):
            log(f"  Cleaned up old image: {old_ref}", "info")
        else:
            # Common benign cases: tag was never pulled locally,
            # or it's still referenced by something else (Docker
            # protects). Don't log loudly.
            err = (result.get('error') or result.get('stderr') or '').strip()
            if 'No such image' not in err and 'is using' not in err:
                log(f"  Could not remove old image {old_ref}: {err[:120]}", "info")


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


def set_module_enabled_in_config(module_name: str, logger=None) -> bool:
    """Flip ``modules.<module_name>.enabled`` to ``true`` in config.yaml.

    Used by the on-demand module upgraders (Prowler / DFIR-O365RC) so that
    an online or offline upgrade through the dashboard also marks the
    module as enabled — matching what install.sh would do if the operator
    had set enabled: true before re-running it. Without this the
    upgrade pulls the image and pins the .env but the sidebar and the
    runtime is_module_enabled() gate still say "disabled", so the
    module never shows up in the UI.

    Targeted regex replacement preserves comments and YAML structure
    (a yaml.dump round-trip strips both). Returns True if a flip
    happened, False if the module was already enabled, the key wasn't
    found, or config.yaml is missing.
    """
    import re
    log = logger or (lambda msg, level="info": None)
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        log(f"config.yaml not found at {config_path}; skipping enable flip", "warning")
        return False
    try:
        with open(config_path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False
    # Indent-aware match: modules.<name>: on one line, then enabled: false
    # on the next. Tolerates true/True/false/False capitalisation.
    pattern = re.compile(
        rf'(^(\s+){re.escape(module_name)}:\s*\n\s+enabled:\s+)(false|False)',
        re.MULTILINE,
    )
    new_content, n = pattern.subn(r'\1true', content, count=1)
    if n == 0:
        # Either the module isn't in config.yaml or it's already enabled.
        return False
    try:
        with open(config_path, 'w') as f:
            f.write(new_content)
        log(f"Marked modules.{module_name}.enabled = true in config.yaml", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


def set_module_version_in_config(module_key: str, new_version: str,
                                   logger=None) -> bool:
    """Rewrite ``versions.<module_key>`` in config.yaml.

    Modeled exactly on :func:`set_module_enabled_in_config` above —
    surgical regex replacement on the YAML text so comments, ordering,
    and operator-local edits (passwords, enabled flags, domain) stay
    byte-identical. A yaml.safe_load+yaml.safe_dump round-trip would
    strip all of those, which is why we don't use it.

    ``module_key`` is the KEY inside the ``versions:`` block (e.g.
    ``backend`` for intact, ``velociraptor``, ``elk``). The key map
    in :func:`get_latest_versions` documents the
    module-id-to-yaml-key mapping that the caller should already have
    applied before calling us.

    Returns ``True`` if a write happened, ``False`` if the module key
    wasn't found, the version was already identical, or the file is
    missing/unwritable. Same partial-failure safety as the enabled
    flip: never raises into the dispatcher.
    """
    import re
    log = logger or (lambda msg, level="info": None)
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        log(f"config.yaml not found at {config_path}; skipping version bump", "warning")
        return False
    try:
        with open(config_path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False

    # Match `  <key>: <ver>` ONLY inside the top-level `versions:` block.
    # The trick: lookbehind for `^versions:` (or a less-indented top-
    # level key) is awkward in Python's re without `regex` package, so
    # we instead bound the match by snapping to the versions block
    # explicitly. The pattern:
    #
    #   (^versions:\s*\n(?:[ \t]+.*\n)*?)   ← header + zero or more
    #                                        deeper-indented lines
    #   ([ \t]+<key>:\s*['"]?)               ← the key line, prefix
    #   [^\n'"#]+                            ← old value
    #   (['"]?\s*(?:#.*)?$)                  ← optional quote + comment + EOL
    #
    # The first group is reflowed verbatim; group 2 carries the
    # original indent + quote style; group 3 preserves trailing
    # comments. Only the value between them gets replaced.
    pattern = re.compile(
        rf"(^versions:\s*\n(?:[ \t]+.*\n)*?)([ \t]+{re.escape(module_key)}:\s*(['\"]?))[^\n'\"#]+((['\"]?)\s*(?:#.*)?$)",
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        log(f"versions.{module_key} not found in config.yaml; skipping bump", "info")
        return False

    # If the line already carries this exact version, do nothing — keeps
    # the file mtime stable on no-op upgrades.
    current_line = match.group(0)
    current_value_match = re.search(
        rf"{re.escape(module_key)}:\s*(['\"]?)([^'\"#\n]+)(['\"]?)",
        current_line,
    )
    if current_value_match and current_value_match.group(2).strip() == new_version:
        return False

    # Group 3 / 5 are the opening / closing quote pair. Use group 3's
    # value (the one that exists) as the quote style for the new value.
    open_q = match.group(3) or ''
    new_line = match.group(2) + new_version + match.group(4)
    new_content = content[:match.start()] + match.group(1) + new_line + content[match.end():]

    try:
        with open(config_path, 'w') as f:
            f.write(new_content)
        log(f"Bumped versions.{module_key} → {new_version} in config.yaml", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


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

    # On-demand modules (Prowler / DFIR-O365RC) have no long-running
    # container — the install signal is the .env pin written by their
    # upgrade functions. When the pin is missing the module has never
    # been deployed, so report 'Not installed' (matching the dashboard
    # vocabulary) instead of the bare 'unknown' fallback. This keeps the
    # VERSION SUMMARY accurate for both "fresh install" runs and "upgrade
    # from X to Y" runs.
    prowler_version = backend_vars.get('PROWLER_VERSION', '').strip()
    versions['prowler'] = {
        'current': prowler_version if prowler_version else 'Not installed',
        'env_file': backend_env,
    }
    o365rc_version = backend_vars.get('DFIR_O365RC_VERSION', '').strip()
    versions['o365rc'] = {
        'current': o365rc_version if o365rc_version else 'Not installed',
        'env_file': backend_env,
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
        'prowler':      'prowler',
        'o365rc':       'o365rc',
        'intact':       'backend',
        # VolWeb (memory-forensics analysis stack). Single
        # `versions.volweb` pin drives both backend + frontend images
        # (forensicxlab releases them in lockstep — same semver tag,
        # same release date). Postgres + Redis are infrastructure deps
        # — not pinned in config.yaml; the compose file defaults them
        # via ${VAR:-x}.
        'volweb':       'volweb',
    }
    fallback = {
        'elk': '9.3.3',
        'timesketch': '20260326',
        'plaso': '20260119',
        'iris': 'v2.4.27',
        'velociraptor': '0.76.5',
        'prowler': '5.28.1',
        'o365rc': 'latest',
        'intact': '1.0.0',
        'volweb': '3.16.0',
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

    # Disk-space check before docker load. The tar size is roughly
    # equal to what docker load needs on /var/lib/docker (Docker's
    # layers are already gzip-compressed inside the tar; load
    # extracts them into the storage driver's filesystem). Add a
    # 1.5× margin since the extracted layers can grow slightly with
    # overlay metadata.
    try:
        tar_size = os.path.getsize(image_tar)
        required = int(tar_size * 1.5)
        # Probe /var/lib/docker via the docker daemon's mountpoint —
        # we run inside a backend container so checking our own /
        # would be wrong. Fall back to the tar's own volume if the
        # docker socket query fails.
        free_bytes = shutil.disk_usage(os.path.dirname(image_tar)).free
        if free_bytes < required:
            tar_human = f"{tar_size // (1024 * 1024)} MB"
            need_human = f"{required // (1024 * 1024)} MB"
            have_human = f"{free_bytes // (1024 * 1024)} MB"
            err = (
                f"Not enough free space to load {os.path.basename(image_tar)}: "
                f"tar is {tar_human}, docker load needs ~{need_human} "
                f"(tar × 1.5), have {have_human}. Free disk and retry."
            )
            log(f"  {err}", "error")
            return {"success": False, "error": err}
    except (FileNotFoundError, OSError) as e:
        log(f"  Disk-space preflight skipped: {e}", "warning")

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

    # Pre-extract integrity check. Catches archives that were
    # produced corrupt by an old prepare (pre-`gzip -t` fix) or
    # truncated in transit during upload. Without this, the operator
    # sees a raw zlib `Error -3 while decompressing data: invalid
    # code lengths set` mid-extraction with no actionable message.
    # `gzip -t` reads the whole file and validates every deflate
    # block — corrupt archives fail HERE with a clear instruction
    # to re-prepare, before we touch the filesystem.
    log("Verifying package integrity (gzip -t)...", "info")
    import subprocess as _subprocess
    verify = _subprocess.run(
        ["gzip", "-t", package_path],
        capture_output=True, text=True,
    )
    if verify.returncode != 0:
        err = (verify.stderr or "").strip() or "gzip integrity check failed"
        return {
            "success": False,
            "error": (
                f"Uploaded package failed gzip integrity check: {err[:200]}. "
                "The archive is corrupt. Re-prepare the package on the "
                "source machine and re-upload."
            ),
        }
    log("  Integrity OK", "success")

    log("Extracting upgrade package...", "info")

    # Use /app/data/tmp/ (mounted from host's data/) for persistence across container restarts
    # This is critical for Phase 2 to find the extracted files after backend restarts
    os.makedirs("/app/data/tmp", exist_ok=True)
    extract_dir = f"/app/data/tmp/intact-upgrade-{int(time.time())}"
    os.makedirs(extract_dir, exist_ok=True)

    # Disk-space check before extraction. tar.gz of image bundles
    # compresses to roughly 1/3 of the uncompressed size (Docker
    # images are already gzip'd layers internally, so compression
    # ratio is modest). Use 3× as the required-free estimate with a
    # bit of headroom — apologetic underestimate beats letting an
    # in-flight extractall fill the disk and leave a half-extracted
    # carcass behind.
    try:
        package_size = os.path.getsize(package_path)
        required = int(package_size * 3)
        free_bytes = shutil.disk_usage(extract_dir).free
        if free_bytes < required:
            shutil.rmtree(extract_dir, ignore_errors=True)
            from_human = f"{package_size // (1024 * 1024)} MB"
            need_human = f"{required // (1024 * 1024)} MB"
            have_human = f"{free_bytes // (1024 * 1024)} MB"
            return {
                "success": False,
                "error": (
                    f"Not enough free space in {extract_dir} for extraction. "
                    f"Package is {from_human}, extracted size needs ~{need_human} "
                    f"(package × 3), have {have_human} free. Free disk and retry."
                ),
            }
    except (FileNotFoundError, OSError) as e:
        log(f"  Disk-space preflight skipped: {e}", "warning")

    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            # TAR-SLIP defense (Mythos finding #7). Reject any member
            # whose name starts with `/` or contains `..` — neither
            # appears in legitimate IntactAI upgrade packages produced
            # by `prepare_package`. The check covers BOTH forward-
            # and back-slash path separators to defeat the Windows-
            # archive variant. Without this, a crafted tarball with a
            # member like `../../../etc/cron.d/evil` would write
            # outside `extract_dir` on apply, escalating to persistent
            # RCE on the host. The check runs INSIDE
            # `verify_upgrade_package` because every apply path
            # funnels through here — one place to enforce, every
            # caller protected.
            for m in tar.getmembers():
                name = m.name
                if not name:
                    continue
                if name.startswith('/') or name.startswith('\\'):
                    raise RuntimeError(
                        f"package contains absolute-path member ({name!r}) "
                        f"— refusing to extract"
                    )
                parts = name.replace('\\', '/').split('/')
                if '..' in parts:
                    raise RuntimeError(
                        f"package contains path-traversal member ({name!r}) "
                        f"— refusing to extract"
                    )
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
    For container-based modules, queries `docker ps -a`. For on-demand
    modules (prowler / o365rc) with no container concept, falls back to
    "is the .env version pin present?" — that's the equivalent install
    signal so the dispatcher can correctly label fresh-install runs as
    INSTALLING instead of UPGRADING. Returns None for plaso (no .env pin
    of its own; lives inside the backend .env)."""
    name = _MODULE_PRIMARY_CONTAINERS.get(module_id)
    if name:
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f'name=^{name}$',
                 '--format', '{{.Names}}'],
                capture_output=True, text=True, timeout=5,
            )
            return name in (result.stdout or '')
        except Exception:
            return None
    # On-demand modules: read the matching .env pin. Both prowler and
    # DFIR-O365RC keep their version in the backend .env.
    on_demand_env_keys = {
        'prowler': 'PROWLER_VERSION',
        'o365rc':  'DFIR_O365RC_VERSION',
    }
    env_key = on_demand_env_keys.get(module_id)
    if not env_key:
        return None
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    try:
        vars_ = read_env_file(backend_env)
        return bool(vars_.get(env_key, '').strip())
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


def load_all_bundled_images(package_dir: str, logger: Callable = None,
                              run_id: str = None) -> None:
    """Load EVERY .tar in `package_dir/images/`. Idempotent — `docker
    load` of an already-loaded image is a no-op, so calling this
    multiple times in a multi-module apply is harmless.

    Air-gap-bulletproof by design: when a module's docker-compose.yaml
    references an image (e.g. `postgres:15`, `redis:7-alpine`,
    `nginx:alpine`, `opensearchproject/opensearch:2.11.0`), the prepare
    side bundles its tar into `/images/`. At install time we just load
    everything in the directory — no per-module prefix allowlist
    needed. Adding a new image to ANY module's compose only requires
    updating DOCKER_IMAGES in package.py (or, future work, deriving
    from the compose file itself); the install side picks it up
    automatically.

    Before this helper, install_module_compose_up matched bundled tars
    against per-module `image_tar_prefixes` lists. That coupled the
    install side to the prepare side's filename conventions and any
    drift caused silent fallback to `docker pull` → air-gap failure
    when compose tried to fetch the missing image from the registry.
    Air-gap testing on 2026-06-09 surfaced this on Velociraptor (prefix
    `velociraptor-server` vs filename `velociraptor-{version}.tar`)
    and would have surfaced it on ELK (missing `logstash` prefix),
    Timesketch (missing all four base-image prefixes), and VolWeb
    (postgres+redis not even bundled). Loading every tar removes
    the failure mode by construction.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    images_dir = os.path.join(package_dir, 'images')
    if not os.path.isdir(images_dir):
        return
    for fn in sorted(os.listdir(images_dir)):
        if not fn.endswith('.tar'):
            continue
        image_tar = os.path.join(images_dir, fn)
        log(f"  Loading bundled image: {fn}", "info")
        loaded = load_docker_image(image_tar, logger=log, run_id=run_id)
        if not loaded.get('success'):
            log(
                f"  Image load failed ({fn}, continuing — compose will "
                f"try to pull): {loaded.get('error')}",
                "warning",
            )


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
    secret generation) layer that BEFORE calling this helper.

    NOTE: image_tar_prefixes is retained as a kwarg for backward-compat
    with callers that haven't been updated, but it is IGNORED. The
    helper now loads EVERY .tar in /images/ via
    load_all_bundled_images — see that function's docstring for the
    air-gap-bulletproofing rationale.
    """
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

    # Load every bundled image. See load_all_bundled_images docstring
    # for why we load ALL tars, not just module-specific ones.
    load_all_bundled_images(package_dir, logger=log, run_id=run_id)

    # The docker CLI we exec'd against /var/run/docker.sock sees the host
    # filesystem, not the container's — translate WORKDIR → HOST_PATH.
    host_work_dir = work_dir.replace(WORKDIR, HOST_PATH, 1)
    log(f"  docker compose up -d on {module_id}...", "info")
    # CRITICAL: --pull never. Without it, docker compose 2.x interprets
    # a compose service that has BOTH `image:` and `build:` (the
    # velociraptor case) plus `pull_policy: build` as "force a rebuild
    # every up", which then tries to `FROM ubuntu:22.04` and fails
    # air-gapped with "failed to fetch anonymous token". With
    # --pull never, compose uses the locally-loaded image (which
    # load_all_bundled_images put in place) and skips the rebuild
    # entirely. Air-gap testing on 2026-06-09 verified this is the
    # specific knob that flips velociraptor install from broken to
    # working in an air-gapped environment. The pre-existing
    # `upgrade_*_offline` paths already pass --pull never for the
    # same reason; only the install helper was missing it.
    r = run_command(
        f"docker compose -f {host_work_dir}/docker-compose.yaml "
        f"--project-directory {host_work_dir} up -d --pull never",
        timeout=300, logger=log, run_id=run_id,
    )
    if not r.get('success'):
        return {"success": False, "error": f"compose up failed: {r.get('error')}"}

    log(f"{module_id} first-time install complete", "success")
    return {"success": True, "version": version, "first_install": True}
