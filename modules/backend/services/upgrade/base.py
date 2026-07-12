#!/usr/bin/env python3
"""
Base utilities for upgrade operations.
Shared functions used across all module upgrade files.
"""

import os
import re
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


# Upgrade staging dirs (data/tmp/intact-upgrade-<ts>) are created by BOTH the
# offline apply (verify_upgrade_package extracts here) and the online flow
# (prepare_upgrade_package builds here) and MUST survive the mid-upgrade backend
# restart so Phase 2 can finish. Phase 2 removes its own dir in a `finally`, but
# if Phase 2 never completes (crash, failed resume, killed by the restart) the
# multi-GB dir is orphaned. This sweep — run at the START of every new upgrade —
# reclaims those orphans regardless of how the prior run ended. Age-guarded so it
# can never touch the current run's freshly-created dir.
_UPGRADE_STAGING_GLOBS = ("/app/data/tmp/intact-upgrade-*", "/tmp/intact-upgrade-*")


def sweep_stale_upgrade_staging(logger: Callable = None, max_age_hours: float = 2.0) -> int:
    """Remove leftover intact-upgrade-* staging dirs older than ``max_age_hours``.
    Returns the number removed. Safe: only dirs, only older than the cutoff (the
    current run's dir is seconds old), errors swallowed per-dir."""
    import glob
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    for pattern in _UPGRADE_STAGING_GLOBS:
        for d in glob.glob(pattern):
            try:
                if os.path.isdir(d) and os.path.getmtime(d) < cutoff:
                    shutil.rmtree(d, ignore_errors=True)
                    removed += 1
                    log(f"  Swept stale upgrade staging: {d}", "info")
            except OSError as e:
                log(f"  Could not sweep {d}: {e}", "warning")
    if removed:
        log(f"Reclaimed {removed} stale upgrade staging dir(s) from prior runs", "info")
    return removed


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


def set_module_block_in_config(module_name: str, block: dict, logger=None) -> bool:
    """Insert a fresh ``modules.<module_name>`` block into config.yaml.

    Closes the new-module gap: when a future release ships a module the
    operator's local config.yaml doesn't yet know about (e.g. v3.0 adds
    ``auditd``), the install function later goes to read
    ``modules.auditd`` for credentials and finds nothing — falling back
    to whatever hardcoded defaults the install function carries.

    This helper writes the missing block into the operator's local file
    so the install function reads from a real source AND the operator
    can see/edit the module's settings in their file like every other
    module.

    Behavior:

    * **Idempotent.** If ``modules.<name>`` already exists in local
      config.yaml, do nothing — the operator's local version wins. We
      never overwrite a hand-customised block.
    * **Targeted insert.** Walks the file line-by-line, finds the end of
      the ``modules:`` block (first top-level key after it, or EOF),
      and inserts the new mapping at that boundary. Everything else
      (comments, ordering, operator-local password edits, the
      ``versions:`` block) stays byte-identical.

    Returns ``True`` if a write happened, ``False`` if the block was
    already present, the input block was empty, or the file is
    missing/unwritable.
    """
    import re
    log = logger or (lambda msg, level="info": None)
    if not block:
        return False
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        log(f"config.yaml not found at {config_path}; skipping module block insert", "warning")
        return False
    try:
        with open(config_path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False

    # Already present at any indent? Skip — operator's version wins.
    if re.search(rf'^[ \t]+{re.escape(module_name)}:[\s]*$', content, re.MULTILINE):
        return False

    # Find the modules: block boundaries by walking lines. The block
    # starts at a line `modules:` (top-level, no leading whitespace) and
    # ends at the next line that's also top-level (or EOF). Comments
    # and blank lines INSIDE the block are part of it.
    lines = content.split('\n')
    modules_start = None
    insert_idx = None  # we'll insert BEFORE this index
    for i, line in enumerate(lines):
        if modules_start is None:
            if re.match(r'^modules:\s*$', line):
                modules_start = i
            continue
        # Inside the modules block; look for the boundary.
        stripped = line.strip()
        if not stripped:
            # blank lines belong to whichever block surrounds them; keep going
            continue
        if line.startswith(' ') or line.startswith('\t') or stripped.startswith('#'):
            # still inside the block (indented child OR a comment)
            continue
        # Top-level non-blank line — modules: block has ended.
        insert_idx = i
        break
    if modules_start is None:
        log("config.yaml has no top-level 'modules:' block; cannot insert "
            f"modules.{module_name}", "warning")
        return False
    if insert_idx is None:
        # Block runs to EOF — append at the very end.
        insert_idx = len(lines)

    # Format the new block. 2-space indent matches what install.sh +
    # config.yaml's existing entries use. String values quoted with
    # single quotes to match the existing style; booleans rendered
    # lowercase (true/false) to stay YAML-conventional.
    indent = '  '
    new_lines = [f'{indent}{module_name}:']
    for k, v in block.items():
        if isinstance(v, bool):
            new_lines.append(f'{indent}{indent}{k}: {str(v).lower()}')
        elif isinstance(v, (int, float)):
            new_lines.append(f'{indent}{indent}{k}: {v}')
        elif v is None:
            new_lines.append(f'{indent}{indent}{k}: null')
        else:
            # string — quote with single quotes; escape any embedded
            # single quotes by YAML doubling convention ('' inside '...')
            s = str(v).replace("'", "''")
            new_lines.append(f"{indent}{indent}{k}: '{s}'")

    # Ensure separation between the new block and what follows. If we're
    # inserting before a top-level key (not EOF), drop a blank line first
    # so it doesn't visually merge with the next section.
    insert_payload = new_lines[:]
    if insert_idx < len(lines):
        insert_payload.append('')  # blank line before the next top-level key

    lines[insert_idx:insert_idx] = insert_payload
    new_content = '\n'.join(lines)

    try:
        with open(config_path, 'w') as f:
            f.write(new_content)
        log(f"Inserted modules.{module_name} block into config.yaml "
            f"({len(block)} keys)", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


def set_module_enabled_in_config(module_name: str, logger=None) -> bool:
    """Flip ``modules.<module_name>.enabled`` to ``true`` in config.yaml.

    Used by the on-demand module upgraders (CloudTrail / DFIR-O365RC) so that
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


def ensure_module_enabled_in_config(module_name: str, default_block: dict = None,
                                    logger=None) -> bool:
    """Guarantee ``modules.<module_name>`` exists AND is enabled.

    This is the "if a module was added, also enable it" rule for upgrades:
    when an upgrade introduces a module the operator's local config.yaml
    doesn't have yet, we must both *create* the block and mark it
    ``enabled: true`` — otherwise the image/data ships but the sidebar +
    runtime ``is_module_enabled()`` gate keep it hidden.

    Two cases, in order:

    1. **Block missing** → splice a fresh block via
       :func:`set_module_block_in_config`, forcing ``enabled: true``
       (operator chose to add the module, so it should be visible). When
       ``default_block`` carries upstream credentials they're preserved,
       but ``enabled`` is always overridden to ``true``.
    2. **Block present** → leave the operator's block untouched except
       flip ``enabled: false → true`` via
       :func:`set_module_enabled_in_config`. An already-enabled block is
       a no-op.

    Returns ``True`` if config.yaml was written (block created or enabled
    flipped), ``False`` if nothing changed (already present + enabled, or
    the file is missing/unwritable).
    """
    log = logger or (lambda msg, level="info": None)
    block = dict(default_block or {})
    block['enabled'] = True  # added module is always enabled
    # set_module_block_in_config is idempotent — returns False (no write)
    # when the block already exists, so we then fall through to the
    # enable flip for the existing-but-disabled case.
    if set_module_block_in_config(module_name, block, logger=log):
        return True
    return set_module_enabled_in_config(module_name, logger=log)


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

    # Replace the value of `  <module_key>: ...` INSIDE the top-level
    # `versions:` block, with a LINEAR line scan.
    #
    # The previous implementation used a single multi-line regex with a
    # `(?:[ \t]+.*\n)*?` segment that CATASTROPHICALLY BACKTRACKED — 100% CPU,
    # forever — whenever <module_key> was ABSENT from the block. That is exactly
    # what happens for intact (module_key='backend') now that the `backend`
    # pin was dropped from config.yaml: the intact online-upgrade step called
    # this with a key the regex could never find, the regex backtracked
    # exponentially, pegged the GIL, and wedged the whole backend mid-upgrade.
    #
    # A line scan can't backtrack and fails fast on a missing key. Comments /
    # ordering / operator-local edits stay byte-identical; only the one value
    # gets rewritten.
    key_line_re = re.compile(
        rf"^(\s+{re.escape(module_key)}:\s*)(['\"]?)([^'\"#\n]*?)(['\"]?)(\s*(?:#.*)?)$"
    )
    out_lines = []
    in_versions = False
    changed = False
    for line in content.splitlines(keepends=True):
        body = line.rstrip("\n")
        if not changed:
            if re.match(r"^versions:\s*(#.*)?$", body):
                in_versions = True
            elif in_versions and body and not body[0].isspace():
                in_versions = False  # next top-level key — left the versions block
            elif in_versions:
                m = key_line_re.match(body)
                if m:
                    if m.group(3).strip() == new_version:
                        return False  # already that version — keep mtime stable
                    nl = "\n" if line.endswith("\n") else ""
                    line = f"{m.group(1)}{m.group(2)}{new_version}{m.group(4)}{m.group(5)}{nl}"
                    changed = True
        out_lines.append(line)

    if not changed:
        log(f"versions.{module_key} not found in config.yaml; skipping bump", "info")
        return False

    new_content = "".join(out_lines)

    try:
        with open(config_path, 'w') as f:
            f.write(new_content)
        log(f"Bumped versions.{module_key} → {new_version} in config.yaml", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


# ---------------------------------------------------------------------------
# Structural rename / delete helpers for config-schema migrations.
#
# Same discipline as the setters above: LINE-SCAN over the YAML text (never a
# whole-file regex — see the catastrophic-backtracking note in
# set_module_version_in_config — and never a yaml load+dump, which would strip
# comments/ordering/operator creds). Each is idempotent so a migration can
# re-run safely. All accept an optional `config_path` override so the migration
# runner (and unit tests) can point them at an explicit file; default is
# WORKDIR/config.yaml like the other helpers.
# ---------------------------------------------------------------------------

def _module_header_present(content: str, name: str) -> bool:
    import re
    return re.search(rf'^[ \t]+{re.escape(name)}:\s*(?:#.*)?$', content,
                     re.MULTILINE) is not None


def delete_module_block_in_config(module_name: str, logger=None,
                                   config_path: str = None) -> bool:
    """Remove the entire ``modules.<module_name>`` block (header + child lines).

    Idempotent: returns False if the block is absent. Line-scan; the block runs
    from its ``  <name>:`` header to the next line at the same-or-lower indent
    that isn't blank (a sibling module, or the next top-level key). Trailing
    blank lines inside that span are removed with it.
    """
    import re
    log = logger or (lambda msg, level="info": None)
    path = config_path or os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(path):
        log(f"config.yaml not found at {path}; skipping module delete", "warning")
        return False
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False

    lines = content.split('\n')
    in_modules = False
    start = None
    header_indent = None
    end = len(lines)
    for i, line in enumerate(lines):
        if not in_modules:
            if re.match(r'^modules:\s*$', line):
                in_modules = True
            continue
        stripped = line.strip()
        # left the modules: block entirely (top-level, non-blank, non-comment)?
        if stripped and not line[:1].isspace() and not stripped.startswith('#'):
            if start is not None:
                end = i
            break
        if start is None:
            m = re.match(rf'^(\s+){re.escape(module_name)}:\s*(?:#.*)?$', line)
            if m:
                start = i
                header_indent = len(m.group(1))
            continue
        # inside the target block: boundary is next non-blank line whose indent
        # is <= the header's (a sibling module or a module-indent comment).
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent:
            end = i
            break

    if start is None:
        return False

    del lines[start:end]
    try:
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        log(f"Removed modules.{module_name} block from config.yaml", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


def rename_module_in_config(old_name: str, new_name: str, logger=None,
                             config_path: str = None) -> bool:
    """Rename ``modules.<old_name>`` -> ``modules.<new_name>``, carrying ALL
    child lines (enabled/id/password/...) verbatim — only the header key token
    is rewritten, so children, comments and ordering stay byte-identical.

    Idempotent:
      * ``modules.<new_name>`` already present -> drop a stale ``<old_name>``
        block if one remains, else no-op.
      * ``<old_name>`` absent -> no-op (False).
    """
    import re
    log = logger or (lambda msg, level="info": None)
    path = config_path or os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(path):
        log(f"config.yaml not found at {path}; skipping module rename", "warning")
        return False
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False

    has_new = _module_header_present(content, new_name)
    has_old = _module_header_present(content, old_name)
    if has_new:
        if has_old:  # stale duplicate — clean it up so the rename is idempotent
            return delete_module_block_in_config(old_name, logger=logger, config_path=path)
        return False
    if not has_old:
        log(f"modules.{old_name} not found; nothing to rename", "info")
        return False

    lines = content.split('\n')
    in_modules = False
    changed = False
    header_re = re.compile(rf'^(\s+){re.escape(old_name)}:(\s*(?:#.*)?)$')
    for i, line in enumerate(lines):
        if not in_modules:
            if re.match(r'^modules:\s*$', line):
                in_modules = True
            continue
        stripped = line.strip()
        if stripped and not line[:1].isspace() and not stripped.startswith('#'):
            break  # left the modules: block
        m = header_re.match(line)
        if m:
            lines[i] = f'{m.group(1)}{new_name}:{m.group(2)}'
            changed = True
            break
    if not changed:
        return False
    try:
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        log(f"Renamed modules.{old_name} -> modules.{new_name} in config.yaml", "info")
        return True
    except Exception as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


def rename_version_key_in_config(old_key: str, new_key: str, logger=None,
                                  config_path: str = None) -> bool:
    """Rename ``versions.<old_key>`` -> ``versions.<new_key>`` inside the
    ``versions:`` block, preserving the value and any inline comment. Only the
    key token is rewritten. The trailing ``:`` anchor prevents a prefix collision
    (renaming ``volweb`` never touches ``volweb_postgres``).

    Idempotent:
      * ``<old_key>`` absent -> no-op (False).
      * both present -> drop the old line (new already exists).
    """
    import re
    log = logger or (lambda msg, level="info": None)
    path = config_path or os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(path):
        log(f"config.yaml not found at {path}; skipping version-key rename", "warning")
        return False
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "warning")
        return False

    lines = content.splitlines(keepends=True)
    old_re = re.compile(rf'^(\s+){re.escape(old_key)}(:\s*.*)$')
    new_re = re.compile(rf'^\s+{re.escape(new_key)}:\s')

    # Pass 1: presence of old/new INSIDE the versions: block.
    in_v = False
    has_old = has_new = False
    for line in lines:
        body = line.rstrip('\n')
        if re.match(r'^versions:\s*(#.*)?$', body):
            in_v = True
            continue
        if in_v and body and not body[:1].isspace():
            in_v = False
        if in_v:
            if old_re.match(body):
                has_old = True
            if new_re.match(body):
                has_new = True
    if not has_old:
        log(f"versions.{old_key} not found; nothing to rename", "info")
        return False

    # Pass 2: rewrite the key token (or drop the old line if new already exists).
    out = []
    in_v = False
    done = False
    for line in lines:
        body = line.rstrip('\n')
        emit = True
        if not done:
            if re.match(r'^versions:\s*(#.*)?$', body):
                in_v = True
            elif in_v and body and not body[:1].isspace():
                in_v = False
            elif in_v:
                m = old_re.match(body)
                if m:
                    if has_new:
                        emit = False  # duplicate — new already present
                    else:
                        nl = '\n' if line.endswith('\n') else ''
                        line = f'{m.group(1)}{new_key}{m.group(2)}{nl}'
                    done = True
        if emit:
            out.append(line)
    try:
        with open(path, 'w') as f:
            f.write(''.join(out))
        log(f"Renamed versions.{old_key} -> versions.{new_key} in config.yaml", "info")
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

    # Helper: is the on-demand module enabled in operator's local
    # config.yaml? install.sh seeds PLASO_VERSION / CLOUDTRAIL_VERSION /
    # DFIR_O365RC_VERSION into backend's .env unconditionally (the
    # backend code path needs the constants regardless), so a pinned
    # version in .env does NOT mean the operator opted into the
    # module. We must ALSO check the modules.<name>.enabled flag.
    # Discovered when an operator did a backend+cve-only install and
    # the Online Upgrade modal incorrectly listed plaso/cloudtrail/o365rc
    # as "installed → upgrade automatically" — they'd never agreed
    # to deploy any of those.
    def _ondemand_enabled(name: str) -> bool:
        try:
            import yaml as _yaml
            with open(os.path.join(WORKDIR, 'config.yaml')) as f:
                cfg = _yaml.safe_load(f) or {}
            mods = cfg.get('modules') or {}
            entry = mods.get(name) or {}
            return bool(entry.get('enabled'))
        except Exception:
            # If config.yaml is unreadable / missing, fall back to
            # "treat as enabled" — better to surface a phantom row in
            # the upgrade plan than to silently hide a module that's
            # actually being used.
            return True

    # Plaso pin lives in the backend .env (no standalone container).
    # Plaso is a SEPARATE module from Timesketch (yes they run in the
    # same automation, but plaso can be invoked standalone for other
    # forensic work and timesketch can ingest pre-parsed events
    # without plaso). It has its own `modules.plaso.enabled` flag.
    # 'Not installed' when the .env pin is blank OR plaso is disabled
    # (or absent) in the operator's modules block.
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    backend_vars = read_env_file(backend_env)
    plaso_version = backend_vars.get('PLASO_VERSION', '').strip()
    if not _ondemand_enabled('plaso'):
        plaso_version = ''
    versions['plaso'] = {
        'current': plaso_version if plaso_version else 'Not installed',
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

    # On-demand/native modules (CloudTrail / DFIR-O365RC) have no long-running
    # container — the install signal is the .env pin AND the
    # modules.<name>.enabled flag in config.yaml. install.sh seeds the
    # .env pin regardless of the operator's choice (backend code path
    # needs the constants), so the enabled-flag gate is mandatory —
    # otherwise a backend-only install incorrectly classifies these as
    # "installed → upgrade automatically".
    cloudtrail_version = backend_vars.get('CLOUDTRAIL_VERSION', '').strip()
    if not _ondemand_enabled('cloudtrail'):
        cloudtrail_version = ''
    versions['cloudtrail'] = {
        'current': cloudtrail_version if cloudtrail_version else 'Not installed',
        'env_file': backend_env,
    }
    o365rc_version = backend_vars.get('DFIR_O365RC_VERSION', '').strip()
    if not _ondemand_enabled('o365rc'):
        o365rc_version = ''
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
        'cloudtrail':   'cloudtrail',
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
        'cloudtrail': '2026.04',
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
        # Generic: also surface any NEW module in the modules: block that has a
        # version pin but isn't in the (legacy) key map above — so a new module
        # in config.yaml appears without editing this map. Infra modules with no
        # upgrade handler (portainer) are skipped; transitive sidecar pins live
        # only in versions: (not modules:) so they're naturally excluded.
        for name in (cfg.get('modules') or {}):
            if name in result or name in ('portainer',):
                continue
            val = versions.get(name)
            if val is not None:
                result[name] = str(val)
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


def preflight_offline_images(module: str, version: str, images_dir: str,
                              logger: Callable = None,
                              run_id: Optional[str] = None) -> Dict:
    """Make a module's PRIMARY images available BEFORE its stack is stopped.

    Fixes the down-then-discover ordering: offline upgraders used to
    `docker compose down` first and only then find that an image tar was
    missing/corrupt — leaving the module DOWN until the compose-up failure
    finally triggered rollback. `docker load` is safe while the old stack
    runs, so do it (and verify) up front:

      for each (image_ref, tar) in package.PRIMARY_IMAGES[module]:
        1. load the tar if present in `images_dir` (idempotent),
        2. `docker image inspect <ref>` — already-present images satisfy
           the check even when the tar wasn't bundled.

    Sidecar/transitive images are NOT checked here — they're stamped from
    the manifest and pre-loaded by load_all_bundled_images, and an absent
    sidecar may legitimately already exist locally.

    Returns {"success": bool, "missing": [image_refs]}. On success the
    caller may safely take the stack down.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .package import PRIMARY_IMAGES  # local import — package.py imports base
    missing = []
    for image_pat, tar_pat in PRIMARY_IMAGES.get(module, []):
        image_ref = image_pat.format(version=version)
        tar_path = os.path.join(images_dir, tar_pat.format(version=version))
        if os.path.exists(tar_path):
            load_docker_image(tar_path, logger=log, run_id=run_id)
        check = run_command(f"docker image inspect {image_ref}",
                            logger=None, timeout=60, run_id=run_id)
        if not check.get('success'):
            missing.append(image_ref)
    if missing:
        log(f"  PRE-CHECK FAILED for {module}: required image(s) not available "
            f"and not loadable from the package: {', '.join(missing)}. "
            f"The running stack was NOT touched.", "error")
        return {"success": False, "missing": missing}
    log(f"  Pre-check OK: all {module} primary images available before stopping the stack", "info")
    return {"success": True, "missing": []}


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

        # Per-file sha256 verification. gzip -t above only proves the OUTER
        # archive isn't corrupt — this catches a truncated/corrupt file
        # INSIDE a gzip-valid archive BEFORE any module is taken down.
        # Older packages have no sha256 block — skip (back-compat).
        sha_map = (manifest.get('contents') or {}).get('sha256') or {}
        if sha_map:
            import hashlib as _hashlib
            log(f"  Verifying {len(sha_map)} file checksum(s)...", "info")
            bad = []
            for rel, expected in sha_map.items():
                fpath = os.path.join(package_dir, rel)
                if not os.path.isfile(fpath):
                    bad.append(f"{rel} (missing)")
                    continue
                h = _hashlib.sha256()
                with open(fpath, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b''):
                        h.update(chunk)
                if h.hexdigest() != expected:
                    bad.append(f"{rel} (checksum mismatch)")
            if bad:
                err = (f"Package integrity check failed for {len(bad)} file(s): "
                       f"{'; '.join(bad[:5])}"
                       + (f" (+{len(bad)-5} more)" if len(bad) > 5 else "")
                       + ". The package is corrupt — re-prepare/re-upload it. "
                         "No module was touched.")
                log(f"  {err}", "error")
                shutil.rmtree(extract_dir, ignore_errors=True)
                return {"success": False, "error": err}
            log(f"  All {len(sha_map)} checksums verified", "success")
        else:
            log("  Package has no sha256 map (older prepare) — integrity is "
                "archive-level only", "info")

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
    """Get manifest info from an upgrade package without fully extracting.

    Fast path — sidecar manifest. The prepare flow writes
    ``<package>.manifest.json`` next to the tarball at prepare time
    specifically so this function can return in O(1) instead of having
    to scan the entire gzipped tar to find ``manifest.json`` (which
    lives near the END of the archive due to tar/gzip ordering — a
    4.8 GB tarball took 54 s of decompression before this sidecar
    existed).

    Slow fallback path — if no sidecar exists (older packages or
    operator-renamed tarballs), crack the tar open and scan members.
    """
    if not os.path.exists(package_path):
        return {"success": False, "error": "Package not found"}

    sidecar = package_path + '.manifest.json'
    if os.path.isfile(sidecar):
        try:
            with open(sidecar, 'r') as f:
                manifest = json.load(f)
            return {
                "success": True,
                "manifest": manifest,
                "versions": manifest.get('versions', {}),
                "created": manifest.get('created'),
                "contents": manifest.get('contents', {})
            }
        except Exception as e:
            # Sidecar exists but is unreadable. Fall through to the
            # slow path; the tarball is the source of truth anyway.
            print(f"[PACKAGE-INFO] sidecar unreadable ({e}); falling back to tar scan", flush=True)

    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            for member in tar.getmembers():
                if member.name.endswith('manifest.json'):
                    f = tar.extractfile(member)
                    if f:
                        manifest = json.load(f)
                        # Opportunistically write the sidecar now so
                        # subsequent calls are fast even for legacy
                        # tarballs the prepare flow didn't stamp.
                        try:
                            with open(sidecar, 'w') as out:
                                json.dump(manifest, out)
                        except Exception:
                            pass
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
    modules (cloudtrail / o365rc) with no container concept, falls back to
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
    # On-demand/native modules: read the matching .env pin. Both cloudtrail and
    # DFIR-O365RC keep their version in the backend .env.
    on_demand_env_keys = {
        'cloudtrail': 'CLOUDTRAIL_VERSION',
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


def stamp_transitive_env_from_manifest(
    module_id: str,
    package_dir: str,
    logger: Callable = None,
) -> Dict[str, str]:
    """Read the bundled manifest's `contents.transitive_versions.<module_id>`
    block and write each `VAR=tag` pair into modules/<module_id>/.env
    BEFORE `docker compose up` runs.

    This is the apply-side counterpart to the prepare-side's transitive
    bundling. Without this, the compose `${VAR:-default}` references
    would resolve to the static default the compose file shipped with —
    NOT the tag whose image was actually bundled into the package.
    Result: compose tries to pull an unavailable image and the stack
    fails to come up on air-gapped targets.

    Backwards-compatible: pre-refactor packages have no
    `transitive_versions` block in their manifest, so this is a no-op for
    those (the apply continues with whatever the operator's existing
    .env already has).

    Returns: dict of {ENV_VAR: tag} actually written (empty when no
    block in manifest, or when the .env couldn't be located).
    """
    log = logger or (lambda msg, level="info": None)
    manifest_path = os.path.join(package_dir, 'manifest.json')
    if not os.path.isfile(manifest_path):
        return {}
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        log(f"  transitive .env stamp: manifest read failed: {e}",
            "warning")
        return {}

    tv_root = ((manifest.get('contents') or {})
                .get('transitive_versions') or {})
    pins = tv_root.get(module_id) or {}
    if not pins:
        return {}

    env_path = os.path.join(WORKDIR, 'modules', module_id, '.env')
    if not os.path.isfile(env_path):
        # No .env yet — create one. UI-driven fresh-install path doesn't
        # have an .env at this point (install.sh's deploy_* creates it
        # from a template, but the Python install_*_offline functions
        # called by the UI/upload flow rely on this helper to bootstrap
        # the file). Before 2026-06-14 this branch silently returned
        # empty, which combined with the compose `${VAR:?}` rule meant
        # fresh installs crashed at compose-up with "VAR required" —
        # exactly the scenario the operator hit during the timesketch
        # fresh-install test.
        try:
            os.makedirs(os.path.dirname(env_path), exist_ok=True)
            open(env_path, 'a').close()
            log(f"  transitive .env stamp: created empty {env_path} "
                f"for fresh install", "info")
        except Exception as e:
            log(f"  transitive .env stamp: cannot create {env_path} "
                f"({type(e).__name__}: {e}); compose up will fail",
                "warning")
            return {}

    try:
        with open(env_path, 'r') as f:
            lines = f.read().splitlines()
    except Exception as e:
        log(f"  transitive .env stamp: read failed for {env_path}: {e}",
            "warning")
        return {}

    written = {}
    keys_remaining = dict(pins)  # var → tag
    out_lines = []
    for raw in lines:
        line = raw.rstrip('\r')
        # Match `VAR=...` or commented-out `# VAR=...`; rewrite the
        # value while preserving everything else (comments above,
        # blank lines, ordering). The replace_all flag at the bottom
        # handles the "key not yet in file" case.
        m = re.match(r'^\s*(?:#\s*)?([A-Z][A-Z0-9_]*)\s*=', line)
        if m and m.group(1) in keys_remaining:
            var = m.group(1)
            tag = keys_remaining.pop(var)
            out_lines.append(f"{var}={tag}")
            written[var] = tag
        else:
            out_lines.append(line)
    # Append any vars not already present.
    for var, tag in keys_remaining.items():
        out_lines.append(f"{var}={tag}")
        written[var] = tag

    try:
        with open(env_path, 'w') as f:
            f.write('\n'.join(out_lines) + '\n')
    except Exception as e:
        log(f"  transitive .env stamp: write failed for {env_path}: {e}",
            "warning")
        return {}

    log(f"  Stamped transitive pins into {module_id}/.env: " +
        ", ".join(f"{k}={v}" for k, v in written.items()), "info")
    return written


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
