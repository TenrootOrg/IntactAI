#!/usr/bin/env python3
"""Forward-only, idempotent config.yaml schema migrations.

The Alembic-for-config layer. Runs in Phase 2 (new backend code, post-restart)
as a SEPARATE step from the versions-merge, so structural config changes a
release needs (renames, new modules, retired keys) ship as small ordered steps
instead of ad-hoc edits scattered across the upgrade path.

Discipline:
  * Every migration edits config.yaml via the base.py text/line-scan helpers
    (rename_module_in_config, rename_version_key_in_config,
    delete_module_block_in_config, set_module_block_in_config, ...) — NEVER a
    yaml load+dump, which would strip operator comments/ordering/credentials.
  * Every migration is IDEMPOTENT (safe to re-run), so a crash-then-resume in
    Phase 2 can replay it harmlessly.
  * schema_version is bumped AFTER each successful step, so a crash mid-chain
    resumes from the right place; on any failure the whole file is restored
    from a backup taken up front (a partial structural edit can't be reverted
    key-by-key the way the versions-merge revert can).

Backup file uses a DISTINCT suffix (.pre-migration-backup) so it never collides
with the versions-merge's .pre-upgrade-backup, which may co-exist in the same
Phase-2 run.
"""
import os
import re
import shutil
from typing import Callable, List, Tuple

from .base import (
    WORKDIR,
    rename_module_in_config,          # noqa: F401 — available to migrations
    rename_version_key_in_config,     # noqa: F401
    delete_module_block_in_config,    # noqa: F401
    delete_version_key_in_config,     # noqa: F401
)

MIGRATION_BACKUP_SUFFIX = ".pre-migration-backup"


# ---------------------------------------------------------------------------
# schema_version — read/write as a comment-preserving text edit
# ---------------------------------------------------------------------------

def read_schema_version(config_path: str) -> int:
    """Return the top-level ``schema_version:`` int, or 1 when absent.

    The shipped config.yaml historically has no schema_version line, so
    "absent == 1" is the normal legacy path: a legacy file runs the full
    migration chain once, after which set_schema_version writes the line.
    """
    try:
        with open(config_path) as f:
            for line in f:
                m = re.match(r'^schema_version:\s*(\d+)\s*(?:#.*)?$', line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 1


def set_schema_version(config_path: str, value: int, logger: Callable = None) -> bool:
    """Rewrite (or insert) the top-level ``schema_version:`` line, preserving
    everything else. Line-scan. When absent, inserts it as the first top-level
    key (after any leading comment/blank block) so it never lands inside a
    nested block like modules:/versions:.
    """
    log = logger or (lambda m, l="info": None)
    try:
        with open(config_path) as f:
            lines = f.read().split('\n')
    except OSError as e:
        log(f"Could not read config.yaml for schema_version write: {e}", "warning")
        return False

    for i, line in enumerate(lines):
        if re.match(r'^schema_version:\s*\d*\s*(?:#.*)?$', line):
            lines[i] = f'schema_version: {value}'
            return _write_lines(config_path, lines, log)

    # Not present — insert before the first top-level, non-comment content line.
    insert_idx = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith('#'):
            insert_idx = i
            break
    lines[insert_idx:insert_idx] = [f'schema_version: {value}']
    return _write_lines(config_path, lines, log)


def _write_lines(path: str, lines: List[str], log: Callable) -> bool:
    """Atomic write: temp file in the same directory + os.replace, so a crash
    mid-write can never leave a truncated/corrupt config.yaml — the file is
    always either the old or the new content. (The migration runner does
    multiple sequential writes, so this matters more here than in the
    single-write base.py helpers, which are additionally covered by the
    runner's whole-file backup.)"""
    import tempfile
    try:
        d = os.path.dirname(os.path.abspath(path)) or '.'
        fd, tmp = tempfile.mkstemp(prefix='.config.yaml.', dir=d)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write('\n'.join(lines))
            # preserve the original file's mode
            try:
                os.chmod(tmp, os.stat(path).st_mode)
            except OSError:
                pass
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except OSError as e:
        log(f"Could not write config.yaml: {e}", "warning")
        return False


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------
#
# Each entry: (target_version:int, description:str, fn) where
#   fn(config_path, logger) applies ONE forward-only, IDEMPOTENT step.
# Keep the list ordered by target_version. To add a migration, append an entry
# and bump nothing else — CURRENT_SCHEMA_VERSION derives from the last entry,
# and install.sh ships that value in the fresh config.yaml.
#
def _m2_consolidate_aws_module_id(config_path, logger=None):
    """schema 1 -> 2: consolidate the AWS module's config id to 'aws_sigma'.

    The AWS module slot was renamed TWICE across releases:
        prowler  (posture, Prowler image)
          -> cloudtrail  (native SIGMA CloudTrail detection)
          -> aws_sigma   (current id)
    'cloudtrail' is also the real AWS service name, but the code rename only
    touched the MODULE ID (UPGRADE_ORDER, dispatch dicts, base.py maps,
    system_routes, frontend status keys, lib/*.sh readers), leaving every
    cloudtrail_* AWS-service name alone.

    This migration folds ANY legacy AWS-module id in the operator's config
    into 'aws_sigma', CARRYING the enabled flag forward so the operator's
    on/off choice survives (a prowler-era config with the AWS module OFF must
    not silently flip ON just because the block name changed — this is the gap
    the e2e upgrade from intact-20260615 surfaced).

    modules block: rename modules.cloudtrail AND modules.prowler -> aws_sigma
    (rename_module carries child lines verbatim; idempotent; if aws_sigma
    already exists the stale legacy block is dropped).

    versions block: cloudtrail's pin IS the rule-pack version → rename it to
    aws_sigma. prowler's pin is the dead Prowler IMAGE version (different
    meaning) → DROP it. The Phase-1 versions-merge already added the new
    versions.aws_sigma, so the cloudtrail rename usually just drops the dup.

    NOT renamed (compat contracts): the CLOUDTRAIL_VERSION env var in every
    installed host's backend .env, and the cloudtrail-<v>.tar package artifact.
    """
    rename_module_in_config('cloudtrail', 'aws_sigma', logger=logger,
                            config_path=config_path)
    rename_module_in_config('prowler', 'aws_sigma', logger=logger,
                            config_path=config_path)
    rename_version_key_in_config('cloudtrail', 'aws_sigma', logger=logger,
                                 config_path=config_path)
    delete_version_key_in_config('prowler', logger=logger,
                                 config_path=config_path)


CONFIG_MIGRATIONS: List[Tuple[int, str, Callable]] = [
    (2, "consolidate AWS module id: prowler/cloudtrail -> aws_sigma",
     _m2_consolidate_aws_module_id),
]

CURRENT_SCHEMA_VERSION = CONFIG_MIGRATIONS[-1][0] if CONFIG_MIGRATIONS else 1


def apply_config_migrations(config_path: str = None, logger: Callable = None) -> dict:
    """Run every migration with target_version > the file's current
    schema_version, in order. Idempotent overall (no pending == clean no-op).

    Returns {"success", "from", "to", "applied":[versions...], ["error"]}.
    Takes its own backup up front; bumps schema_version after each successful
    step; on any step raising, restores the whole file from the backup and
    returns success=False (caller aborts Phase 2 before the module loop).
    """
    log = logger or (lambda m, l="info": None)
    path = config_path or os.path.join(WORKDIR, 'config.yaml')
    if not os.path.isfile(path):
        log(f"  [config-migrate] {path} not found; nothing to migrate", "info")
        return {"success": True, "from": None, "to": None, "applied": []}

    current = read_schema_version(path)
    start = current
    pending = sorted((m for m in CONFIG_MIGRATIONS if m[0] > current),
                     key=lambda x: x[0])
    if not pending:
        return {"success": True, "from": current, "to": current, "applied": []}

    backup = path + MIGRATION_BACKUP_SUFFIX
    try:
        shutil.copy2(path, backup)
    except Exception as e:
        log(f"  [config-migrate] could not write backup {backup}: {e}; "
            f"refusing to migrate without a rollback path", "error")
        return {"success": False, "from": start, "to": current,
                "applied": [], "error": f"backup failed: {e}"}

    applied: List[int] = []
    try:
        for target, desc, fn in pending:
            log(f"  [config-migrate] {current} -> {target}: {desc}", "info")
            fn(path, logger=log)                     # idempotent step
            if not set_schema_version(path, target, logger=log):
                raise RuntimeError(f"failed to write schema_version {target}")
            current = target
            applied.append(target)
        try:
            os.remove(backup)
        except OSError:
            pass
        log(f"  [config-migrate] config.yaml migrated schema {start} -> {current}",
            "success")
        return {"success": True, "from": start, "to": current, "applied": applied}
    except Exception as e:
        log(f"  [config-migrate] step failed ({type(e).__name__}: {e}); "
            f"restoring config.yaml from {backup}", "error")
        try:
            shutil.copy2(backup, path)
            os.remove(backup)
        except Exception as re_:
            log(f"  [config-migrate] RESTORE FAILED ({re_}); backup kept at {backup}",
                "error")
        return {"success": False, "from": start, "to": current,
                "applied": applied, "error": str(e)}
