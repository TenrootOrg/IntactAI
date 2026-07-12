#!/usr/bin/env python3
"""CloudTrail (AWS DFIR detection) upgrade functions.

The AWS module is native: CloudTrail events are collected via boto3 and matched
by the SIGMA AWS CloudTrail rule pack (cloned from SigmaHQ into /opt/sigma-rules).
There is NO container image — the versioned artifact is the SIGMA AWS rule pack.
"Upgrade" therefore means refreshing that rule pack and pinning CLOUDTRAIL_VERSION
in the backend .env. No backend restart is needed (rules are read fresh per scan).

/opt/sigma-rules is mounted read-only inside the backend, so writes to it are done
by a one-shot container that mounts the host path read-write (the backend has the
docker socket) — the same host directory install-time `download_sigma_rules` writes.
Every rule operation is best-effort: a rule refresh must never fail the upgrade.

Internal function names `upgrade_aws` / `upgrade_aws_offline` are kept as aliases so
the dispatcher tables in __init__.py continue to resolve; the public module key is
now 'aws_sigma' (module id; the AWS service itself is CloudTrail).
"""

import os
import shlex
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR,
    run_command, read_env_file, update_env_file,
    backup_env_file, restore_env_file, cleanup_backup,
    set_module_enabled_in_config,
)

SIGMA_RULES_DIR = "/opt/sigma-rules"
AWS_RULES_SUBPATH = "rules/cloud/aws"
_GIT_IMAGE = "alpine/git:latest"
_TAR_IMAGE = "ubuntu:22.04"


def upgrade_cloudtrail(version: str, logger: Callable = None) -> Dict:
    """Online: refresh the SIGMA AWS rule pack (git pull the SigmaHQ clone) and pin
    CLOUDTRAIL_VERSION. Rule refresh is best-effort; version pin + enable always run."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting CloudTrail (SIGMA AWS rule pack) upgrade...", "info")
    current_version = read_env_file(backend_env).get('CLOUDTRAIL_VERSION', 'unknown')
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        # Refresh the host-mounted SigmaHQ clone via a one-shot git container.
        log(f"Refreshing SIGMA AWS rule pack -> {version}...", "info")
        r = run_command(
            f"docker run --rm -w {SIGMA_RULES_DIR} -v {SIGMA_RULES_DIR}:{SIGMA_RULES_DIR} "
            f"{_GIT_IMAGE} pull --ff-only",
            logger=log, timeout=600)
        if not r.get('success'):
            log("  Rule-pack git pull skipped (non-fatal) — keeping current rules", "warning")

        update_env_file(backend_env, 'CLOUDTRAIL_VERSION', version, logger=log)
        set_module_enabled_in_config('aws_sigma', logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"CloudTrail rule-pack upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"CloudTrail upgrade FAILED: {error_msg}", "error")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK CloudTrail to version {current_version}", "warning")
        return {"success": False, "error": error_msg, "rolled_back": True,
                "restored_version": current_version}


def upgrade_cloudtrail_offline(package_dir: str, version: str, logger: Callable = None,
                               run_id: Optional[str] = None) -> Dict:
    """Offline: install the bundled AWS rule pack (cloudtrail-<version>.tar) into the
    host SIGMA rules dir via a one-shot container (tar streamed over stdin, so no
    host-path translation needed). Best-effort; version pin + enable always run."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting CloudTrail (SIGMA AWS rule pack) offline upgrade...", "info")
    current_version = read_env_file(backend_env).get('CLOUDTRAIL_VERSION', 'unknown')
    backup_file = backup_env_file(backend_env, logger=log)

    try:
        tar_path = os.path.join(images_dir, f"cloudtrail-{version}.tar")
        if os.path.exists(tar_path):
            log("Installing SIGMA AWS rule pack from package...", "info")
            dest = f"{SIGMA_RULES_DIR}/{AWS_RULES_SUBPATH}"
            # Stream the tar (readable in the backend fs) into a one-shot that mounts
            # the host rules dir read-write. Avoids mounting the tar (no host-path map).
            r = run_command(
                f"docker run --rm -i -v {SIGMA_RULES_DIR}:{SIGMA_RULES_DIR} {_TAR_IMAGE} "
                f"sh -c 'mkdir -p {dest} && tar xf - -C {dest}' < {shlex.quote(tar_path)}",
                logger=log, timeout=300)
            if not r.get('success'):
                log("  Rule-pack extract failed (non-fatal) — keeping current rules", "warning")
        else:
            log(f"CloudTrail rule pack not in package (cloudtrail-{version}.tar) — "
                f"skipping (rules ship with the SigmaHQ clone)", "warning")

        update_env_file(backend_env, 'CLOUDTRAIL_VERSION', version, logger=log)
        set_module_enabled_in_config('aws_sigma', logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"CloudTrail offline upgrade completed: {current_version} -> {version}", "success")
        return {"success": True, "version": version}

    except Exception as e:
        error_msg = str(e)
        log(f"CloudTrail offline upgrade FAILED: {error_msg}", "error")
        if restore_env_file(backend_env, backup_file, logger=log):
            log(f"ROLLED BACK CloudTrail to version {current_version}", "warning")
        return {"success": False, "error": error_msg, "rolled_back": True,
                "restored_version": current_version}


# Back-compat aliases for the dispatcher tables in __init__.py.
upgrade_aws = upgrade_cloudtrail
upgrade_aws_offline = upgrade_cloudtrail_offline
