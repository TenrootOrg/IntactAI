#!/usr/bin/env python3
"""Portainer (Docker management UI) upgrade functions.

Portainer is optional infra (ships `enabled: false` by default) with two
containers sharing ONE version pin (`versions.portainer` in config.yaml
drives both PORTAINER_VERSION and PORTAINER_AGENT_VERSION — Portainer's own
docs require the agent to match the server's version exactly).
"""

import os
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file,
    backup_env_file, restore_env_file, cleanup_backup,
    load_docker_image, remove_old_module_image,
    enforce_module_health,
)


def _ensure_portainer_admin_secret(logger: Callable = None) -> None:
    """Seed the admin-password file if missing — mirrors
    lib/modules.sh:generate_portainer_secrets() exactly, since a fresh
    install triggered via the upgrade flow (operator flips
    enabled: false -> true and applies a later release) never runs
    install.sh's bash bootstrap. Portainer enforces a 12-char minimum on
    the seeded password even via --admin-password-file; short/missing
    values silently never create the admin account, so this must match
    the bash version's fallback exactly."""
    # Same shipped default rejected by lib/modules.sh:generate_portainer_secrets()
    # (config.yaml's modules.portainer.password) — it's exactly 12 chars, so the
    # length check alone lets it slip through; it must be denied explicitly.
    _KNOWN_DEFAULT_PASSWORD = "1234qwer!@#$"
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    secrets_dir = os.path.join(WORKDIR, 'modules', 'portainer', 'secrets')
    secret_path = os.path.join(secrets_dir, 'admin_password')
    if os.path.exists(secret_path) and os.path.getsize(secret_path) > 0:
        return
    os.makedirs(secrets_dir, exist_ok=True)
    from config import load_main_config
    cfg = load_main_config() or {}
    password = ((cfg.get('modules') or {}).get('portainer') or {}).get('password')
    if not password or len(password) < 12 or password == _KNOWN_DEFAULT_PASSWORD:
        # A hardcoded fallback here would ship the same publicly-known
        # password to every install that hits this path — generate a random
        # one instead, same as every other auto-provisioned secret in this
        # codebase (see iris.py's IRIS_SECRET_KEY / POSTGRES_*_PASSWORD via
        # secrets.token_hex). Must match lib/modules.sh's bash version.
        import secrets as _secrets
        password = _secrets.token_hex(16)
        log("  Portainer password missing, < 12 chars, or matches the shipped "
            "config.yaml default; generated a random one instead", "warning")
        log(f"  Retrieve it with: cat {secret_path}", "warning")
        log("  Change it from the Portainer UI after first login "
            "(Settings -> Users)", "warning")
    with open(secret_path, 'w') as f:
        f.write(password)
    os.chmod(secret_path, 0o600)
    log("  Created Portainer admin password file", "info")


def _update_portainer_versions(env_file: str, version: str, logger: Callable) -> None:
    """One config.yaml pin drives both containers — Portainer's own docs
    require the agent to run the exact same version as the server."""
    update_env_file(env_file, 'PORTAINER_VERSION', version, logger=logger)
    update_env_file(env_file, 'PORTAINER_AGENT_VERSION', version, logger=logger)
    # Called from here rather than from each of the three upgrade entry points,
    # so no path can be added later that stamps versions but forgets the secret
    # — which would leave that path unable to start Portainer at all.
    _ensure_agent_secret(env_file, logger)


def _ensure_agent_secret(env_file: str, logger: Callable = None) -> None:
    """Create modules/portainer/secrets/agent.env if absent.

    AGENT_SECRET is the only thing authenticating callers to portainer-agent,
    which is a full Docker API proxy running as root with docker.sock mounted —
    unauthenticated access to it is a container-to-host-root path. It was
    previously never set at all.

    This MUST run on the upgrade path, not just in lib/modules.sh: the compose
    file now declares `env_file: ./secrets/agent.env` for BOTH services, so a
    box upgraded without it fails `docker compose up` outright. The bash
    bootstrap never runs again after the first install, so this is the only
    thing standing between an upgraded box and a dead Portainer.

    Written to secrets/ rather than the module .env on purpose: that .env is
    git-tracked, and a credential written there would be staged by the next
    `git add`. secrets/* is gitignored.

    Generated once and then left alone — rotating it would unpair a working
    server/agent until both were recreated together.
    """
    log = logger or (lambda m, l="info": None)
    secrets_dir = os.path.join(os.path.dirname(env_file), 'secrets')
    agent_env = os.path.join(secrets_dir, 'agent.env')
    try:
        if os.path.exists(agent_env) and os.path.getsize(agent_env) > 0:
            return
        os.makedirs(secrets_dir, exist_ok=True)
        import secrets as _secrets
        with open(agent_env, 'w') as f:
            f.write(f"AGENT_SECRET={_secrets.token_hex(32)}\n")
        os.chmod(agent_env, 0o600)
        log("  Generated Portainer agent secret (the agent was previously "
            "unauthenticated)", "success")
    except Exception as e:
        # Loud: without this file Portainer will not start at all, so a silent
        # failure here would look like an unrelated Portainer outage later.
        log(f"  Could not write {agent_env} ({type(e).__name__}: {e}) — "
            f"Portainer will fail to start until it exists", "error")


def upgrade_portainer(version: str, logger: Callable = None) -> Dict:
    """Upgrade Portainer (server + agent) to the specified version, with
    automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'portainer')
    env_file = os.path.join(work_dir, '.env')

    log("Starting Portainer upgrade...", "info")
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('PORTAINER_VERSION', '0.0.0')

    if current_version == version:
        log(f"Portainer is already at version {version}", "info")
        return {"success": True, "version": version, "message": "Already at target version"}

    backup_file = backup_env_file(env_file, logger=log)
    try:
        log("Stopping Portainer containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Portainer: {result['error']}")

        log(f"Updating version to {version}...", "info")
        _update_portainer_versions(env_file, version, log)

        log("Pulling new images...", "info")
        result = run_command("docker compose pull", cwd=work_dir, timeout=300, logger=log)
        if not result['success']:
            log(f"Pull warning: {result.get('error', '')[:100]}", "warning")

        _ensure_portainer_admin_secret(log)

        log("Starting Portainer containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Portainer: {result['error']}")

        health = enforce_module_health('portainer', timeout=90, logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"Portainer upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('portainer', current_version, version, logger=log)
        return {"success": True, "version": version,
                "health": health["health"], "health_detail": health["detail"]}

    except Exception as e:
        error_msg = str(e)
        log(f"Portainer upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")
        return {"success": False, "error": error_msg, "rolled_back": True,
                "restored_version": current_version}


def upgrade_portainer_offline(package_dir: str, version: str, logger: Callable = None,
                               run_id: Optional[str] = None) -> Dict:
    """Upgrade Portainer from a pre-saved offline package, with automatic
    rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'portainer')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Portainer offline upgrade...", "info")
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('PORTAINER_VERSION', '0.0.0')

    from .base import preflight_offline_images
    pre = preflight_offline_images('portainer', version, images_dir, logger=log, run_id=run_id)
    if not pre['success']:
        return {"success": False,
                "error": f"required Portainer images unavailable (stack left running): {', '.join(pre['missing'])}"}

    backup_file = backup_env_file(env_file, logger=log)
    try:
        log("Stopping Portainer containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop Portainer: {result['error']}")

        log("Loading docker images from package...", "info")
        for tar_name in [f"portainer-ce-{version}.tar", f"portainer-agent-{version}.tar"]:
            tar_path = os.path.join(images_dir, tar_name)
            if os.path.exists(tar_path):
                result = load_docker_image(tar_path, logger=log, run_id=run_id)
                if not result['success']:
                    log(f"  Warning: failed to load {tar_name}", "warning")
            else:
                # See elk.py's twin: pre-check already verified presence and the
                # orchestrator reclaims tars after loading them.
                log(f"  {tar_name}: already reclaimed after pre-load "
                    f"(image verified present by the pre-check) — nothing to do.", "info")

        log(f"Updating version to {version}...", "info")
        _update_portainer_versions(env_file, version, log)
        _ensure_portainer_admin_secret(log)

        log("Starting Portainer containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Portainer: {result['error']}")

        health = enforce_module_health('portainer', timeout=90, logger=log)

        cleanup_backup(backup_file, logger=log)
        log(f"Portainer offline upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('portainer', current_version, version, logger=log)
        return {"success": True, "version": version,
                "health": health["health"], "health_detail": health["detail"]}

    except Exception as e:
        error_msg = str(e)
        log(f"Portainer offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")
        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK to version {current_version}", "warning")
        return {"success": False, "error": error_msg, "rolled_back": True,
                "restored_version": current_version}


def install_portainer_offline(package_dir: str, version: str, logger: Callable = None,
                               run_id: Optional[str] = None) -> Dict:
    """Fresh-install Portainer from an offline package — picked by the apply
    orchestrator when intact_portainer is not present on the host (covers
    both a true fresh install and an operator flipping
    modules.portainer.enabled false -> true on an already-upgraded box,
    neither of which ever runs install.sh's bash bootstrap)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    work_dir = os.path.join(WORKDIR, 'modules', 'portainer')
    env_file = os.path.join(work_dir, '.env')
    version = version or ''
    log(f"Installing Portainer (first-time) -> {version or 'tracked default'}...", "info")

    if os.path.exists(env_file) and version:
        _update_portainer_versions(env_file, version, log)

    _ensure_portainer_admin_secret(log)

    compose_result = install_module_compose_up(
        'portainer', package_dir, version,
        image_tar_prefixes=['portainer-ce', 'portainer-agent'],
        logger=log, run_id=run_id,
    )
    if not compose_result.get('success'):
        return compose_result

    health = enforce_module_health('portainer', timeout=90, logger=log)
    compose_result['health'] = health['health']
    compose_result['health_detail'] = health['detail']
    return compose_result
