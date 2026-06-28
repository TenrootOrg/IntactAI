#!/usr/bin/env python3
"""IRIS upgrade functions."""

import os
import time
import requests
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup,
    remove_old_module_image,
)


def ensure_iris_web_cert(work_dir: str, logger: Callable = None) -> None:
    """Make sure the IRIS nginx TLS cert exists before the stack comes up.

    The IRIS web cert (config/certificates/web_certificates/iris_dev_{cert,key}.pem)
    is operator-generated and gitignored — the ONLY thing that creates it is
    lib/modules.sh:generate_certificates at install time, gated on iris.enabled.
    So enabling IRIS after a disabled install, or a change_ip that removed the
    cert while IRIS was disabled, leaves intact_iris_nginx with no cert and it
    crash-loops on `cannot load certificate "/www/certs/iris_dev_cert.pem"` —
    the whole IRIS UI is then down even though app/db/worker are healthy.

    Every IRIS bring-up path (online upgrade, offline apply, package install)
    calls this to self-heal. It mirrors lib/modules.sh: copy the shared nginx
    cert into the IRIS web-cert path, and generate the IRIS Root CA if missing.
    Missing-only — a present cert (operator- or change_ip-managed, carrying the
    current CN) is never clobbered.
    """
    log = logger or (lambda m, l="info": None)
    web_dir = os.path.join(work_dir, 'config', 'certificates', 'web_certificates')
    cert = os.path.join(web_dir, 'iris_dev_cert.pem')
    key = os.path.join(web_dir, 'iris_dev_key.pem')

    def _present(p):
        return os.path.exists(p) and os.path.getsize(p) > 0

    if not (_present(cert) and _present(key)):
        nginx_crt = os.path.join(WORKDIR, 'modules', 'nginx', 'ssl', 'nginx-cert.crt')
        nginx_key = os.path.join(WORKDIR, 'modules', 'nginx', 'ssl', 'nginx-cert.key')
        if _present(nginx_crt) and _present(nginx_key):
            try:
                import shutil
                os.makedirs(web_dir, exist_ok=True)
                shutil.copy2(nginx_crt, cert)
                shutil.copy2(nginx_key, key)
                # 0o644: iris nginx reads these as a non-root user; a 0o600
                # root-owned mount would be unreadable (mirrors lib/modules.sh).
                os.chmod(cert, 0o644)
                os.chmod(key, 0o644)
                log("  Synced IRIS web TLS cert from the shared nginx certificate", "success")
            except Exception as e:
                log(f"  Could not sync IRIS web cert ({type(e).__name__}: {e}) — "
                    "intact_iris_nginx may fail to start", "warning")
        else:
            log("  IRIS web cert missing and the shared nginx cert is unavailable "
                "to sync from — intact_iris_nginx may fail to start", "warning")

    # IRIS Root CA — best-effort parity with lib/modules.sh.
    ca_dir = os.path.join(work_dir, 'config', 'certificates', 'rootCA')
    ca_cert = os.path.join(ca_dir, 'irisRootCACert.pem')
    ca_key = os.path.join(ca_dir, 'irisRootCAKey.pem')
    if not _present(ca_cert):
        try:
            os.makedirs(ca_dir, exist_ok=True)
            run_command(
                "openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
                f"-keyout {ca_key} -out {ca_cert} "
                "-subj '/CN=IRIS Root CA/O=Intact.AI/C=US'", logger=None)
        except Exception:
            pass


def upgrade_iris(version: str, logger: Callable = None) -> Dict:
    """Upgrade IRIS to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')

    log("Starting IRIS upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('IRIS_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping IRIS containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop IRIS: {result['error']}")

        # Update version in .env
        log(f"Updating version to {version}...", "info")
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

        # Pull new images
        log("Pulling new images...", "info")
        run_command("docker compose pull", cwd=work_dir, timeout=1800, logger=log)

        # Ensure the web TLS cert exists or iris-nginx crash-loops (see helper).
        ensure_iris_web_cert(work_dir, logger=log)

        # Start containers
        log("Starting IRIS containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start IRIS: {result['error']}")

        # Health check - wait for IRIS to respond
        # Use docker exec since we're inside a container and can't reach localhost:8443
        log("Waiting for IRIS container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking IRIS container... ({i*5}s)", "info")
            # Check IRIS nginx container - it proxies to the app
            check_result = run_command(
                "docker exec intact_iris_nginx curl -sk --max-time 5 https://localhost:8443/ -o /dev/null -w '%{http_code}'",
                logger=None
            )
            if check_result['success']:
                http_code = check_result.get('stdout', '').strip()
                # Accept 200, redirects, or 401 (auth required = service is up)
                if http_code in ['200', '301', '302', '303', '307', '308', '401']:
                    log(f"  Container healthy - HTTP {http_code}", "success")
                    healthy = True
                    break
                else:
                    log(f"  Container not ready yet (HTTP {http_code})...", "info")
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("IRIS health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_iris --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"IRIS failed to start - container status: {container_status}")
            log("IRIS health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"IRIS upgrade completed: {current_version} -> {version}", "success")
        # Remove the OLD pinned image(s) — frees ~1.5 GB per IRIS bump.
        # Safe by design: skipped on no-op upgrade, Docker refuses on
        # in-use, errors swallowed (helper logs at info level).
        remove_old_module_image('iris', current_version, version, logger=log)
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"IRIS upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK IRIS to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_iris_offline(package_dir: str, version: str, logger: Callable = None,
                          run_id: Optional[str] = None) -> Dict:
    """Upgrade IRIS from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting IRIS offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('IRIS_VERSION', 'unknown')

    # Create backup before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    backup_file = backup_env_file(env_file, logger=log)

    try:
        # Stop containers
        log("Stopping IRIS containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop IRIS: {result['error']}")

        # Load docker images (including DB for air-gap support - data is in volumes)
        log("Loading docker images from package...", "info")
        for img_name in ['iris-app', 'iris-nginx', 'iris-db']:
            tar_path = os.path.join(images_dir, f"{img_name}-{version}.tar")
            if os.path.exists(tar_path):
                load_docker_image(tar_path, logger=log, run_id=run_id)
            else:
                log(f"  Image not found: {tar_path}", "warning")

        # Infrastructure deps: rabbitmq is a fixed-version dep declared
        # in IRIS compose. Load it if bundled (newer packages include
        # it for offline support; older packages don't — falling
        # through to docker-hub pull is fine when there's internet).
        rabbitmq_tar = os.path.join(images_dir, 'rabbitmq-3-management-alpine.tar')
        if os.path.exists(rabbitmq_tar):
            log("  Loading bundled rabbitmq image (infrastructure dep)...", "info")
            load_docker_image(rabbitmq_tar, logger=log, run_id=run_id)

        # Update version in .env
        log(f"Updating version to {version}...", "info")
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

        # Ensure the web TLS cert exists or iris-nginx crash-loops (see helper).
        ensure_iris_web_cert(work_dir, logger=log)

        # Start containers
        log("Starting IRIS containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start IRIS: {result['error']}")

        # Health check - wait for IRIS to respond
        # Use docker exec since we're inside a container and can't reach localhost:8443
        log("Waiting for IRIS container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking IRIS container... ({i*5}s)", "info")
            # Check IRIS nginx container - it proxies to the app
            check_result = run_command(
                "docker exec intact_iris_nginx curl -sk --max-time 5 https://localhost:8443/ -o /dev/null -w '%{http_code}'",
                logger=None
            )
            if check_result['success']:
                http_code = check_result.get('stdout', '').strip()
                # Accept 200, redirects, or 401 (auth required = service is up)
                if http_code in ['200', '301', '302', '303', '307', '308', '401']:
                    log(f"  Container healthy - HTTP {http_code}", "success")
                    healthy = True
                    break
                else:
                    log(f"  Container not ready yet (HTTP {http_code})...", "info")
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("IRIS health check: PASSED", "success")
        else:
            check_result = run_command("docker ps -a --filter name=intact_iris --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"IRIS failed to start - container status: {container_status}")
            log("IRIS health check: TIMEOUT (containers may still be starting)", "warning")

        # Success - cleanup backup
        cleanup_backup(backup_file, logger=log)
        log(f"IRIS offline upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('iris', current_version, version, logger=log)
        return {"success": True, "version": version, "health": "green" if healthy else "pending"}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"IRIS offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        if restore_env_file(env_file, backup_file, logger=log):
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK IRIS to version {current_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def install_iris_offline(package_dir: str, version: str, logger=None, run_id=None) -> Dict:
    """Fresh-install IRIS — picked when intact_iris_app absent.

    Generates the secret files lib/modules.sh:generate_iris_secrets
    would otherwise create (IRIS_ADM_PASSWORD from config.yaml,
    IRIS_SECRET_KEY + IRIS_SECURITY_PASSWORD_SALT as `openssl rand -hex 32`
    equivalents, POSTGRES_* passwords).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    import secrets as _secrets

    work_dir = os.path.join(WORKDIR, 'modules', 'iris')
    env_file = os.path.join(work_dir, '.env')
    secrets_dir = os.path.join(work_dir, 'secrets')
    os.makedirs(secrets_dir, exist_ok=True)

    log(f"Installing IRIS (first-time) -> {version or 'tracked default'}...", "info")
    # Ensure .env exists + has IRIS_VERSION before compose up. Fresh
    # install via UI may run with no pre-existing .env. Without writing
    # this unconditionally, compose would either fall back to ${IRIS_VERSION}
    # (empty) or hit the `${VAR:?}` rule. update_env_file is idempotent.
    if version:
        os.makedirs(work_dir, exist_ok=True)
        if not os.path.exists(env_file):
            open(env_file, 'a').close()
        update_env_file(env_file, 'IRIS_VERSION', version, logger=log)

    iris_admin_pw = '123123'
    try:
        from config import load_main_config
        cfg = load_main_config() or {}
        v = (cfg.get('modules', {}) or {}).get('iris', {}).get('password')
        if v:
            iris_admin_pw = str(v)
    except Exception:
        pass

    secret_specs = [
        ('IRIS_ADM_PASSWORD', iris_admin_pw),
        ('IRIS_SECRET_KEY', _secrets.token_hex(32)),
        ('IRIS_SECURITY_PASSWORD_SALT', _secrets.token_hex(32)),
        ('POSTGRES_ADMIN_PASSWORD', _secrets.token_hex(32)),
        ('POSTGRES_PASSWORD', _secrets.token_hex(32)),
    ]
    for name, val in secret_specs:
        path = os.path.join(secrets_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            log(f"  {name}: already present, keeping existing", "info")
            # Re-chmod existing files to 0o644 — fixes pre-existing 0o600
            # secrets from older versions of this code that locked
            # iris_app out (iris_app runs as nobody/uid 65534; root-owned
            # 0o600 secrets bind-mounted into /run/secrets/ are
            # unreadable, so iris_app reads an empty password and
            # connects with "" → password-auth-failed crashloop).
            try:
                os.chmod(path, 0o644)
            except (PermissionError, FileNotFoundError):
                pass
            continue
        with open(path, 'w') as f:
            f.write(val or '')
        # 0o644 (world-readable) — not 0o600. The iris_app container runs
        # the gunicorn process as `nobody` (uid 65534) while the secret
        # files are owned by root inside the container (because docker
        # bind-mounts inherit host ownership and we wrote them as root
        # from the backend container). A 0o600 file owned by root is
        # unreadable to nobody; iris_app then gets an empty password,
        # connects with "", and crashes with "password authentication
        # failed for user postgres" in an endless loop. install.sh's
        # generate_iris_secrets doesn't chmod the files at all (leaving
        # them at the default umask 0o644), which is why the regular
        # install path doesn't hit this. Matching that policy here.
        os.chmod(path, 0o644)
        log(f"  Generated {name}", "info")

    # Stamp transitive container versions from the bundled manifest
    # (RABBITMQ_VERSION) into modules/iris/.env BEFORE compose up.
    # The compose file's `${RABBITMQ_VERSION:?...}` interpolation will
    # fail without it.
    from .base import stamp_transitive_env_from_manifest
    try:
        stamp_transitive_env_from_manifest('iris', package_dir, logger=log)
    except Exception as _e:
        log(f"  transitive .env stamp raised "
            f"({type(_e).__name__}: {_e}); compose up will likely fail",
            "warning")

    # Ensure the web TLS cert exists or iris-nginx crash-loops (see helper).
    ensure_iris_web_cert(work_dir, logger=log)

    compose_result = install_module_compose_up(
        'iris', package_dir, version,
        image_tar_prefixes=['iris', 'rabbitmq', 'postgres'],
        logger=log, run_id=run_id,
    )
    if not compose_result.get('success'):
        return compose_result

    # Post-install bootstrap. Without this, the install reports success
    # but the IntactAI backend has NO IRIS api_key in its secrets DB →
    # every backend → IRIS API call fails with 401. Mirrors
    # lib/modules.sh:bootstrap_iris_api_key.
    log("IRIS containers up. Waiting for first-init + extracting api_key...", "info")

    import subprocess as _sub

    # Stage 1: wait for the IRIS user table to be populated AND for the
    # administrator's api_key column to be non-NULL. IRIS's first-init
    # runs alembic migrations + a seed step that creates the
    # administrator row WITHOUT an api_key initially, then a separate
    # step populates the key. Polling for `api_key IS NOT NULL` is what
    # tells us the stack is actually ready to authenticate.
    api_key = None
    waited = 0
    while waited < 300:  # 5 minutes — IRIS first-init is slow (DB + alembic + seed)
        try:
            probe = _sub.run(
                ["docker", "exec", "intact_iris_db", "psql", "-U", "iris", "-d", "iris_db",
                 "-tAc", 'SELECT api_key FROM "user" WHERE name=\'administrator\' AND api_key IS NOT NULL;'],
                capture_output=True, text=True, timeout=15,
            )
            out = (probe.stdout or "").strip()
            if probe.returncode == 0 and out:
                api_key = out
                log(f"  IRIS administrator api_key materialized ({waited}s)", "success")
                break
        except _sub.TimeoutExpired:
            pass
        except Exception:
            pass
        time.sleep(5)
        waited += 5
        if waited % 30 == 0:
            log(f"  Still waiting for IRIS first-init... ({waited}s)", "info")

    if not api_key:
        log(
            "IRIS administrator api_key did not appear in iris_db after 5 minutes. "
            "Containers ARE running, but backend → IRIS API calls will fail until "
            "the key is stored. Fix manually once IRIS is ready: "
            "`docker exec intact_iris_db psql -U iris -d iris_db -tAc "
            "\"SELECT api_key FROM \\\"user\\\" WHERE name='administrator';\"` "
            "then `docker exec intact_backend python3 -c \"from services.storage."
            "secret_store import set_secret; set_secret('iris.administrator.api_key', '<key>')\"`",
            "warning",
        )
        return compose_result

    # Stage 2: store the api_key in the backend's secrets DB so iris_service
    # can auth without doing a docker-exec lookup on every call.
    log("Storing IRIS api_key in backend secrets DB...", "info")
    try:
        from services.storage.secret_store import set_secret, get_secret
        if set_secret('iris.administrator.api_key', api_key):
            # Read-back verify (set_secret can succeed but a transient
            # SQLite lock can roll the write back silently).
            persisted = get_secret('iris.administrator.api_key')
            if persisted == api_key:
                log("  IRIS api_key persisted to backend secrets table — verified", "success")
            else:
                log(
                    "  IRIS api_key set_secret() returned OK but read-back didn't match. "
                    "Run the manual set_secret() shown in the prior warning.",
                    "warning",
                )
        else:
            log("  IRIS api_key set_secret() returned False. Fix manually.", "warning")
    except Exception as e:
        log(f"  Failed to persist IRIS api_key to backend secrets: {e}", "warning")

    return compose_result
