#!/usr/bin/env python3
"""Timesketch upgrade functions."""

import os
import time
import shlex
import requests
from datetime import datetime
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup
)


# Where pg_dump files land. Bind-mounted at host so they survive container
# restarts. We keep dumps indefinitely on success and prune by hand —
# operators occasionally need an older one and an aggressive auto-prune
# would defeat the safety-net purpose.
_DB_BACKUP_DIR = os.path.join(WORKDIR, 'backups', 'timesketch')
_DB_BACKUP_DIR_HOST = os.path.join(HOST_PATH, 'backups', 'timesketch')

# Hardcoded — matches what intact_timesketch_postgres ships with and what
# Timesketch's docker-compose.yaml configures.
_PG_CONTAINER = 'intact_timesketch_postgres'
_PG_USER = 'timesketch'
_PG_DB = 'timesketch'
_WEB_CONTAINER = 'intact_timesketch_web'


def _backup_timesketch_db(current_version: str, target_version: str, logger: Callable = None) -> Optional[str]:
    """pg_dump the live Timesketch DB to a timestamped file under WORKDIR.

    Runs while the old containers are still up so the dump sees a consistent
    snapshot (postgres handles MVCC; no need to stop the DB first). Returns
    the dump path on success, None on failure — the caller decides whether
    "no backup" is fatal.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    os.makedirs(_DB_BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_cur = current_version.replace('/', '_').replace(' ', '_')
    safe_tgt = target_version.replace('/', '_').replace(' ', '_')
    dump_path = os.path.join(_DB_BACKUP_DIR, f'timesketch_{safe_cur}_to_{safe_tgt}_{stamp}.sql')

    log(f"Backing up Timesketch DB via pg_dump → {dump_path}", "info")
    # `-t` would allocate a TTY which corrupts binary-safe redirection; omit it.
    cmd = (
        f"docker exec {_PG_CONTAINER} pg_dump -U {shlex.quote(_PG_USER)} "
        f"-d {shlex.quote(_PG_DB)} > {shlex.quote(dump_path)}"
    )
    result = run_command(cmd, timeout=600, logger=log)
    if not result['success']:
        log(f"pg_dump failed: {result.get('error','?')[:200]}", "error")
        # Remove the empty/partial file so we don't try to restore from it.
        try:
            if os.path.exists(dump_path) and os.path.getsize(dump_path) == 0:
                os.remove(dump_path)
        except Exception:
            pass
        return None

    size_mb = os.path.getsize(dump_path) / (1024 * 1024) if os.path.exists(dump_path) else 0
    if size_mb < 0.001:
        log(f"pg_dump produced an empty file at {dump_path}", "error")
        try:
            os.remove(dump_path)
        except Exception:
            pass
        return None

    log(f"DB backup OK ({size_mb:.2f} MB)", "success")
    return dump_path


def _restore_timesketch_db(dump_path: str, logger: Callable = None) -> bool:
    """Restore the Timesketch DB from a pg_dump file. Used in the rollback path.

    Drops + recreates the database first so the restore doesn't accumulate
    on top of the already-migrated schema, then streams the dump back in
    via psql.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    if not dump_path or not os.path.exists(dump_path):
        log(f"DB restore skipped — no backup file at {dump_path}", "warning")
        return False

    log(f"Restoring Timesketch DB from {dump_path}", "info")

    # Postgres can't drop a DB while sessions are connected; terminate them
    # first. The web container should already be stopped by the caller, but
    # belt-and-braces.
    terminate = (
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d postgres -c "
        f"\"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{_PG_DB}' AND pid<>pg_backend_pid();\""
    )
    run_command(terminate, timeout=30, logger=log)

    for cmd in (
        f"docker exec {_PG_CONTAINER} dropdb -U {_PG_USER} --if-exists {_PG_DB}",
        f"docker exec {_PG_CONTAINER} createdb -U {_PG_USER} {_PG_DB}",
        f"docker exec -i {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} < {shlex.quote(dump_path)}",
    ):
        result = run_command(cmd, timeout=600, logger=log)
        if not result['success']:
            log(f"DB restore step failed ({cmd[:60]}...): {result.get('error','?')[:200]}", "error")
            return False

    log("DB restore OK", "success")
    return True


def _fetch_migrations_dir(version: str, logger: Callable = None) -> Optional[str]:
    """Download Timesketch's alembic migrations/ tree for `version` from GitHub.

    The Timesketch wheel installed in the container does NOT include
    migrations/ — they live only in the source repo. The upstream upgrade
    guide handles this by `git clone`-ing the repo inside the container.
    We do the equivalent via a tarball download from the backend container
    (which has curl) and return a host-bind-mounted path to the extracted
    migrations directory so the caller can docker-cp it into the running
    web container.

    Tries the version tag first, falls back to master if the tag 404s.
    Returns None on failure (caller handles).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_root = os.path.join(WORKDIR, 'backups', 'timesketch', 'migrations_cache')
    os.makedirs(work_root, exist_ok=True)
    extract_dir = os.path.join(work_root, version)
    tarball = os.path.join(work_root, f'{version}.tar.gz')

    # Try tagged release first, then master as a fallback.
    candidates = [
        f"https://github.com/google/timesketch/archive/refs/tags/{version}.tar.gz",
        "https://github.com/google/timesketch/archive/refs/heads/master.tar.gz",
    ]
    fetched = False
    for url in candidates:
        log(f"Fetching Timesketch migrations from {url}", "info")
        # -fL: fail on HTTP errors, follow redirects. -o: output file.
        result = run_command(f"curl -fLsS -o {shlex.quote(tarball)} {shlex.quote(url)}", timeout=120, logger=None)
        if result['success'] and os.path.exists(tarball) and os.path.getsize(tarball) > 1024:
            fetched = True
            break
        log(f"  → not available ({result.get('error','no detail')[:120]})", "warning")
    if not fetched:
        log("Could not download Timesketch source for migrations — schema upgrade will be skipped", "error")
        return None

    # Extract only timesketch/migrations/ from the tarball to keep the cache lean.
    # tar's --strip-components removes the version-prefixed top dir.
    if os.path.isdir(extract_dir):
        run_command(f"rm -rf {shlex.quote(extract_dir)}", logger=None)
    os.makedirs(extract_dir, exist_ok=True)
    # GNU tar needs --wildcards to glob across the version-prefixed top dir.
    # --strip-components=1 drops the `timesketch-<version>/` prefix so the
    # extracted tree starts with `timesketch/migrations/`.
    result = run_command(
        f"tar -xzf {shlex.quote(tarball)} -C {shlex.quote(extract_dir)} "
        f"--wildcards --strip-components=1 '*/timesketch/migrations'",
        timeout=60, logger=log
    )
    if not result['success']:
        log(f"Failed to extract migrations from tarball: {result.get('error','?')[:200]}", "error")
        return None

    migrations_path = os.path.join(extract_dir, 'timesketch', 'migrations')
    if not os.path.isdir(migrations_path):
        log(f"Expected migrations dir not found at {migrations_path} after extract", "error")
        return None

    log(f"Migrations dir ready at {migrations_path}", "success")
    return migrations_path


def _run_db_schema_upgrade(target_version: str, logger: Callable = None) -> bool:
    """Run `tsctl db upgrade` inside the (already-upgraded) web container.

    The installed Timesketch wheel doesn't ship the alembic migrations/
    directory, so we fetch the matching version's migrations from GitHub,
    docker-cp them into the running web container at /migrations, then run
    `tsctl db upgrade -d /migrations` (idempotent — a no-op for patch-level
    upgrades returns 0).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    migrations_host_path = _fetch_migrations_dir(target_version, logger=log)
    if not migrations_host_path:
        log("Skipping schema migration — no migrations available. Run "
            "'docker exec intact_timesketch_web tsctl db upgrade -d <path>' "
            "manually if the new version has schema changes.", "warning")
        return False

    # docker cp the host-side migrations into the web container. The trailing
    # /. on the source copies dir contents (not the dir itself) into /migrations.
    log("Copying migrations into intact_timesketch_web:/migrations", "info")
    run_command(f"docker exec {_WEB_CONTAINER} rm -rf /migrations", logger=None)
    cp = run_command(
        f"docker cp {shlex.quote(migrations_host_path)} {_WEB_CONTAINER}:/migrations",
        timeout=60, logger=log
    )
    if not cp['success']:
        log(f"docker cp migrations into container failed: {cp.get('error','?')[:200]}", "error")
        return False

    # If the DB has never been alembic-tracked (no alembic_version row),
    # stamp it to head BEFORE attempting `upgrade` — otherwise alembic will
    # try to run every migration from scratch and collide with the tables
    # Timesketch already create_all'd at first setup. Most install paths of
    # Timesketch don't initialise the alembic table; this bootstraps it.
    check = run_command(
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} -tAc "
        f"\"SELECT version_num FROM alembic_version LIMIT 1;\"",
        logger=None
    )
    current_marker = (check.get('stdout') or '').strip()
    if not current_marker:
        log("DB has no alembic_version marker — stamping head to bootstrap tracking", "warning")
        stamp = run_command(
            f"docker exec {_WEB_CONTAINER} tsctl db stamp -d /migrations head",
            timeout=120, logger=log
        )
        if not stamp['success']:
            log(f"db stamp failed: {stamp.get('error','?')[:300]}", "error")
            return False
        log("Alembic stamped to head — future upgrades will apply pending migrations cleanly", "success")
    else:
        log(f"DB alembic version marker: {current_marker}", "info")

    log("Running tsctl db upgrade (alembic schema migration)...", "info")
    cmd = f"docker exec {_WEB_CONTAINER} tsctl db upgrade -d /migrations"
    result = run_command(cmd, timeout=600, logger=log)
    if not result['success']:
        log(f"tsctl db upgrade FAILED: {result.get('error','?')[:300]}", "error")
        return False
    out = (result.get('stdout') or '').strip()
    if out:
        log(f"tsctl db upgrade output: {out[:300]}", "info")
    log("tsctl db upgrade OK", "success")
    return True


def _clear_timesketch_pip_cache(logger: Callable = None):
    """Clear stale pip packages from Timesketch volume to prevent version conflicts.

    LLM packages (google-generativeai, anthropic, etc.) installed by Timesketch
    persist in the volume and can conflict when Timesketch is upgraded.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # List of LLM-related packages that can cause conflicts
    conflicting_packages = [
        'google-generativeai',
        'google-ai-generativelanguage',
        'google-api-core',
        'google-api-python-client',
        'googleapis-common-protos',
        'grpcio',
        'grpcio-status',
        'proto-plus',
        'protobuf',
    ]

    # Run pip uninstall in a temporary container with the volume mounted
    for package in conflicting_packages:
        result = run_command(
            f"docker run --rm -v intact_timesketch_venv:/opt/venv "
            f"us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:latest "
            f"pip uninstall -y {package} 2>/dev/null || true",
            logger=lambda msg, level="info": None  # Silent
        )

    log("Cleared potentially conflicting pip packages", "info")


def upgrade_timesketch(version: str, logger: Callable = None, plaso_version: str = None) -> Dict:
    """Upgrade Timesketch to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting Timesketch upgrade...", "info")

    # Get current versions for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('TIMESKETCH_VERSION', 'unknown')
    backend_vars = read_env_file(backend_env)
    current_plaso_version = backend_vars.get('PLASO_VERSION', 'unknown')

    # Create backups before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    ts_backup = backup_env_file(env_file, logger=log)
    plaso_backup = backup_env_file(backend_env, logger=log) if plaso_version else None

    # pg_dump the live DB BEFORE we stop containers — postgres gives a
    # consistent MVCC snapshot, and dumping a stopped DB is a non-starter.
    # If the dump fails we still proceed (env-backup rollback is better than
    # nothing), but log loudly so the operator knows the safety net is gone.
    db_backup_path = _backup_timesketch_db(current_version, version, logger=log)
    if not db_backup_path:
        log("Proceeding without DB backup — rollback will be config-only if upgrade fails", "warning")

    try:
        # Stop containers
        log("Stopping Timesketch containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Timesketch: {result['error']}")

        # Clear stale pip packages from persistent volume to prevent version conflicts
        log("Clearing stale pip packages from volume...", "info")
        _clear_timesketch_pip_cache(log)

        # Update version in .env
        log(f"Updating Timesketch version to {version}...", "info")
        update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

        # Pull new images
        log("Pulling new Timesketch images...", "info")
        run_command("docker compose pull", cwd=work_dir, timeout=600, logger=log)

        # Pull and update Plaso image if specified
        if plaso_version:
            log(f"Pulling Plaso {plaso_version}...", "info")
            run_command(f"docker pull log2timeline/plaso:{plaso_version}", logger=log, timeout=600)
            log(f"Updating Plaso version to {plaso_version}...", "info")
            update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

        # Start containers
        log("Starting Timesketch containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Timesketch: {result['error']}")

        # Health check - wait for Timesketch container to be ready
        # Use pgrep to check if gunicorn is running (curl not available in container)
        log("Waiting for Timesketch container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking Timesketch container... ({i*5}s)", "info")
            # Check if gunicorn process is running in the container
            check_result = run_command(
                "docker exec intact_timesketch_web pgrep -f gunicorn",
                logger=None
            )
            if check_result['success']:
                pids = check_result.get('stdout', '').strip()
                log(f"  Container healthy - gunicorn running (PIDs: {pids.replace(chr(10), ', ')})", "success")
                healthy = True
                break
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("Timesketch health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_timesketch --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Timesketch failed to start - container status: {container_status}")
            log("Timesketch health check: TIMEOUT (containers may still be starting)", "warning")

        # Run the alembic schema migration from inside the NEW container.
        # This is the step that was missing before — without it the new
        # container code can hit columns/tables the old schema doesn't have,
        # which is what bit the 2024 → 2026 upgrade.
        if not _run_db_schema_upgrade(version, logger=log):
            raise Exception("tsctl db upgrade failed — DB schema is not in sync with new code")

        # Success - cleanup env-file backups. Keep the DB dump on disk so the
        # operator has a manual rollback artifact for the next 24-48h until
        # they're confident the new version is stable.
        cleanup_backup(ts_backup, logger=log)
        if plaso_backup:
            cleanup_backup(plaso_backup, logger=log)
        if db_backup_path:
            log(f"DB backup kept at {db_backup_path} (delete manually once confident)", "info")

        # NOTE: Backend restart NOT needed - Plaso runs as a separate Docker container
        # The new Plaso image will be used when a Plaso job is triggered

        log(f"Timesketch upgrade completed: {current_version} -> {version}", "success")
        result = {"success": True, "version": version, "health": "green" if healthy else "pending"}
        if plaso_version:
            result["plaso_version"] = plaso_version
        if db_backup_path:
            result["db_backup"] = db_backup_path
        return result

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Timesketch upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore backup files
        rollback_env_ok = restore_env_file(env_file, ts_backup, logger=log)
        if rollback_env_ok:
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK Timesketch config to version {current_version}", "warning")

            # With the old-version container back up, restore the pre-upgrade
            # DB so the schema matches what the rolled-back code expects.
            if db_backup_path:
                # Wait briefly for postgres in the rolled-back container to be ready.
                for _ in range(15):
                    chk = run_command(f"docker exec {_PG_CONTAINER} pg_isready -U {_PG_USER}", logger=None)
                    if chk['success']:
                        break
                    time.sleep(2)
                if _restore_timesketch_db(db_backup_path, logger=log):
                    log(f"ROLLED BACK DB from {db_backup_path}", "warning")
                else:
                    log(f"DB restore failed — dump kept at {db_backup_path} for manual recovery", "error")

        if plaso_backup and restore_env_file(backend_env, plaso_backup, logger=log):
            log(f"ROLLED BACK Plaso to version {current_plaso_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
            "db_backup": db_backup_path,
        }


def upgrade_timesketch_offline(package_dir: str, version: str, plaso_version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Timesketch from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Timesketch offline upgrade...", "info")

    # Get current versions for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('TIMESKETCH_VERSION', 'unknown')
    backend_vars = read_env_file(backend_env)
    current_plaso_version = backend_vars.get('PLASO_VERSION', 'unknown')

    # Create backups before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    ts_backup = backup_env_file(env_file, logger=log)
    plaso_backup = backup_env_file(backend_env, logger=log) if plaso_version else None

    # pg_dump the live DB BEFORE stop — same rationale as the online path.
    db_backup_path = _backup_timesketch_db(current_version, version, logger=log)
    if not db_backup_path:
        log("Proceeding without DB backup — rollback will be config-only if upgrade fails", "warning")

    try:
        # Stop containers
        log("Stopping Timesketch containers...", "info")
        result = run_command("docker compose down", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Timesketch: {result['error']}")

        # Clear stale pip packages from persistent volume to prevent version conflicts
        log("Clearing stale pip packages from volume...", "info")
        _clear_timesketch_pip_cache(log)

        # Load docker images
        log("Loading docker images from package...", "info")
        ts_tar = os.path.join(images_dir, f"timesketch-{version}.tar")
        if os.path.exists(ts_tar):
            load_docker_image(ts_tar, logger=log)

        if plaso_version:
            plaso_tar = os.path.join(images_dir, f"plaso-{plaso_version}.tar")
            if os.path.exists(plaso_tar):
                load_docker_image(plaso_tar, logger=log)
            log(f"Updating Plaso version to {plaso_version}...", "info")
            update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

        # Update version in .env
        log(f"Updating Timesketch version to {version}...", "info")
        update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

        # Start containers
        log("Starting Timesketch containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Timesketch: {result['error']}")

        # Health check - wait for Timesketch container to be ready
        # Use pgrep to check if gunicorn is running (like online version)
        log("Waiting for Timesketch container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking Timesketch container... ({i*5}s)", "info")
            # Check if gunicorn process is running in the container
            check_result = run_command(
                "docker exec intact_timesketch_web pgrep -f gunicorn",
                logger=None
            )
            if check_result['success']:
                pids = check_result.get('stdout', '').strip()
                log(f"  Container healthy - gunicorn running (PIDs: {pids.replace(chr(10), ', ')})", "success")
                healthy = True
                break
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("Timesketch health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_timesketch --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Timesketch failed to start - container status: {container_status}")
            log("Timesketch health check: TIMEOUT (containers may still be starting)", "warning")

        # Apply alembic schema migration from inside the new container.
        if not _run_db_schema_upgrade(version, logger=log):
            raise Exception("tsctl db upgrade failed — DB schema is not in sync with new code")

        # Success - cleanup env-file backups; keep the DB dump for manual rollback.
        cleanup_backup(ts_backup, logger=log)
        if plaso_backup:
            cleanup_backup(plaso_backup, logger=log)
        if db_backup_path:
            log(f"DB backup kept at {db_backup_path} (delete manually once confident)", "info")

        # NOTE: Backend restart NOT needed - Plaso runs as a separate Docker container
        # The new Plaso image will be used when a Plaso job is triggered

        log(f"Timesketch offline upgrade completed: {current_version} -> {version}", "success")
        result = {"success": True, "version": version, "health": "green" if healthy else "pending"}
        if plaso_version:
            result["plaso_version"] = plaso_version
        if db_backup_path:
            result["db_backup"] = db_backup_path
        return result

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Timesketch offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        rollback_env_ok = restore_env_file(env_file, ts_backup, logger=log)
        if rollback_env_ok:
            run_command("docker compose down", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK Timesketch config to version {current_version}", "warning")

            if db_backup_path:
                for _ in range(15):
                    chk = run_command(f"docker exec {_PG_CONTAINER} pg_isready -U {_PG_USER}", logger=None)
                    if chk['success']:
                        break
                    time.sleep(2)
                if _restore_timesketch_db(db_backup_path, logger=log):
                    log(f"ROLLED BACK DB from {db_backup_path}", "warning")
                else:
                    log(f"DB restore failed — dump kept at {db_backup_path} for manual recovery", "error")

        if plaso_backup and restore_env_file(backend_env, plaso_backup, logger=log):
            log(f"ROLLED BACK Plaso to version {current_plaso_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
            "db_backup": db_backup_path,
        }
