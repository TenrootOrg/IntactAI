"""VolWeb upgrade functions (online + offline/airgap).

The VolWeb in-tree module (``modules/volweb/``) brings up six
containers: backend (Django + daphne), two celery worker queues
(plugins + yarascan), postgres, redis, frontend. An "upgrade" here
means swapping the backend + frontend image pins (driven by the
single ``versions.volweb`` pin in ``config.yaml`` — forensicxlab
ships the two images in lockstep) and restarting the stack. Postgres
and Redis are infrastructure deps defaulted in
``modules/volweb/docker-compose.yaml`` and are not bumped by this flow.

This mirrors the existing per-module upgrade pattern (see
``upgrade/plaso.py`` for the cleanest reference): pull the new
image(s), update the pin(s) in ``modules/volweb/.env``, restart the
container(s). Idempotent on a no-op pin change.

The VolWeb postgres + media volumes are NEVER touched by upgrade.
The on-disk YARA rules + plugin extraction results + memory analyse
reports all survive.
"""

from __future__ import annotations

import os
import time
import subprocess as _subprocess
from typing import Callable, Dict

from .base import (
    HOST_PATH,
    WORKDIR,
    load_docker_image,
    read_env_file,
    run_command,
    update_env_file,
)


_VOLWEB_DIR = os.path.join(WORKDIR, "modules", "volweb")
_VOLWEB_ENV = os.path.join(_VOLWEB_DIR, ".env")

# Containers we restart on a backend image bump. The frontend +
# postgres + redis are independent — bumped only if their own pin
# changes (handled by the dispatcher in `__init__.py`).
_BACKEND_CONTAINERS = (
    "intact_volweb_backend",
    "intact_volweb_workers",
    "intact_volweb_workers_yarascan",
)


def _log_default(msg: str, level: str = "info") -> None:
    print(f"[{level}] {msg}", flush=True)


def _compose_up(log: Callable, run_id: str | None = None) -> Dict:
    """Recreate VolWeb containers so they pick up the new image
    + .env values. ``docker compose up -d`` is idempotent — services
    whose image hasn't changed stay running.
    """
    host_volweb_dir = _VOLWEB_DIR.replace(WORKDIR, HOST_PATH, 1)
    return run_command(
        f"docker compose -f {host_volweb_dir}/docker-compose.yaml "
        f"--project-directory {host_volweb_dir} up -d",
        timeout=300, logger=log, run_id=run_id,
    )


def upgrade_volweb(version: str, logger: Callable = None, run_id: str | None = None) -> Dict:
    """Online upgrade — pull the new backend + frontend images, bump
    both pins, recreate containers.

    ``version`` is a single semver tag that drives BOTH
    ``VOLWEB_BACKEND_VERSION`` and ``VOLWEB_FRONTEND_VERSION``.
    forensicxlab releases the two images in lockstep (same tag, same
    push date), so a single operator-supplied version is sufficient.
    Postgres + Redis pins are not touched — they're infrastructure
    deps defaulted in modules/volweb/docker-compose.yaml.
    """
    log = logger or _log_default
    log(f"Starting VolWeb upgrade (backend + frontend → {version})...", "info")

    if not os.path.exists(_VOLWEB_ENV):
        msg = f"VolWeb env missing: {_VOLWEB_ENV}. Has install.sh run?"
        log(msg, "error")
        return {"success": False, "error": msg}

    cur = read_env_file(_VOLWEB_ENV).get("VOLWEB_BACKEND_VERSION", "unknown")
    if cur == version:
        log(f"VolWeb already at {version}; no change", "info")
        return {"success": True, "version": version, "noop": True}

    # 1. Pull both images
    for image in ("forensicxlab/volweb-backend", "forensicxlab/volweb-frontend"):
        log(f"Pulling {image}:{version}...", "info")
        pull = run_command(
            f"docker pull {image}:{version}",
            timeout=600, logger=log, run_id=run_id,
        )
        if not pull.get("success"):
            return {"success": False, "error": f"pull {image} failed: {pull.get('error')}"}

    # 2. Bump both pins
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_FRONTEND_VERSION", version, logger=log)

    # 3. Recreate
    log("Recreating VolWeb backend + frontend + worker containers...", "info")
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        return {"success": False, "error": f"compose up failed: {up.get('error')}"}

    log(f"VolWeb upgrade completed: {cur} → {version}", "success")
    return {"success": True, "version": version}


def upgrade_volweb_offline(
    package_dir: str,
    version: str,
    logger: Callable = None,
    run_id: str | None = None,
) -> Dict:
    """Airgap upgrade — load the bundled image tar from the prepared
    package, then recreate.

    Expects the prepare-package step to have placed:
      <package_dir>/images/volweb-backend-<version>.tar
    (mirrors the timesketch / plaso bundling convention).
    """
    log = logger or _log_default
    log(f"Starting VolWeb offline upgrade (backend + frontend → {version})...", "info")

    if not os.path.exists(_VOLWEB_ENV):
        msg = f"VolWeb env missing: {_VOLWEB_ENV}"
        log(msg, "error")
        return {"success": False, "error": msg}

    cur = read_env_file(_VOLWEB_ENV).get("VOLWEB_BACKEND_VERSION", "unknown")
    if cur == version:
        log(f"VolWeb already at {version}; no change", "info")
        return {"success": True, "version": version, "noop": True}

    # 1. Load both images from the bundle. Backend is required;
    # frontend is best-effort (a transitional prepare-package built
    # before this refactor will only bundle the backend, in which case
    # the frontend stays on whatever's already pulled).
    backend_tar = os.path.join(package_dir, "images", f"volweb-backend-{version}.tar")
    if not os.path.exists(backend_tar):
        return {
            "success": False,
            "error": f"image bundle missing: {backend_tar}",
        }
    loaded = load_docker_image(backend_tar, logger=log, run_id=run_id)
    if not loaded.get("success"):
        return {"success": False, "error": f"docker load failed (backend): {loaded.get('error')}"}

    frontend_tar = os.path.join(package_dir, "images", f"volweb-frontend-{version}.tar")
    if os.path.exists(frontend_tar):
        loaded = load_docker_image(frontend_tar, logger=log, run_id=run_id)
        if not loaded.get("success"):
            log(f"frontend image load failed (continuing with current frontend): {loaded.get('error')}", "warning")
    else:
        log(f"frontend image bundle absent ({frontend_tar}) — frontend stays on current pin", "warning")

    # 2. Bump both pins + recreate
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_FRONTEND_VERSION", version, logger=log)
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        return {"success": False, "error": f"compose up failed: {up.get('error')}"}

    log(f"VolWeb offline upgrade completed: {cur} → {version}", "success")
    return {"success": True, "version": version}


# ---------------------------------------------------------------------------
# Fresh-install path — picked by the apply orchestrator when the
# intact_volweb_backend container is absent on the host.
# ---------------------------------------------------------------------------

def install_volweb_offline(
    package_dir: str,
    version: str,
    logger: Callable = None,
    run_id: str | None = None,
) -> Dict:
    """Fresh install of VolWeb from an offline upgrade package.

    Mirrors what lib/modules.sh:deploy_volweb does at install time,
    scoped to what's reachable from inside the backend container:
      1. Render modules/volweb/.env from .env.template with random
         per-install secrets (DJANGO_SECRET, POSTGRES_PASSWORD).
      2. Pre-create the intact_memory_dumps shared docker volume.
      3. Load bundled images from the offline package if present.
      4. docker compose up -d.

    Post-install seeding (YARA rulesets, VolWeb admin user) is left
    to the operator — Maintenance → Refresh YARA Rulesets handles
    it once the stack is up.
    """
    log = logger or _log_default
    import secrets as _secrets

    log("VolWeb not currently installed — running first-time install...", "info")

    env_template = os.path.join(_VOLWEB_DIR, ".env.template")
    if not os.path.exists(env_template):
        return {
            "success": False,
            "error": (
                f".env.template missing at {env_template} — upgrade the "
                "Intact.AI source first so the VolWeb template lands on disk"
            ),
        }
    if not os.path.exists(_VOLWEB_ENV):
        log(f"  Rendering {_VOLWEB_ENV} from .env.template...", "info")
        with open(env_template) as f:
            content = f.read()
        substitutions = {
            "__VOLWEB_BACKEND_VERSION__":  version or 'latest',
            "__VOLWEB_FRONTEND_VERSION__": version or 'latest',
            "__VOLWEB_POSTGRES_VERSION__": "15",
            "__VOLWEB_REDIS_VERSION__":    "7",
            "__VOLWEB_POSTGRES_PASSWORD__": _secrets.token_hex(24),
            "__VOLWEB_DJANGO_SECRET__":    _secrets.token_hex(32),
            "__VOLWEB_CSRF_TRUSTED_ORIGINS__": "http://localhost:3000,https://localhost",
        }
        for ph, val in substitutions.items():
            content = content.replace(ph, val)
        with open(_VOLWEB_ENV, "w") as f:
            f.write(content)
        log("  .env rendered", "success")

    log("  Ensuring shared volume `intact_memory_dumps`...", "info")
    run_command("docker volume create intact_memory_dumps", logger=None)

    # Load every bundled image in /images/ — covers volweb-backend,
    # volweb-frontend, AND the base images compose needs (postgres,
    # redis). Previously this loop only matched `volweb-backend`/
    # `volweb-frontend` tarballs and assumed postgres + redis could be
    # pulled at compose-up time — true for internet-connected installs
    # but BROKEN air-gapped (compose fails with "failed to fetch
    # anonymous token" trying to pull postgres:15 from Docker Hub).
    # The generic helper loads everything in /images/, idempotent on
    # already-loaded images.
    from .base import load_all_bundled_images
    load_all_bundled_images(package_dir, logger=log, run_id=run_id)

    log("  docker compose up -d ...", "info")
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        return {"success": False, "error": f"compose up failed: {up.get('error')}"}

    # Post-install bootstrap — without this, the install reports success
    # but the IntactAI backend can never authenticate to VolWeb's REST
    # API because no admin user exists in VolWeb's Django auth. Operator
    # sees "VolWeb shows no connection" / memory module unable to
    # dispatch jobs. Mirrors lib/modules.sh:deploy_volweb post-compose.
    log("VolWeb containers up. Waiting for backend + seeding admin user...", "info")

    # Stage 1: wait for VolWeb's DB migrations to finish. The Django
    # shell can boot ~immediately (before postgres migrations are
    # done), so a `print('READY')` probe alone returns success too
    # early — we then hit "relation auth_user does not exist" inside
    # the seed step. Check the actual table existence:
    # `User.objects.exists()` will throw if the auth_user table isn't
    # there yet. Catch that and keep polling. When the call returns 0
    # AND prints SCHEMA_OK, migrations are done and seeding will work.
    backend_ready = False
    waited = 0
    probe_script = (
        "from django.contrib.auth import get_user_model\n"
        # `.exists()` runs a SELECT against auth_user; throws
        # ProgrammingError if migrations haven't created the table yet.
        "get_user_model().objects.exists()\n"
        "print('SCHEMA_OK')\n"
    )
    while waited < 180:
        try:
            probe = _subprocess.run(
                ["docker", "exec", "--user", "app", "-w", "/home/app/web", "-i",
                 "intact_volweb_backend", "python3", "manage.py", "shell"],
                input=probe_script,
                capture_output=True, text=True, timeout=20,
            )
            if probe.returncode == 0 and "SCHEMA_OK" in (probe.stdout or ""):
                backend_ready = True
                log(f"  VolWeb backend + DB ready ({waited}s)", "success")
                break
        except _subprocess.TimeoutExpired:
            pass  # exec itself hung — keep polling
        except Exception:
            pass
        time.sleep(5)
        waited += 5

    if not backend_ready:
        log(
            "VolWeb backend did not become ready after 120s. Containers ARE "
            "running, but admin-user seeding has been SKIPPED — operator "
            "must seed manually: `docker exec intact_volweb_backend "
            "python3 manage.py createsuperuser`. Continuing.",
            "warning",
        )
        return {"success": True, "version": version, "first_install": True}

    # Stage 2: seed the platform's tenroot admin user from config.yaml.
    # Same payload + Django shell call lib/modules.sh:seed_volweb_admin uses.
    try:
        import yaml
        config_path = os.path.join(HOST_PATH, "config.yaml")
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        volweb_cfg = (cfg.get("modules") or {}).get("volweb") or {}
        admin_user = volweb_cfg.get("id") or "tenroot"
        admin_pass = volweb_cfg.get("password") or "123123"
    except Exception as e:
        log(f"Could not read VolWeb creds from config.yaml: {e}", "warning")
        admin_user, admin_pass = "tenroot", "123123"

    log(f"  Seeding VolWeb admin user ({admin_user})...", "info")
    # Pass the script via stdin (manage.py shell reads from stdin) and
    # interpolate the creds via Python repr() — never via the shell —
    # so a password with special chars can't break the call.
    # run_command() doesn't expose stdin, so use subprocess directly.
    django_script = (
        "from django.contrib.auth import get_user_model\n"
        "U = get_user_model()\n"
        f"u, created = U.objects.get_or_create(username={admin_user!r}, "
        "defaults={'is_superuser': True, 'is_staff': True})\n"
        "u.is_superuser = True\n"
        "u.is_staff = True\n"
        f"u.set_password({admin_pass!r})\n"
        "u.save()\n"
        "print('CREATED' if created else 'UPDATED', 'admin', u.username)\n"
    )
    try:
        proc = _subprocess.run(
            ["docker", "exec", "--user", "app", "-w", "/home/app/web", "-i",
             "intact_volweb_backend", "python3", "manage.py", "shell"],
            input=django_script,
            capture_output=True, text=True, timeout=60,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 and ("CREATED" in out or "UPDATED" in out):
            log(f"  VolWeb admin '{admin_user}' seeded — backend API auth ready", "success")
        else:
            log(
                f"  VolWeb admin seeding returned rc={proc.returncode}: {out[:200]}. "
                f"Fix manually: `docker exec --user app -w /home/app/web -i "
                f"intact_volweb_backend python3 manage.py createsuperuser`. "
                "Continuing.",
                "warning",
            )
    except _subprocess.TimeoutExpired:
        log("  VolWeb admin seeding timed out (60s). Containers up but "
            "admin not seeded; run createsuperuser manually.", "warning")
    except Exception as e:
        log(f"  VolWeb admin seeding errored: {e}. Continuing.", "warning")

    log("VolWeb first-time install complete", "success")
    log(
        "  Next step (operator): Settings → Maintenance → 'Refresh YARA Rulesets' "
        "to seed the YARA corpus (3 sources, ~3 min, idempotent).",
        "info",
    )
    return {"success": True, "version": version, "first_install": True}


__all__ = ["upgrade_volweb", "upgrade_volweb_offline", "install_volweb_offline"]
