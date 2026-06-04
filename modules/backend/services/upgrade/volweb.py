"""VolWeb upgrade functions (online + offline/airgap).

The VolWeb in-tree module (``modules/volweb/``) brings up six
containers: backend (Django + daphne), two celery worker queues
(plugins + yarascan), postgres, redis, frontend. An "upgrade" here
means swapping the four pinned images (``volweb_backend``,
``volweb_frontend``, ``volweb_postgres``, ``volweb_redis`` per
``config.yaml:versions``) for newer pins and restarting the stack.

This mirrors the existing per-module upgrade pattern (see
``upgrade/plaso.py`` for the cleanest reference): pull the new
image(s), update the pin in ``modules/volweb/.env``, restart the
container(s). Idempotent on a no-op pin change.

The VolWeb postgres + media volumes are NEVER touched by upgrade.
The on-disk YARA rules + plugin extraction results + memory analyse
reports all survive.
"""

from __future__ import annotations

import os
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
    """Online upgrade — pull the new backend image, bump the pin,
    recreate containers.

    ``version`` is the new value for ``VOLWEB_BACKEND_VERSION``. The
    frontend pin and the postgres/redis pins are updated separately
    via their own upgrade callsites (kept distinct so a single bumped
    version doesn't force a full-stack recreate).
    """
    log = logger or _log_default
    log(f"Starting VolWeb upgrade (backend → {version})...", "info")

    if not os.path.exists(_VOLWEB_ENV):
        msg = f"VolWeb env missing: {_VOLWEB_ENV}. Has install.sh run?"
        log(msg, "error")
        return {"success": False, "error": msg}

    cur = read_env_file(_VOLWEB_ENV).get("VOLWEB_BACKEND_VERSION", "unknown")
    if cur == version:
        log(f"VolWeb already at {version}; no change", "info")
        return {"success": True, "version": version, "noop": True}

    # 1. Pull
    log(f"Pulling forensicxlab/volweb-backend:{version}...", "info")
    pull = run_command(
        f"docker pull forensicxlab/volweb-backend:{version}",
        timeout=600, logger=log, run_id=run_id,
    )
    if not pull.get("success"):
        return {"success": False, "error": f"pull failed: {pull.get('error')}"}

    # 2. Bump the pin
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)

    # 3. Recreate
    log("Recreating VolWeb backend + worker containers...", "info")
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
    log(f"Starting VolWeb offline upgrade (backend → {version})...", "info")

    if not os.path.exists(_VOLWEB_ENV):
        msg = f"VolWeb env missing: {_VOLWEB_ENV}"
        log(msg, "error")
        return {"success": False, "error": msg}

    cur = read_env_file(_VOLWEB_ENV).get("VOLWEB_BACKEND_VERSION", "unknown")
    if cur == version:
        log(f"VolWeb already at {version}; no change", "info")
        return {"success": True, "version": version, "noop": True}

    # 1. Load image from the bundle
    image_tar = os.path.join(package_dir, "images", f"volweb-backend-{version}.tar")
    if not os.path.exists(image_tar):
        return {
            "success": False,
            "error": f"image bundle missing: {image_tar}",
        }
    loaded = load_docker_image(image_tar, logger=log, run_id=run_id)
    if not loaded.get("success"):
        return {"success": False, "error": f"docker load failed: {loaded.get('error')}"}

    # 2. Bump pin + recreate
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        return {"success": False, "error": f"compose up failed: {up.get('error')}"}

    log(f"VolWeb offline upgrade completed: {cur} → {version}", "success")
    return {"success": True, "version": version}


__all__ = ["upgrade_volweb", "upgrade_volweb_offline"]
