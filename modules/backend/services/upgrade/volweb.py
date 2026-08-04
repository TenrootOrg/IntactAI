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
    backup_env_file,
    cleanup_backup,
    load_docker_image,
    read_env_file,
    remove_old_module_image,
    restore_env_file,
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


def _get_volweb_admin_password(logger: Callable = None) -> str:
    """Return the VolWeb admin password, generating + persisting a random
    one on first use if config.yaml doesn't set ``modules.volweb.password``.

    Persisted to ``modules/volweb/secrets/ADMIN_PASSWORD`` — the same file
    lib/modules.sh:get_volweb_admin_password() reads/writes — so whichever
    path seeds the admin user first (bash install.sh or this upgrade-driven
    fresh install) and whatever later reads the creds (e.g. the backend's
    VolWeb API client) all agree. A hardcoded fallback here would ship the
    same publicly-known password to every install that hits this path
    (mirrors lib/modules.sh and _ensure_portainer_admin_secret()).
    """
    log = logger or _log_default
    secrets_dir = os.path.join(_VOLWEB_DIR, "secrets")
    secret_path = os.path.join(secrets_dir, "ADMIN_PASSWORD")
    if os.path.exists(secret_path) and os.path.getsize(secret_path) > 0:
        with open(secret_path) as f:
            return f.read().strip()

    os.makedirs(secrets_dir, exist_ok=True)
    admin_pass = None
    try:
        import yaml
        config_path = os.path.join(HOST_PATH, "config.yaml")
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        volweb_cfg = (cfg.get("modules") or {}).get("volweb") or {}
        admin_pass = volweb_cfg.get("password") or None
    except Exception as e:
        log(f"Could not read VolWeb creds from config.yaml: {e}", "warning")

    if not admin_pass:
        import secrets as _secrets
        admin_pass = _secrets.token_hex(16)
        log("  No VolWeb password set in config.yaml; generated a random one instead", "warning")
        log(f"  Retrieve it with: cat {secret_path}", "warning")

    with open(secret_path, "w") as f:
        f.write(admin_pass)
    os.chmod(secret_path, 0o600)
    return admin_pass


# Transient compose-up error substrings that a retry resolves. The
# big one is the shared-volume init race: VolWeb's image ships
# /home/app/web/media/{symbols,temp_uploads} baked in, so when the 4-6
# containers that mount the shared `volweb_media` volume start nearly
# simultaneously on a FRESH install, docker's per-container
# volume-from-image population races — whichever container loses gets
#   "failed to mkdir .../volweb_media/_data/temp_uploads: file exists"
# (or symbols/). The dirs exist after the first attempt, so a second
# compose-up succeeds cleanly. Verified 2026-06-16. depends_on in the
# compose file serializes START order but NOT docker's volume-init, so
# it can't fully prevent the race on its own — the retry closes it.
_VOLWEB_TRANSIENT_COMPOSE_ERRORS = (
    "file exists",
    "failed to mkdir",
    "device or resource busy",
    "error while creating mount source path",
)


def _compose_up(log: Callable, run_id: str | None = None) -> Dict:
    """Recreate VolWeb containers so they pick up the new image
    + .env values. ``docker compose up -d`` is idempotent — services
    whose image hasn't changed stay running.

    Retries up to 3 times on the known-transient shared-volume init
    race (see _VOLWEB_TRANSIENT_COMPOSE_ERRORS). A permanent error
    (bad image, port conflict, missing env) fails fast on the first
    attempt — we only retry when the error string matches a transient
    pattern.
    """
    host_volweb_dir = _VOLWEB_DIR.replace(WORKDIR, HOST_PATH, 1)
    cmd = (
        f"docker compose -f {host_volweb_dir}/docker-compose.yaml "
        f"--project-directory {host_volweb_dir} up -d"
    )
    max_attempts = 3
    last = None
    for attempt in range(1, max_attempts + 1):
        last = run_command(cmd, timeout=300, logger=log, run_id=run_id)
        if last.get("success"):
            if attempt > 1:
                log(f"  VolWeb compose up succeeded on attempt {attempt} "
                    f"(transient volume-init race cleared)", "success")
            return last
        if last.get("cancelled"):
            return last
        err = (last.get("error") or "") + (last.get("stderr") or "") + (last.get("stdout") or "")
        err_low = err.lower()
        is_transient = any(p in err_low for p in _VOLWEB_TRANSIENT_COMPOSE_ERRORS)
        if not is_transient or attempt == max_attempts:
            if is_transient:
                log(f"  VolWeb compose up still failing after {max_attempts} "
                    f"attempts on the volume-init race — giving up", "error")
            return last
        log(f"  VolWeb compose up hit a transient volume-init race "
            f"(attempt {attempt}/{max_attempts}); the shared-volume dirs "
            f"now exist, retrying in 3s...", "warning")
        import time as _t
        _t.sleep(3)
    return last


# ---------------------------------------------------------------------------
# Air-gap YARA seeding (install + upgrade)
# ---------------------------------------------------------------------------
#
# Stock VolWeb's `yararulesets` table is empty on a fresh install. The
# operator-facing path is `POST /api/yararulesets/import/github/` per
# ruleset — but that requires internet at apply time on the VolWeb
# host. For air-gap targets the prepare side (`package.py` —
# `manifest["contents"]["yara_rulesets"]`) bundles each repo as a
# `.zip` in `package_dir/yara_rulesets/`; the helper below imports
# them from those local bundles via a small in-container Python
# script that mirrors what VolWeb's own `GitHubImportView` does
# internally minus the clone step.
#
# Idempotent — re-runs are safe. The helper looks up YaraRuleSet by
# `name` (get_or_create) and YaraRule by `etag` (which is a hash of
# name+content+source_url, so identical content → same etag → no
# duplicate row, just an update of metadata).

_VOLWEB_BACKEND_CONTAINER = "intact_volweb_backend"

# Python script executed INSIDE the volweb backend container. Imports
# YaraRule + YaraRuleSet from VolWeb's own Django app — no need to
# reverse-engineer the schema. Reads zip paths + names + descriptions
# from environment variables we set on the docker exec call.
_YARA_INGEST_SCRIPT = r"""
import os, sys, re, zipfile, hashlib, tempfile, shutil, json
sys.path.insert(0, '/home/app/web')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
import django
django.setup()
from yararulesets.models import YaraRuleSet
from yararules.models import YaraRule
try:
    from yararules.utils import BatchUploadManager
except Exception:
    BatchUploadManager = None

with open(os.environ['INTACT_YARA_SPECS_FILE']) as _f:
    specs = json.loads(_f.read())
out = {'total': 0, 'rulesets': []}
for spec in specs:
    name = spec['name']
    zip_path = spec['zip_path']
    description = spec.get('description', '')
    source_url = spec.get('source_url', 'bundled')
    if not os.path.exists(zip_path):
        out['rulesets'].append({'name': name, 'error': 'zip missing on container'})
        continue
    ruleset, _ = YaraRuleSet.objects.get_or_create(name=name, defaults={'description': description})
    created = 0
    skipped = 0
    extract_dir = tempfile.mkdtemp(prefix='intact-yara-')
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        yara_files = []
        for root, _, files in os.walk(extract_dir):
            for fn in files:
                low = fn.lower()
                if low.endswith('.yar') or low.endswith('.yara'):
                    yara_files.append(os.path.join(root, fn))
        # BatchUploadManager disables per-rule ruleset validation, so
        # we trigger one final compile at the end instead of N. Mirrors
        # what GitHubImportView does internally.
        ctx = BatchUploadManager(ruleset_id=ruleset.id).batch_context() if BatchUploadManager else None
        if ctx is not None:
            ctx.__enter__()
        try:
            for path in yara_files:
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    rule_name = os.path.splitext(os.path.basename(path))[0]
                    m = re.search(r'rule\s+(\w+)', content)
                    if m:
                        rule_name = m.group(1)
                    etag = hashlib.md5(f"{rule_name}_{content}_{source_url}".encode()).hexdigest()
                    obj, was_created = YaraRule.objects.get_or_create(
                        etag=etag,
                        defaults={
                            'name': rule_name,
                            'rule_content': content,
                            'description': description or f"Imported from bundled package: {os.path.basename(path)}",
                            'linked_yararuleset': ruleset,
                            'source': 'bundled',
                            'url': source_url,
                            'is_active': True,
                        },
                    )
                    if was_created:
                        created += 1
                    else:
                        skipped += 1
                except Exception:
                    continue
        finally:
            if ctx is not None:
                ctx.__exit__(None, None, None)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
    out['total'] += created
    out['rulesets'].append({
        'name': name,
        'files_found': len(yara_files),
        'created': created,
        'skipped_duplicates': skipped,
    })
print('INTACT_YARA_RESULT=' + json.dumps(out))
"""


def _seed_yara_from_bundle(package_dir: str, logger: Callable, run_id: str | None = None) -> Dict:
    """Import the prepare-side-bundled YARA rule zips into VolWeb's
    yararulesets table. Idempotent; safe to call on fresh installs AND
    after every upgrade.

    Expects the manifest at ``{package_dir}/manifest.json`` to list the
    bundled rulesets (`contents.yara_rulesets`), each entry with
    ``filename`` / ``name`` / ``description`` / ``source_url``.
    Each zip lives at ``{package_dir}/yara_rulesets/{filename}``.

    Strategy: docker cp each zip into the volweb backend container's
    /tmp, then docker exec a single Python script that imports them
    all via VolWeb's own ORM (`yararules.models.YaraRule` +
    `yararulesets.models.YaraRuleSet`). This mirrors what
    `GitHubImportView` does internally without the network step.

    Returns ``{"success": bool, "imported": int, "rulesets": [...]}``.
    Soft-fails on any error — caller logs the result but doesn't
    fail the install/upgrade over a YARA seed hiccup.
    """
    log = logger or _log_default
    import json

    manifest_path = os.path.join(package_dir, 'manifest.json')
    if not os.path.exists(manifest_path):
        log("  YARA seed: package manifest missing — skipping", "warning")
        return {"success": False, "error": "manifest missing"}
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception as e:
        log(f"  YARA seed: failed to parse manifest ({e}) — skipping", "warning")
        return {"success": False, "error": f"manifest parse error: {e}"}

    yara_entries = (manifest.get('contents') or {}).get('yara_rulesets') or []
    if not yara_entries:
        log("  YARA seed: no rulesets bundled in package (operator can run "
            "Maintenance → Refresh YARA Rulesets to seed online).", "info")
        return {"success": True, "imported": 0, "rulesets": []}

    yara_dir = os.path.join(package_dir, 'yara_rulesets')
    log(f"  YARA seed: importing {len(yara_entries)} bundled ruleset(s) "
        f"into VolWeb...", "info")

    # Verify volweb backend is up before trying to docker cp / exec.
    chk = run_command(
        f"docker inspect -f '{{{{.State.Running}}}}' {_VOLWEB_BACKEND_CONTAINER}",
        logger=None, timeout=10,
    )
    if not (chk.get('success') and 'true' in (chk.get('stdout') or '').lower()):
        log(f"  YARA seed: {_VOLWEB_BACKEND_CONTAINER} not running — "
            f"skipping (operator can run Maintenance → Refresh YARA Rulesets later)", "warning")
        return {"success": False, "error": "volweb backend not running"}

    # Copy each zip into the container and build the spec list
    # describing what the in-container script should import.
    specs = []
    for entry in yara_entries:
        fname = entry.get('filename')
        name = entry.get('name')
        if not fname or not name:
            continue
        src = os.path.join(yara_dir, fname)
        if not os.path.exists(src):
            log(f"    ✗ {name}: bundled zip missing on disk ({src})", "warning")
            continue
        # docker cp the zip into /tmp/intact-yara/ in the container.
        host_src = src.replace(WORKDIR, HOST_PATH, 1)
        container_path = f"/tmp/intact-yara-{fname}"
        cp = run_command(
            f"docker cp {host_src} {_VOLWEB_BACKEND_CONTAINER}:{container_path}",
            logger=None, timeout=120,
        )
        if not cp.get('success'):
            log(f"    ✗ {name}: docker cp failed ({cp.get('error', '')[:100]})", "warning")
            continue
        specs.append({
            'name': name,
            'zip_path': container_path,
            'description': entry.get('description', ''),
            'source_url': entry.get('source_url', 'bundled'),
        })

    if not specs:
        log("  YARA seed: no zips successfully copied; aborting", "warning")
        return {"success": False, "error": "no zips copied"}

    # Run the ingest script via docker exec. The script reads the spec
    # list from INTACT_YARA_SPECS env var (avoids quoting nightmares
    # of inlining JSON into a shell argument). The script's `print`
    # at the end emits a parseable result line.
    script_path = f"/tmp/intact-yara-ingest.py"
    write_cmd = (
        f"docker exec -i {_VOLWEB_BACKEND_CONTAINER} "
        f"sh -c 'cat > {script_path}'"
    )
    # Use subprocess directly with stdin to avoid shell-quote breakage
    try:
        _subprocess.run(
            write_cmd, input=_YARA_INGEST_SCRIPT,
            shell=True, check=True, text=True, timeout=30,
        )
    except Exception as e:
        log(f"    ✗ YARA seed: couldn't write ingest script ({e})", "warning")
        return {"success": False, "error": f"script write failed: {e}"}

    # Write the specs JSON into the container as a file so the script
    # can read it. Avoids stuffing multi-KB JSON through the exec
    # command line / env vars (some kernels cap env to 128 KB).
    specs_json = json.dumps(specs)
    specs_path = "/tmp/intact-yara-specs.json"
    try:
        _subprocess.run(
            f"docker exec -i {_VOLWEB_BACKEND_CONTAINER} sh -c 'cat > {specs_path}'",
            input=specs_json, shell=True, check=True, text=True, timeout=30,
        )
    except Exception as e:
        log(f"    ✗ YARA seed: couldn't write spec file ({e})", "warning")
        return {"success": False, "error": f"spec write failed: {e}"}

    # Run the script — point it at the in-container specs file via
    # env var. Reading the JSON from a file inside the container
    # sidesteps the docker-exec command-substitution + shell-quote
    # nightmare of inlining JSON into the exec command line.
    run = run_command(
        f"docker exec --user app "
        f"-e INTACT_YARA_SPECS_FILE={specs_path} "
        f"{_VOLWEB_BACKEND_CONTAINER} python {script_path}",
        logger=None, timeout=900, run_id=run_id,
    )

    # Cleanup zips and scripts inside the container (best-effort).
    cleanup_paths = " ".join(s['zip_path'] for s in specs) + f" {script_path} {specs_path}"
    run_command(
        f"docker exec {_VOLWEB_BACKEND_CONTAINER} rm -f {cleanup_paths}",
        logger=None, timeout=30,
    )

    if not run.get('success'):
        log(f"  YARA seed: ingest script failed: "
            f"{(run.get('error') or run.get('stderr') or '')[:200]}", "warning")
        return {"success": False, "error": "ingest script failed"}

    stdout = run.get('stdout', '') or ''
    result_line = None
    for line in stdout.splitlines():
        if line.startswith('INTACT_YARA_RESULT='):
            result_line = line[len('INTACT_YARA_RESULT='):]
            break
    if not result_line:
        log(f"  YARA seed: ingest script ran but didn't emit result "
            f"(stdout: {stdout[-200:]})", "warning")
        return {"success": False, "error": "no result line"}

    try:
        result = json.loads(result_line)
    except Exception as e:
        log(f"  YARA seed: couldn't parse result line ({e})", "warning")
        return {"success": False, "error": f"result parse: {e}"}

    total = result.get('total', 0)
    log(f"  YARA seed: imported {total} new rules across "
        f"{len(result.get('rulesets', []))} ruleset(s)", "success")
    for rs in result.get('rulesets', []):
        if 'error' in rs:
            log(f"    ✗ {rs['name']}: {rs['error']}", "warning")
        else:
            log(f"    ✓ {rs['name']}: "
                f"{rs.get('files_found', 0)} files → "
                f"{rs.get('created', 0)} new, "
                f"{rs.get('skipped_duplicates', 0)} already present", "info")

    return {"success": True, "imported": total, "rulesets": result.get('rulesets', [])}


# Curated YARA rulesets seeded into VolWeb. Online upgrade imports them
# straight from GitHub (it has internet); the offline paths seed the same rules
# from bundled zips via _seed_yara_from_bundle. Kept in lockstep with
# routes/maintenance_routes._YARA_RULESETS.
_GITHUB_YARA_RULESETS = [
    {"name": "Neo23x0 signature-base",
     "github_url": "https://github.com/Neo23x0/signature-base",
     "description": "Florian Roth's curated YARA rules"},
    {"name": "Elastic protections",
     "github_url": "https://github.com/elastic/protections-artifacts",
     "description": "Elastic security YARA detection rules"},
]


def _seed_yara_from_github(logger: Callable, run_id: str | None = None) -> Dict:
    """Import the curated YARA rulesets into VolWeb directly from GitHub.

    Online counterpart of _seed_yara_from_bundle (which seeds from package
    zips). Best-effort: a YARA import failure must never fail the upgrade — the
    operator can always re-run Settings → Maintenance → Refresh YARA Rulesets.
    """
    def log(m, level="info"):
        if logger:
            try:
                logger(m, level)
            except Exception:
                pass

    try:
        from services.memory.volweb_client import VolWebClient
        client = VolWebClient(logger=lambda m, lvl="info": log(m, lvl))
    except Exception as e:
        log(f"YARA seed skipped: VolWeb client unavailable ({e})", "warning")
        return {"success": False, "error": str(e)}

    imported = 0
    for rs in _GITHUB_YARA_RULESETS:
        try:
            client._post_json("/api/yararulesets/import/github/", rs, timeout=600)
            log(f"YARA seed: imported {rs['name']} from GitHub", "info")
            imported += 1
        except Exception as e:
            log(f"YARA seed: {rs['name']} failed: {e}", "warning")
    return {"success": imported > 0, "imported": imported}


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

    # 2. Bump both pins — with a .env backup first so a failed recreate can
    # roll back instead of leaving the pins bumped over a broken stack
    # (VolWeb previously had NO rollback; this mirrors the elk.py pattern).
    backup_file = backup_env_file(_VOLWEB_ENV, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_FRONTEND_VERSION", version, logger=log)

    # 3. Recreate
    log("Recreating VolWeb backend + frontend + worker containers...", "info")
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        log("Compose up failed — rolling back VolWeb pins to the previous version...", "error")
        if backup_file and restore_env_file(_VOLWEB_ENV, backup_file, logger=log):
            rb = _compose_up(log, run_id=run_id)
            if rb.get("success"):
                log(f"Rollback complete — VolWeb back on {cur}", "success")
            else:
                log(f"Rollback compose up also failed: {rb.get('error')}", "error")
        return {"success": False, "rolled_back": True,
                "error": f"compose up failed: {up.get('error')}"}
    if backup_file:
        cleanup_backup(backup_file, logger=log)

    # Seed YARA rulesets from GitHub — online parity with the offline bundle
    # seeding, so rules are present after an upgrade without the operator
    # having to run Maintenance → Refresh YARA. Best-effort.
    try:
        _seed_yara_from_github(logger=log, run_id=run_id)
    except Exception as e:
        log(f"YARA ruleset seeding skipped: {e}", "warning")

    log(f"VolWeb upgrade completed: {cur} → {version}", "success")
    remove_old_module_image('volweb', cur, version, logger=log)
    # Honest health verdict (G5). VolWeb runs 'report' policy (never
    # auto-rollback on timeout) until its new rollback path is field-proven —
    # but the verdict is carried in the result so the run summary can flag a
    # degraded/down stack instead of the old silent success.
    from .base import enforce_module_health
    health = enforce_module_health('volweb', timeout=120, logger=log)
    return {"success": True, "version": version,
            "health": health["health"], "health_detail": health["detail"]}


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

    # 1. Load every bundled image. Same rationale as timesketch's
    # upgrade path: VolWeb's compose declares two sidecars
    # (volweb_postgres, volweb_redis) whose tags can drift between
    # install and upgrade. Loading only the primary tars would leave
    # compose-up to find sidecars in the local docker store — which
    # fails air-gap with "No such image" the moment a sidecar pin
    # bumps. load_all_bundled_images is idempotent (docker load on
    # an already-loaded image is a no-op).
    #
    # Sanity: confirm the primary backend tar is bundled before we
    # commit to the version bump — without it, compose-up would
    # silently start the stack at the old pin and the operator
    # would think the upgrade succeeded.
    backend_tar = os.path.join(package_dir, "images", f"volweb-backend-{version}.tar")
    if not os.path.exists(backend_tar):
        return {
            "success": False,
            "error": f"image bundle missing: {backend_tar}",
        }
    from .base import load_all_bundled_images
    load_all_bundled_images(package_dir, logger=log, run_id=run_id)
    frontend_tar = os.path.join(package_dir, "images", f"volweb-frontend-{version}.tar")
    if not os.path.exists(frontend_tar):
        log(f"frontend image bundle absent ({frontend_tar}) — frontend stays on current pin", "warning")

    # 2. Bump both pins + recreate — with a .env backup so a failed recreate
    # rolls back instead of leaving bumped pins over a broken stack (mirrors
    # the elk.py pattern; VolWeb previously had NO rollback).
    backup_file = backup_env_file(_VOLWEB_ENV, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_BACKEND_VERSION", version, logger=log)
    update_env_file(_VOLWEB_ENV, "VOLWEB_FRONTEND_VERSION", version, logger=log)
    up = _compose_up(log, run_id=run_id)
    if not up.get("success"):
        log("Compose up failed — rolling back VolWeb pins to the previous version...", "error")
        if backup_file and restore_env_file(_VOLWEB_ENV, backup_file, logger=log):
            rb = _compose_up(log, run_id=run_id)
            if rb.get("success"):
                log(f"Rollback complete — VolWeb back on {cur}", "success")
            else:
                log(f"Rollback compose up also failed: {rb.get('error')}", "error")
        return {"success": False, "rolled_back": True,
                "error": f"compose up failed: {up.get('error')}"}
    if backup_file:
        cleanup_backup(backup_file, logger=log)

    # Re-seed YARA rules from the bundled rule sources. Idempotent
    # via etag-based de-duplication in the in-container script — safe
    # to run on every upgrade. Covers the cross-major case where the
    # operator was on volweb<3.16 (no yararulesets table) and the
    # upgrade brought them up to a YARA-aware version: the table now
    # exists but is empty, so seeding here populates it.
    try:
        _seed_yara_from_bundle(package_dir, logger=log, run_id=run_id)
    except Exception as _e:
        log(f"  YARA re-seed raised ({type(_e).__name__}: {_e}); "
            f"upgrade still succeeded — operator can refresh via "
            f"Maintenance → Refresh YARA Rulesets if needed.", "warning")

    log(f"VolWeb offline upgrade completed: {cur} → {version}", "success")
    remove_old_module_image('volweb', cur, version, logger=log)
    # Honest health verdict (G5). VolWeb runs 'report' policy (never
    # auto-rollback on timeout) until its new rollback path is field-proven —
    # but the verdict is carried in the result so the run summary can flag a
    # degraded/down stack instead of the old silent success.
    from .base import enforce_module_health
    health = enforce_module_health('volweb', timeout=120, logger=log)
    return {"success": True, "version": version,
            "health": health["health"], "health_detail": health["detail"]}


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
    # Need to render the template when secrets are missing — not just
    # when the file doesn't exist. The orchestrator's pre-stamp may have
    # CREATED a bare .env with only POSTGRES_VERSION/REDIS_VERSION lines
    # (apply-side stamp_transitive_env_from_manifest); without
    # VOLWEB_POSTGRES_USER + DJANGO_SECRET + etc. compose up fails on
    # the missing env interpolation. Detect "secrets missing" by
    # checking for VOLWEB_POSTGRES_USER specifically.
    needs_render = True
    if os.path.exists(_VOLWEB_ENV):
        try:
            with open(_VOLWEB_ENV) as f:
                existing = f.read()
            if 'VOLWEB_POSTGRES_USER=' in existing and 'VOLWEB_DJANGO_SECRET=' in existing:
                needs_render = False
        except Exception:
            pass
    if needs_render:
        log(f"  Rendering {_VOLWEB_ENV} from .env.template "
            f"(secrets missing — first-time install)...", "info")
        # Preserve any transitive-version lines the orchestrator's
        # stamp wrote, so they survive the template render.
        preserved = {}
        if os.path.exists(_VOLWEB_ENV):
            try:
                with open(_VOLWEB_ENV) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('VOLWEB_POSTGRES_VERSION=') or \
                           line.startswith('VOLWEB_REDIS_VERSION='):
                            k, _, v = line.partition('=')
                            preserved[k] = v
            except Exception:
                pass
        with open(env_template) as f:
            content = f.read()
        # POSTGRES/REDIS pins come from config.yaml's
        # `versions.volweb_postgres` and `versions.volweb_redis` after the
        # 2026-06-14 refactor. The hardcoded "15" and "7" that used to
        # live here were the source of the install-vs-upgrade postgres
        # drift bug — install used 15 from this hardcode, upgrade pulled
        # 14.1 from upstream, postgres-14 refused to start against
        # postgres-15 data. Read from config.yaml so install + upgrade
        # converge.
        from .package import _read_config_yaml_versions
        cfg_versions = _read_config_yaml_versions()
        volweb_pg = cfg_versions.get('volweb_postgres')
        volweb_rd = cfg_versions.get('volweb_redis')
        if not volweb_pg or not volweb_rd:
            return {
                "success": False,
                "error": (
                    "versions.volweb_postgres and versions.volweb_redis "
                    "must be set in config.yaml. The 2026-06-14 refactor "
                    "moved transitive sidecar pins out of hardcoded "
                    "Python defaults; check the config.yaml `versions:` "
                    "block."
                ),
            }
        substitutions = {
            "__VOLWEB_BACKEND_VERSION__":  version or 'latest',
            "__VOLWEB_FRONTEND_VERSION__": version or 'latest',
            "__VOLWEB_POSTGRES_VERSION__": volweb_pg,
            "__VOLWEB_REDIS_VERSION__":    volweb_rd,
            "__VOLWEB_POSTGRES_PASSWORD__": _secrets.token_hex(24),
            "__VOLWEB_DJANGO_SECRET__":    _secrets.token_hex(32),
            "__VOLWEB_CSRF_TRUSTED_ORIGINS__": "http://localhost:3000,https://localhost",
        }
        for ph, val in substitutions.items():
            content = content.replace(ph, val)
        with open(_VOLWEB_ENV, "w") as f:
            f.write(content)
        log(f"  .env rendered (postgres={volweb_pg}, redis={volweb_rd} "
            f"from config.yaml)", "success")

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

    # Stamp transitive container versions from the bundled manifest
    # (VOLWEB_POSTGRES_VERSION, VOLWEB_REDIS_VERSION) into
    # modules/volweb/.env BEFORE compose up. The compose file's
    # `${VAR:?...}` interpolation will fail without these.
    from .base import stamp_transitive_env_from_manifest
    try:
        stamp_transitive_env_from_manifest('volweb', package_dir, logger=log)
    except Exception as _e:
        log(f"  transitive .env stamp raised "
            f"({type(_e).__name__}: {_e}); compose up will likely fail",
            "warning")

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
    # 300s budget (was 180; warning text said 120 which was already
    # stale). Bumped on 2026-06-11 to match Timesketch / Velociraptor /
    # ELK so the whole upgrade suite survives slow-disk machines without
    # silently degrading to "completed with warning" state.
    _BACKEND_READY_WAIT_SECS = 300
    while waited < _BACKEND_READY_WAIT_SECS:
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
        # Heartbeat every 30 s so the operator knows we haven't hung.
        if waited and waited % 30 == 0:
            log(f"  …still waiting for VolWeb backend ({waited}s elapsed of "
                f"{_BACKEND_READY_WAIT_SECS}s budget)", "info")
        time.sleep(5)
        waited += 5

    if not backend_ready:
        log(
            f"VolWeb backend did not become ready after "
            f"{_BACKEND_READY_WAIT_SECS}s. Containers ARE running, but "
            f"admin-user seeding has been SKIPPED — operator must seed "
            f"manually: `docker exec intact_volweb_backend "
            f"python3 manage.py createsuperuser`. Continuing.",
            "warning",
        )
        return {"success": True, "version": version, "first_install": True}

    # Stage 2: seed the platform's tenroot admin user from config.yaml.
    # Same payload + Django shell call lib/modules.sh:seed_volweb_admin uses.
    admin_user = "tenroot"
    try:
        import yaml
        config_path = os.path.join(HOST_PATH, "config.yaml")
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        volweb_cfg = (cfg.get("modules") or {}).get("volweb") or {}
        admin_user = volweb_cfg.get("id") or "tenroot"
    except Exception as e:
        log(f"Could not read VolWeb creds from config.yaml: {e}", "warning")
    admin_pass = _get_volweb_admin_password(logger=log)

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

    # Seed YARA rules from the bundled rule sources. Same helper the
    # upgrade path uses. Idempotent via etag-based de-dup, so running
    # this here AND later from Maintenance → Refresh is safe.
    try:
        seed_result = _seed_yara_from_bundle(package_dir, logger=log, run_id=run_id)
        if seed_result.get('success') and seed_result.get('imported', 0) > 0:
            log(f"  YARA corpus seeded automatically from bundled sources "
                f"({seed_result.get('imported')} rules)", "success")
        elif not seed_result.get('success'):
            log("  YARA bundle seed did not run — operator can use "
                "Settings → Maintenance → 'Refresh YARA Rulesets' to seed online.",
                "info")
    except Exception as _e:
        log(f"  YARA seed raised ({type(_e).__name__}: {_e}); "
            f"install still succeeded — operator can run Maintenance → "
            f"Refresh YARA Rulesets manually.", "warning")

    log("VolWeb first-time install complete", "success")
    return {"success": True, "version": version, "first_install": True}


__all__ = ["upgrade_volweb", "upgrade_volweb_offline", "install_volweb_offline"]
