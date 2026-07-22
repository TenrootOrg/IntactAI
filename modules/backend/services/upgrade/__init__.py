#!/usr/bin/env python3
"""
Upgrade Service Package - Module upgrade functions for Intact.AI platform.
Supports upgrading: ELK, Timesketch, IRIS, Velociraptor, Backend, Frontend

Two-Phase Upgrade Support:
- Phase 1: Upgrades Intact.AI (backend code), saves state, triggers restart
- Phase 2: Resumes after restart, upgrades remaining modules
"""

import json
import os
import re
import shutil
import subprocess
from typing import Dict, Callable, Optional

# Base utilities
from .base import (
    WORKDIR,
    HOST_PATH,
    run_command,
    read_env_file,
    update_env_file,
    compare_versions,
    get_current_versions,
    get_latest_versions,
    load_docker_image,
    verify_upgrade_package,
    get_package_info,
)

# Module-specific upgrade functions
from .elk import upgrade_elk, upgrade_elk_offline
from .timesketch import upgrade_timesketch, upgrade_timesketch_offline
from .iris import upgrade_iris, upgrade_iris_offline
from .velociraptor import upgrade_velociraptor, upgrade_velociraptor_offline
from .intact import (
    upgrade_intact, upgrade_intact_offline,
    # Full-mode machinery used by the recreate handoff + finalizer.
    backend_full_mode, backend_target_tag, running_backend_image,
    ensure_backend_runtime_image, cleanup_rollback_snapshots,
)
from .plaso import upgrade_plaso, upgrade_plaso_offline
from .aws import upgrade_aws, upgrade_aws_offline
from .azure import upgrade_azure, upgrade_azure_offline
from .volweb import upgrade_volweb, upgrade_volweb_offline, install_volweb_offline
from .elk import install_elk_offline
from .timesketch import install_timesketch_offline
from .velociraptor import install_velociraptor_offline
from .iris import install_iris_offline

# Storage functions for two-phase upgrade state
from services.storage.base import (
    save_upgrade_state,
    get_pending_upgrade,
    get_upgrade_state,
    update_upgrade_phase,
    clear_upgrade_state,
)

# Database volumes that can be reset for fresh install (schema compatibility)
RESET_VOLUMES = {
    'timesketch': ['timesketch_timesketch_postgres_data', 'timesketch_timesketch_opensearch_data'],
    'iris': ['iris_iris_db_data'],
    'elk': ['elk_elasticsearch_data'],
}


def reset_module_database(module_name: str, logger: Callable = None) -> bool:
    """DESTRUCTIVE: delete a module's data volumes for a fresh/empty install.

    This is NOT required for schema upgrades. Schema changes between versions
    are applied by database migrations (e.g. Timesketch's alembic
    `tsctl db upgrade`, verified to preserve all sketches + events across a
    2024 -> 2026 jump) — the normal upgrade keeps every row and index.

    Only call this when the operator has EXPLICITLY asked to start that module
    from scratch (db_overwrite flag). It permanently removes all data:
    Timesketch sketches + every timeline event in OpenSearch, IRIS cases,
    ELK indices, etc. There is no automatic backup of these volumes.

    Args:
        module_name: Name of the module (timesketch, iris, elk)
        logger: Logging function

    Returns:
        True if successful, False otherwise
    """
    if module_name not in RESET_VOLUMES:
        return True

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log(f"⚠️ FRESH INSTALL: PERMANENTLY DELETING all {module_name} data "
        f"(volumes: {', '.join(RESET_VOLUMES[module_name])}). This is not "
        f"needed for schema upgrades — migrations handle those without data loss.",
        "warning")

    # Get module directory
    module_dir = os.path.join(HOST_PATH, 'modules', module_name)

    # Stop containers first
    log(f"Stopping {module_name} containers...", "info")
    run_command("docker compose down --remove-orphans", cwd=module_dir, logger=log)

    # Remove volumes
    for volume in RESET_VOLUMES[module_name]:
        log(f"Removing volume: {volume}", "info")
        run_command(f"docker volume rm {volume} 2>/dev/null || true", logger=log)

    log(f"Database volumes removed for {module_name}", "success")
    return True


def recreate_timesketch_user(logger: Callable = None) -> bool:
    """Recreate Timesketch user after database reset.

    Reads credentials from config.yaml and creates the user.

    Args:
        logger: Logging function

    Returns:
        True if successful, False otherwise
    """
    import time
    import yaml

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log("Recreating Timesketch user after database reset...", "info")

    # Load config.yaml
    config_path = os.path.join(HOST_PATH, 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        log(f"Could not read config.yaml: {e}", "error")
        return False

    ts_user = config.get('modules', {}).get('timesketch', {}).get('id')
    ts_pass = config.get('modules', {}).get('timesketch', {}).get('password')

    if not ts_user or not ts_pass:
        log("Timesketch credentials not found in config.yaml", "error")
        return False

    # Wait for Timesketch to be ready
    log("Waiting for Timesketch to be ready...", "info")
    time.sleep(15)

    # Create user
    result = run_command(
        f'docker exec intact_timesketch_web tsctl create-user "{ts_user}" --password "{ts_pass}"',
        logger=log
    )
    if not result.get('success'):
        log(f"Failed to create user: {result.get('error')}", "error")
        return False

    # Make admin
    result = run_command(
        f'docker exec intact_timesketch_web tsctl make-admin "{ts_user}"',
        logger=log
    )
    if not result.get('success'):
        log(f"Warning: Could not make user admin: {result.get('error')}", "warning")

    log(f"Timesketch user '{ts_user}' created successfully", "success")
    return True


def schedule_backend_restart():
    """Schedule backend restart after short delay using detached process."""
    subprocess.Popen(
        ['sh', '-c', 'sleep 3 && docker restart intact_backend intact_tusd'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )



_RELEASE_TAG_RE = re.compile(r'^intact-(\d{8})')


def _version_is_older(target: str, current: str) -> bool:
    """True only when `target` is CONFIDENTLY older than `current`.

    Deliberately conservative — an ambiguous comparison must never block a
    legitimate upgrade, so anything unparseable returns False:

    * release tags (`intact-YYYYMMDD…`) compare on the date, because
      compare_versions() parses them as a single non-numeric part and would
      call every pair equal;
    * `Not installed` / `unknown` / empty are not versions at all (a module the
      box does not have is an INSTALL, never a downgrade);
    * everything else falls through to compare_versions(), which handles the
      dotted numeric pins (0.77.1, 2026.04) and the date-ish ones (20260630).
    """
    t, c = (target or '').strip(), (current or '').strip()
    if not t or not c:
        return False
    if c.lower() in ('not installed', 'unknown', 'from_package', 'latest'):
        return False
    if t.lower() in ('from_package', 'latest', 'development'):
        return False           # rolling / package-sourced: no ordering to judge
    mt, mc = _RELEASE_TAG_RE.match(t), _RELEASE_TAG_RE.match(c)
    if mt and mc:
        return mt.group(1) < mc.group(1)
    if mt or mc:
        return False           # one is a release tag, the other isn't — unjudgeable
    try:
        return compare_versions(t, c) < 0
    except Exception:
        return False




def _reject_downgrades(modules_dict: Dict, current_versions: Dict,
                       logger: Callable = None):
    """Return an error string when the package would move any module BACKWARDS.

    Downgrades are refused outright, with no force flag. The DB-backed modules
    are the reason: OpenSearch and Postgres migrate their on-disk schema
    forward, and pointing an older engine at a migrated volume does not fail
    cleanly — it corrupts or refuses to mount, and the data is gone. Catching
    it here costs nothing; catching it afterwards is not possible.

    Runs BEFORE any extraction or mutation, so a rejected run leaves the
    platform exactly as it was.
    """
    log = logger or (lambda m, l="info": None)
    offenders = []
    for mod, target in sorted((modules_dict or {}).items()):
        cur = ((current_versions or {}).get(mod) or {})
        cur = cur.get('current') if isinstance(cur, dict) else cur
        if _version_is_older(str(target), str(cur or '')):
            offenders.append(f"{mod}: installed {cur} -> package {target}")
    if not offenders:
        return None
    for o in offenders:
        log(f"  DOWNGRADE REFUSED — {o}", "error")
    return ("this package would downgrade " +
            ", ".join(offenders) +
            ". Downgrades are not supported: the database-backed modules migrate "
            "their on-disk schema forward, and an older engine cannot read a "
            "migrated volume. Apply a package at or above the installed versions.")


# The package layout this release knows how to read. The manifest has always
# carried `package_version`, but nothing ever read it — so the day the layout
# changes, every older box would misread the new package instead of declining it.
# Phase 1 runs the OLD release's code and can never be fixed retroactively, which
# is exactly why it must be able to say "I don't understand this" cleanly.
SUPPORTED_PACKAGE_FORMAT = 1


def check_package_format(manifest: Dict, logger: Callable = None):
    """Return an error string if this release cannot read the package's format.

    Deliberately permissive: only a MAJOR bump is refused. A minor bump means
    additive changes an older reader can ignore, and an unparseable or missing
    value is treated as the original format — refusing those would block valid
    upgrades, which is a worse failure than reading an old package loosely.
    """
    log = logger or (lambda m, l="info": None)
    raw = str((manifest or {}).get('package_version') or '1.0').strip()
    try:
        major = int(raw.split('.')[0])
    except Exception:
        log(f"  package_version {raw!r} is unparseable — assuming format "
            f"{SUPPORTED_PACKAGE_FORMAT}.x", "warning")
        return None
    if major > SUPPORTED_PACKAGE_FORMAT:
        return (f"this package uses format {raw}, newer than this release can "
                f"read (supports {SUPPORTED_PACKAGE_FORMAT}.x). Upgrade to a "
                f"newer release first, then apply this package.")
    if raw != f"{SUPPORTED_PACKAGE_FORMAT}.0":
        log(f"  package format {raw} (this release reads "
            f"{SUPPORTED_PACKAGE_FORMAT}.x) — proceeding", "info")
    return None



def preflight_package(package_path: str, logger: Callable = None) -> Dict:
    """Answer "would this package apply cleanly here?" WITHOUT touching anything.

    Adapted from the newer releases for this tree: it has no config_validate
    module, so the disk check reads free space directly rather than calling
    preflight_environment, and there is no legacy module-key normalizer to
    apply (this release predates the aws_sigma rename).

    Every other check is the SAME function the real apply calls —
    verify_upgrade_package for structure/integrity, _reject_downgrades for
    ordering, backend_full_mode for the deploy mode — so this cannot drift into
    a reassuring lie about what apply will do.

    STRICTLY READ-ONLY: it removes the extract dir verify_upgrade_package
    created and never mirrors source, loads an image, writes config.yaml, or
    touches a container.

    Returns {"ok": bool, "checks": [{name, ok, detail}], "blocking": [str]}.
    """
    import shutil as _sh
    log = logger or (lambda m, l="info": None)
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}",
            "info" if ok else "warning")

    scratch = None
    try:
        if not package_path or not os.path.exists(package_path):
            add("package exists", False, f"{package_path} not found")
            return {"ok": False, "checks": checks,
                    "blocking": [f"package not found: {package_path}"]}
        pkg_bytes = os.path.getsize(package_path)
        add("package exists", True, f"{pkg_bytes / (1024**3):.2f} GiB")

        vr = verify_upgrade_package(package_path, logger=None)
        scratch = vr.get('extract_dir') or vr.get('package_dir')
        if not vr.get('success'):
            add("archive integrity + manifest", False, str(vr.get('error'))[:160])
            return {"ok": False, "checks": checks,
                    "blocking": [f"package failed verification: {vr.get('error')}"]}
        manifest = vr.get('manifest') or {}
        package_dir = vr.get('package_dir') or scratch
        _fmt = check_package_format(manifest, logger=None)
        add("package format readable by this release", _fmt is None, _fmt or "")

        versions = manifest.get('versions', {}) or {}
        add("archive integrity + manifest", True, f"{len(versions)} module(s)")

        dg = _reject_downgrades(versions, get_current_versions(), logger=None)
        add("no module downgrades", dg is None, dg[:200] if dg else "")

        # Sized from the package rather than a fixed floor: extraction restores
        # the payload and `docker load` writes the layers again, so budget ~3x
        # the archive plus headroom.
        staging = '/app/data' if os.path.isdir('/app/data') else WORKDIR
        need_gb = max(10.0, round((pkg_bytes * 3 / (1024**3)) * 1.15, 1))
        free_gb = _sh.disk_usage(staging).free / (1024**3)
        add(f"disk (needs ~{need_gb} GiB)", free_gb >= need_gb,
            f"{free_gb:.1f} GiB free on {staging}" if free_gb < need_gb else "")

        # The most common silent defect: a Full-mode release whose backend image
        # is absent or named for a different tag makes the box rebuild from
        # source. Inspection only — no docker load.
        # The tag the TARGET will resolve, not the one this box currently has.
        # Phase 1 merges the release's versions: block into config.yaml BEFORE
        # backend_target_tag() is consulted, so the post-merge answer is the
        # package's own intact version. Reading the pre-merge pin here would
        # make a perfectly good package look broken on every box that is not
        # already on the target release — which is every box that needs it.
        tgt = (versions.get('intact') or '').strip() or backend_target_tag()
        img_tar = os.path.join(package_dir, 'images', f'intact-backend-{tgt}.tar')
        src_compose = os.path.join(package_dir, 'source', 'intact', 'modules',
                                   'backend', 'docker-compose.yaml')
        if os.path.isfile(src_compose) and backend_full_mode(src_compose):
            if not os.path.exists(img_tar):
                idir = os.path.join(package_dir, 'images')
                shipped = ([f for f in os.listdir(idir)
                            if f.startswith('intact-backend-')]
                           if os.path.isdir(idir) else [])
                add("backend image for this target", False,
                    f"expected intact-backend-{tgt}.tar; package has "
                    f"{shipped or 'no backend image'} — the box would rebuild "
                    f"from source")
            else:
                add("backend image for this target", True,
                    f"intact-backend-{tgt}.tar")
        else:
            add("backend image for this target", True,
                "target is not Full-mode; no image expected")

        blocking = [f"{c['name']}: {c['detail']}" for c in checks if not c['ok']]
        return {"ok": not blocking, "checks": checks, "blocking": blocking}
    except Exception as e:
        add("preflight completed", False, f"{type(e).__name__}: {e}")
        return {"ok": False, "checks": checks,
                "blocking": [f"preflight error: {type(e).__name__}: {e}"]}
    finally:
        if scratch and os.path.isdir(scratch):
            try:
                _sh.rmtree(scratch)
            except Exception:
                pass


def shlex_quote(s: str) -> str:
    import shlex as _shlex
    return _shlex.quote(s)


_RECREATE_HELPER_TEMPLATE = r'''#!/bin/sh
H="__H__"; BD="$H/modules/backend"; RUN="__RUN__"
NEW="__NEW__"; OLD="__OLD__"; SNAP="__SNAP__"; PROJ="__PROJ__"
LOG="$H/data/tmp/recreate-$RUN.log"
exec >> "$LOG" 2>&1
echo "== helper start recreate -> intact-backend:$NEW =="
C() { docker compose -p "$PROJ" -f "$BD/docker-compose.yaml" --project-directory "$BD" "$@"; }
fail_marker() { printf '{"run_id":"%s","reason":"%s"}' "$RUN" "$1" > "$H/data/tmp/recreate-failed-$RUN.json"; }
# tusd's pinned image tag can lag what's actually present locally (e.g. an
# older box still running tusd:latest while the release pins a newer tag,
# and --pull never blocks fetching it) — a missing tusd image must never
# block the backend swap itself, since recreating tusd here is a bonus, not
# the thing being fixed. Try both together; if that fails, retry backend
# alone and leave tusd exactly as it is.
up_backend() {
  if ! C up -d --no-build --pull never "$@" backend tusd; then
    echo "combined backend+tusd recreate failed (tusd image likely missing locally under --pull never) -- retrying backend alone; tusd left on its current image"
    C up -d --no-build --pull never "$@" backend
  fi
}
wait_healthy() {
  i=0
  while [ $i -lt 60 ]; do
    s=$(docker inspect -f "{{.State.Health.Status}}" intact_backend 2>/dev/null)
    [ "$s" = "healthy" ] && return 0
    i=$((i+1)); sleep 5
  done
  return 1
}
sleep 3
if ! docker image inspect "intact-backend:$NEW" >/dev/null 2>&1; then
  echo "target image intact-backend:$NEW MISSING at recreate"; fail_marker "target image missing at recreate"; exit 1
fi
echo "== up -d --no-build --pull never backend tusd =="
up_backend
if wait_healthy; then echo "== healthy on $NEW =="; exit 0; fi
echo "== UNHEALTHY on $NEW after 300s — rolling back to $OLD =="
docker logs --tail 120 intact_backend 2>&1 || true
if [ -n "$SNAP" ] && [ -d "$SNAP/backend" ]; then cp -a "$SNAP/backend/." "$BD/"; echo "restored snapshot tree (old compose+code)"; fi
if [ -f "$BD/.env.pre-upgrade-backup" ]; then cp "$BD/.env.pre-upgrade-backup" "$BD/.env"; echo "restored .env"; fi
fail_marker "new image unhealthy after 300s; rolled back to $OLD"
if ! up_backend --force-recreate; then docker rm -f intact_backend intact_tusd 2>/dev/null; up_backend; fi
if wait_healthy; then echo "== rollback healthy on $OLD =="; exit 1; fi
echo "== ROLLBACK ALSO UNHEALTHY — manual: $H/data/tmp/recreate-recover-$RUN.sh =="
exit 2
'''

_RECREATE_RECOVER_TEMPLATE = r'''#!/bin/sh
# Manual recovery for an interrupted backend recreate (run_id __RUN__).
# Run this on the HOST. Option A rolls FORWARD (retry the new image);
# option B rolls BACK to the previous image.
set -e
BD="__H__/modules/backend"
cd "$BD"

# --- A) roll forward to the new image (intact-backend:__NEW__) ---
# (tusd's pinned tag may not be present locally under this project's normal
# --pull never policy; if the combined recreate fails, retry backend alone
# and leave tusd untouched rather than blocking the backend roll-forward.)
BACKEND_VERSION=__NEW__ docker compose -p __PROJ__ -f "$BD/docker-compose.yaml" --project-directory "$BD" up -d --no-build backend tusd || \
BACKEND_VERSION=__NEW__ docker compose -p __PROJ__ -f "$BD/docker-compose.yaml" --project-directory "$BD" up -d --no-build backend

# --- B) roll back to the previous image (__OLD__) — uncomment to use ---
# [ -f "$BD/.env.pre-upgrade-backup" ] && cp "$BD/.env.pre-upgrade-backup" "$BD/.env"
# [ -d "__SNAP__/backend" ] && cp -a "__SNAP__/backend/." "$BD/"
# docker compose -p __PROJ__ -f "$BD/docker-compose.yaml" --project-directory "$BD" up -d --no-build --force-recreate backend tusd || \
# docker compose -p __PROJ__ -f "$BD/docker-compose.yaml" --project-directory "$BD" up -d --no-build --force-recreate backend
'''


def _render_recreate_script(template: str, subs: Dict) -> str:
    out = template
    for k, v in subs.items():
        out = out.replace(k, str(v))
    return out




# ─────────────────────────────────────────────────────────────────────────────
# Full-mode recreate handoff (ported verbatim from intact-20260721).
#
# The swap counterpart of schedule_backend_restart: instead of `docker restart`
# (which cannot apply a new image), a DETACHED helper container — spawned from
# the OLD image, so it survives its own parent being stopped — recreates the
# backend onto intact-backend:<release>. Phase 2 then resumes inside the NEW
# container, i.e. the new release drives the rest of its own upgrade.
# ─────────────────────────────────────────────────────────────────────────────

def prepare_recreate_handoff(run_id: str, swap_info: Dict, logger: Callable = None) -> bool:
    """Recreate the backend container from a new image (Full-mode swap).

    Mirrors schedule_backend_restart: stamps .env, writes an operator recovery
    script + logs it FIRST, spawns the detached helper, and arms a 120s×2
    still-alive watchdog (fires only if the helper failed to stop us — a
    successful recreate kills this process, so the timer dies harmlessly).
    Returns True if the helper was spawned.
    """
    import threading as _threading
    from .base import HOST_PATH, backup_env_file, update_env_file
    log = logger or (lambda m, l="info": print(f"[{l}] {m}", flush=True))

    H = HOST_PATH
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')   # container-visible
    backend_dir_host = os.path.join(H, 'modules', 'backend')
    # Never silently fall back to the placeholder '1.0.0' tag — that recreates
    # the backend onto the OLD install-day image (old code) and is exactly how a
    # box gets stranded. Resolve the real release tag instead.
    new_tag = swap_info.get('target_tag') or backend_target_tag()
    old_image = swap_info.get('old_image') or (running_backend_image() or 'intact-backend:1.0.0')
    snap = swap_info.get('snapshot') or ''
    snap_host = snap.replace('/app/data', os.path.join(H, 'data')) if snap else ''

    tmp_c = '/app/data/tmp'                        # container view of the data-bind tmp
    os.makedirs(tmp_c, exist_ok=True)
    helper_c = os.path.join(tmp_c, f'recreate-helper-{run_id}.sh')
    recover_c = os.path.join(tmp_c, f'recreate-recover-{run_id}.sh')
    helper_host = os.path.join(H, 'data', 'tmp', f'recreate-helper-{run_id}.sh')
    recover_host = os.path.join(H, 'data', 'tmp', f'recreate-recover-{run_id}.sh')

    # 1. backup .env, stamp new tag + the INTACT_HOST_PATH trap fix (missing from
    #    .env historically — a recreate would otherwise resolve the wrong default).
    backup_env_file(backend_env, logger=log)
    update_env_file(backend_env, 'BACKEND_VERSION', new_tag, logger=log)
    update_env_file(backend_env, 'INTACT_HOST_PATH', H, logger=log)

    # 2. compose project name from the running container's label (fallback 'backend')
    pr = run_command(
        "docker inspect -f '{{index .Config.Labels \"com.docker.compose.project\"}}' intact_backend",
        logger=None, timeout=15)
    project = (pr.get('stdout') or '').strip() if pr.get('success') else ''
    project = project or 'backend'

    # Record the outgoing tag (boot-time image-retention prune reads it) + the
    # compose hash we're about to apply (needs_swap's compose-hash safety term).
    try:
        import hashlib as _hl
        with open('/app/data/backend-image.previous', 'w') as _pf:
            _pf.write((old_image or '') + '\n')
        with open(os.path.join(WORKDIR, 'modules', 'backend', 'docker-compose.yaml'), 'rb') as _cf:
            _hash = _hl.sha256(_cf.read()).hexdigest()
        with open('/app/data/backend-compose.applied.sha256', 'w') as _hf:
            _hf.write(_hash + '\n')
        from .intact import record_backend_source_fingerprint
        record_backend_source_fingerprint(logger=log)
    except Exception as _re:
        log(f"  (retention/compose-hash record skipped: {_re})", "warning")

    subs = {'__H__': H, '__RUN__': run_id, '__NEW__': new_tag, '__OLD__': old_image,
            '__SNAP__': snap_host, '__PROJ__': project}

    # 3. write recover script + log its path BEFORE the handoff (rows 7/8 recovery)
    try:
        with open(recover_c, 'w') as f:
            f.write(_render_recreate_script(_RECREATE_RECOVER_TEMPLATE, subs))
        os.chmod(recover_c, 0o755)
    except Exception as e:
        log(f"  Could not write recovery script ({e})", "warning")
    log(f"Recreating backend -> intact-backend:{new_tag}. If the box is left "
        f"down, recover with: {recover_host}", "info")

    # 4. write the helper script to the shared data bind, then spawn the helper
    #    container FROM THE OLD IMAGE (has docker + compose; survives our death).
    try:
        with open(helper_c, 'w') as f:
            f.write(_render_recreate_script(_RECREATE_HELPER_TEMPLATE, subs))
        os.chmod(helper_c, 0o755)
    except Exception as e:
        log(f"Could not write recreate helper script ({e}) — ABORTING handoff, "
            f"platform untouched", "error")
        return False

    helper_name = f"intact-upgrade-helper-{run_id}"
    spawn = (f"docker rm -f {helper_name} >/dev/null 2>&1; "
             f"docker run -d --rm --name {helper_name} "
             f"-v /var/run/docker.sock:/var/run/docker.sock -v {H}:{H} "
             f"-e INTACT_HOST_PATH={H} --entrypoint sh {old_image} {helper_host}")
    try:
        log_path = f"/app/data/tmp/recreate-spawn-{run_id}.log"
        with open(log_path, 'a') as lf:
            subprocess.Popen(['sh', '-c', spawn], stdout=lf, stderr=lf,
                             start_new_session=True)
    except Exception as e:
        log(f"Could not spawn recreate helper ({type(e).__name__}: {e})", "error")
        return False

    # 5. still-alive watchdog — fires ONLY if the helper never stopped us.
    def _recreate_watchdog(attempt: int):
        try:
            from services.workflow_service import add_log_to_run, update_run_status
            tail = ''
            try:
                with open(f"/app/data/tmp/recreate-{run_id}.log") as lf:
                    tail = ''.join(lf.readlines()[-15:])
            except Exception:
                pass
            if attempt == 1:
                add_log_to_run(run_id, "Backend recreate did not occur within 120s — "
                                       f"respawning helper once. Recent helper log:\n{tail}", "error")
                run_command(f"sh -c {shlex_quote(spawn)}", logger=None, timeout=60)
                t = _threading.Timer(120, _recreate_watchdog, args=(2,))
                t.daemon = True
                t.start()
            else:
                from .base import restore_env_file
                restore_env_file(backend_env, backend_env + '.pre-upgrade-backup', logger=None)
                update_run_status(
                    run_id, "failed",
                    error=("Backend recreate could not be performed — the platform is "
                           "still on the OLD image, .env restored. Upgrade state is "
                           f"preserved: run {recover_host} to retry, then Phase 2 "
                           f"resumes. Helper log tail:\n{tail}"))
        except Exception as e:
            print(f"[UPGRADE] recreate watchdog error: {e}", flush=True)

    t = _threading.Timer(120, _recreate_watchdog, args=(1,))
    t.daemon = True
    t.start()
    return True


# ── Boot-time self-heal for a stranded Full-mode swap ───────────────────────
# A box upgraded by OLD (pre-Wave-F) code — e.g. an 'intact'-alone run with no
# other sidecar module in the same batch — mirrors the new release's files and
# restarts the SAME container, because that old code predates the whole
# image-swap concept and has no way to know one is needed. VERSION and
# config.yaml end up correctly stamped to the new release, but the running
# container never changes image. Nothing else ever notices: the 'intact'-alone
# code path (old AND new) never persists Phase-2 resume state, so there is no
# later point where anything re-checks whether a swap is still owed. This
# check closes that gap: it runs unconditionally on every boot with no pending
# upgrade (see app.py) and is a no-op unless the running image genuinely
# doesn't match what config.yaml says the release should be.

def restart_nginx(log: Callable) -> bool:
    """Restart the main intact_nginx AND every per-module *_nginx.

    Every nginx container resolves its upstream hostname ONCE at
    startup. If an upstream is recreated after the nginx started,
    nginx keeps the stale IP (or worse, the cached "no such host"
    NXDOMAIN) and returns 502 forever. This bit us on fresh-install
    apply with Timesketch — install_timesketch_offline brings up
    intact_timesketch_nginx + intact_timesketch_web in the same
    compose, but the main intact_nginx was already running from
    install.sh and had cached "no upstream" for intact_timesketch_nginx.

    Restarting only intact_nginx (the previous behavior) refreshed
    the main reverse-proxy's cache, but missed the per-module nginxes
    that ALSO need refreshing when their upstream web containers come
    up. Mirrors lib/health.sh:refresh_nginx_upstreams.
    """
    log("Refreshing per-module nginx DNS caches...", "info")
    # Find every nginx container — both the main intact_nginx and any
    # per-module intact_*_nginx that's currently running.
    list_cmd = "docker ps --filter 'name=intact_' --format '{{.Names}}'"
    listing = run_command(list_cmd, logger=None, timeout=10)
    names = []
    if listing.get('success'):
        for n in (listing.get('stdout', '') or '').splitlines():
            n = n.strip()
            if n and (n == 'intact_nginx' or n.endswith('_nginx')):
                names.append(n)

    if not names:
        log("  No nginx containers found to refresh.", "warning")
        return False

    ok = True
    for name in names:
        result = run_command(f"docker restart {name}", logger=None, timeout=60)
        if result.get('success'):
            log(f"  Restarted {name} (cleared upstream DNS cache)", "success")
        else:
            log(f"  WARNING: Failed to restart {name}: {result.get('error', '')[:160]}", "warning")
            ok = False
    return ok


def run_upgrade_workflow(modules: Dict[str, str], run_id: str = None, mode: str = 'online',
                         logger: Callable = None, db_overwrite: Dict = None) -> Dict:
    """Run upgrade workflow for selected modules with two-phase support.

    Two-Phase Upgrade:
    - If Intact.AI is in modules, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules

    Args:
        modules: Dict of module_name -> target_version (e.g., {"elk": "8.19.0", "iris": "v2.5.0"})
        run_id: Workflow run ID for state tracking
        mode: 'online' or 'offline'
        logger: Logging function
        db_overwrite: Dict of module -> bool for fresh install (e.g., {"timesketch": True})

    Returns:
        Dict with success status and results per module
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    db_overwrite = db_overwrite or {}

    # Intact.AI must be first so backend code is updated before modules
    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'prowler', 'o365rc', 'volweb']
    upgrade_functions = {
        'elk': upgrade_elk,
        'timesketch': upgrade_timesketch,
        'plaso': upgrade_plaso,
        'iris': upgrade_iris,
        'velociraptor': upgrade_velociraptor,
        'prowler': upgrade_aws,
        'o365rc': upgrade_azure,
        'volweb': upgrade_volweb,
        'intact': upgrade_intact,
    }

    results = {}
    total = len(modules)
    completed = 0
    completed_modules = []
    overall_status = "success"

    current_versions = get_current_versions()

    log(f"Starting upgrade workflow for {total} module(s)", "info")
    log(f"Mode: {mode}", "info")
    log("=" * 50, "info")

    for module_name, target_version in modules.items():
        current = current_versions.get(module_name, {}).get('current', 'unknown')
        log(f"  {module_name.upper()}: {current} -> {target_version}", "info")
    log("=" * 50, "info")

    # Save initial state if we have a run_id
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules, [], mode, db_overwrite=db_overwrite)

    try:
        for module_name in upgrade_order:
            if module_name not in modules:
                continue

            target_version = modules[module_name]
            current = current_versions.get(module_name, {}).get('current', 'unknown')
            log("", "info")
            log(f"{'='*50}", "info")
            log(f"UPGRADING: {module_name.upper()}", "info")
            log(f"  Current version: {current}", "info")
            log(f"  Target version:  {target_version}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            upgrade_fn = upgrade_functions.get(module_name)
            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            try:
                if module_name == 'intact':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed += 1
                    completed_modules.append(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    # Special handling for Intact.AI - trigger backend restart.
                    # The container's Python interpreter cached the OLD
                    # services/upgrade/*.py at startup; without a restart any
                    # subsequent module work in this run (Phase 2) AND any work
                    # in a future separate run would still execute the old
                    # in-memory code — and miss new module-integration logic
                    # like the post-2026-06-14 mandatory-scrape transitive
                    # resolver. Restart unconditionally, regardless of whether
                    # remaining modules follow in this same run (operator hit
                    # the split-run footgun 2026-06-14: ran intact alone, then
                    # a second workflow with timesketch — the old in-memory
                    # backend bundled opensearch:2.11.0 from the stale
                    # TRANSITIVE_DEFAULTS).
                    if module_name == 'intact' and run_id:
                        remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
                        if remaining:
                            # In-run Phase 2: save state, restart, resume after boot.
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode,
                                               db_overwrite=db_overwrite)
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart()

                            return {
                                "success": True,
                                "phase": "awaiting_restart",
                                "status": "awaiting_restart",
                                "message": "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.",
                                "results": results,
                                "completed": completed,
                                "total": total
                            }
                        else:
                            # Intact-alone run: still restart, but no Phase 2
                            # to resume — workflow finishes its own cleanup
                            # first, then the delayed restart (sleep 3 inside
                            # schedule_backend_restart) fires after this
                            # function returns. Next upgrade run starts with
                            # the new code already in memory.
                            log("Backend will restart to load new code so the "
                                "next upgrade picks up new module-integration "
                                "logic. (Sleep-3 delay lets this workflow "
                                "finish + return first.)", "info")
                            schedule_backend_restart()

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"
                    # Per-module config.yaml revert: drop only the failing
                    # module's pin family (timesketch + timesketch_*) back
                    # to the pre-merge values so a re-run starts from a
                    # clean state for THIS module while keeping pins for
                    # modules that succeeded.
                    try:
                        from .intact import revert_module_versions_from_backup
                        revert_module_versions_from_backup(
                            module_name,
                            os.path.join(WORKDIR, 'config.yaml'),
                            logger=log,
                        )
                    except Exception as _re:
                        log(f"  [config-rollback {module_name}] revert raised "
                            f"({type(_re).__name__}: {_re}); pins left as-is",
                            "warning")

            except Exception as e:
                # Per-module try/except is what gives the apply step
                # cascade resilience: one module's crash never kills
                # the run. The MODULE_FAILED log marker is what
                # operators grep for in the install log.
                import traceback as _tb
                log(f"MODULE_FAILED: {module_name.upper()} — exception: {str(e)}", "error")
                log(f"  Traceback: {_tb.format_exc()[:600]}", "error")
                log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"
                # Per-module config.yaml revert (same as above, exception path)
                try:
                    from .intact import revert_module_versions_from_backup
                    revert_module_versions_from_backup(
                        module_name,
                        os.path.join(WORKDIR, 'config.yaml'),
                        logger=log,
                    )
                except Exception as _re:
                    log(f"  [config-rollback {module_name}] revert raised "
                        f"({type(_re).__name__}: {_re}); pins left as-is",
                        "warning")

    except Exception as unexpected_error:
        # Catch any unexpected error in the workflow itself
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        # ==============================================================
        # THIS BLOCK RUNS NO MATTER WHAT - SUCCESS, FAILURE, OR EXCEPTION
        # ==============================================================
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING UPGRADE WORKFLOW", "info")
        log(f"{'='*50}", "info")

        # CRITICAL: Always restart Nginx to pick up new container IPs
        restart_nginx(log)

        # Clear upgrade state on completion (if not awaiting restart)
        if run_id:
            clear_upgrade_state(run_id)

        # Print summary
        log("", "info")
        log(f"{'='*50}", "info")
        log(f"UPGRADE COMPLETE - Status: {overall_status}", "info")
        log(f"{'='*50}", "info")

        for module_name, result in results.items():
            if module_name.startswith("_"):
                continue
            icon = "OK" if result.get('success') else "FAILED"
            log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")
            if result.get('rolled_back'):
                log(f"       -> Rolled back to {result.get('restored_version')}", "warning")

        log(f"{'='*50}", "info")

    # Workflow done. Clean up the config.yaml pre-merge backup (if any
    # — only the online flow creates one). Per-module reverts have
    # already run for each FAILED module via the orchestrator's
    # MODULE_FAILED branches above, so the operator's config.yaml is
    # in the right shape regardless of outcome.
    try:
        from .intact import cleanup_config_yaml_backup
        cleanup_config_yaml_backup(
            os.path.join(WORKDIR, 'config.yaml'), logger=log,
        )
    except Exception as _e:
        log(f"  [config-cleanup] post-workflow cleanup raised "
            f"({type(_e).__name__}: {_e}); harmless leftover at "
            f"config.yaml.pre-upgrade-backup", "warning")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "results": results,
        "completed": completed,
        "total": total
    }


def resume_upgrade_workflow(run_id: str, logger: Callable = None) -> Dict:
    """Resume upgrade after backend restart (Phase 2).

    Called automatically on startup when a pending upgrade is detected.

    Args:
        run_id: The workflow run ID to resume
        logger: Logging function

    Returns:
        Dict with success status and results
    """
    log = logger or (lambda msg, level="info": print(f"[UPGRADE-RESUME] [{level}] {msg}"))

    # Get saved state
    state = get_upgrade_state(run_id)
    if not state:
        return {"success": False, "error": f"No upgrade state found for {run_id}"}

    if state['phase'] != 'awaiting_restart':
        return {"success": False, "error": f"Upgrade not in awaiting_restart phase: {state['phase']}"}

    log("", "info")
    log(f"{'='*50}", "info")
    log("PHASE 2 - RESUMING UPGRADE AFTER RESTART", "info")
    log(f"Run ID: {run_id}", "info")
    log(f"{'='*50}", "info")

    # Restart nginx first (for new UI code)
    restart_nginx(log)

    # Mark as phase 2 in progress
    update_upgrade_phase(run_id, 'phase2')

    modules = state['target_modules']
    completed_modules = set(state['completed_modules'])
    mode = state.get('mode', 'online')
    db_overwrite = state.get('db_overwrite', {})  # Per-module fresh install flags

    # Parse package paths from state (stored as JSON with extract_dir and package_path)
    package_dir_raw = state.get('package_dir')
    extract_dir = None
    package_path = None
    package_dir = None

    if package_dir_raw:
        try:
            paths = json.loads(package_dir_raw)
            extract_dir = paths.get('extract_dir')
            package_path = paths.get('package_path')
            # Find the actual package subdir inside extract_dir
            if extract_dir and os.path.exists(extract_dir):
                subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
                if subdirs:
                    package_dir = os.path.join(extract_dir, subdirs[0])
                else:
                    package_dir = extract_dir
        except (json.JSONDecodeError, TypeError):
            # Backwards compatibility: old format was just a path string
            package_dir = package_dir_raw
            extract_dir = package_dir_raw

    # 2026-06-16 incident: volweb was silently dropped from Phase 2
    # because resume_upgrade_workflow's upgrade_order didn't include it,
    # even though run_offline_upgrade_workflow and run_online_upgrade
    # (the other two copies of this list) DID. Operator selected volweb,
    # Phase 1 ran, backend restarted, this loop iterated — volweb wasn't
    # in the list, never got dispatched, never appeared in the summary.
    # All three copies of upgrade_order must include the same modules;
    # this one drifted. Keep them in sync.
    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'prowler', 'o365rc', 'volweb']

    # Use online or offline functions based on mode
    if mode == 'offline':
        upgrade_functions = {
            'elk': lambda v, **kw: upgrade_elk_offline(package_dir, v, **kw),
            'timesketch': lambda v, **kw: upgrade_timesketch_offline(package_dir, v, **kw),
            'plaso': lambda v, **kw: upgrade_plaso_offline(package_dir, v, **kw),
            'iris': lambda v, **kw: upgrade_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: upgrade_velociraptor_offline(package_dir, v, **kw),
            'prowler': lambda v, **kw: upgrade_aws_offline(package_dir, v, **kw),
            'o365rc': lambda v, **kw: upgrade_azure_offline(package_dir, v, **kw),
            'volweb': lambda v, **kw: upgrade_volweb_offline(package_dir, v, **kw),
            'intact': lambda **kw: upgrade_intact_offline(package_dir, **kw),
        }
        # Install-vs-upgrade dispatch (Phase-2 needs the same auto-detect
        # the main loop has — otherwise a fresh install hits Phase 1
        # for intact, then Phase 2 runs UPGRADE functions for modules
        # whose containers don't exist yet, and they fail with cryptic
        # "No such container" errors or report false success.
        # See the 2026-06-08 fresh-install log where iris/timesketch
        # both crashed because their upgrade fns tried to docker-exec
        # into containers that hadn't been created yet.
        install_functions = {
            'elk':          lambda v, **kw: install_elk_offline(package_dir, v, **kw),
            'timesketch':   lambda v, **kw: install_timesketch_offline(package_dir, v, **kw),
            'iris':         lambda v, **kw: install_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: install_velociraptor_offline(package_dir, v, **kw),
            'volweb':       lambda v, **kw: install_volweb_offline(package_dir, v, **kw),
        }
    else:
        upgrade_functions = {
            'elk': upgrade_elk,
            'timesketch': upgrade_timesketch,
            'plaso': upgrade_plaso,
            'iris': upgrade_iris,
            'velociraptor': upgrade_velociraptor,
            'intact': upgrade_intact,
        }
        # Online mode doesn't currently expose install_* — operator
        # is expected to have run install.sh first. Keep as-is.
        install_functions = {}

    # Reuse the container-existence detector — same source of truth
    # the main run_offline_upgrade_workflow uses.
    from .base import _module_container_exists

    results = {}
    overall_status = "success"
    current_versions = get_current_versions()

    # Show what's remaining
    remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
    log(f"Modules to upgrade: {', '.join(remaining)}", "info")
    log("=" * 50, "info")

    # STRUCTURAL: pre-load every bundled image into the local docker
    # store BEFORE the per-module loop. Eliminates the "did this
    # module's upgrade function remember to load its sidecar tars?"
    # failure mode that hit timesketch on 2026-06-15 (opensearch /
    # postgres / redis / nginx tars were bundled but the upgrade
    # function only loaded the primary timesketch tar; compose-up
    # then failed with "No such image"). With this call here, every
    # module's compose-up finds every bundled image already in the
    # store — regardless of what the per-module upgrade function
    # does or doesn't do. Per-module load_all_bundled_images calls
    # (in timesketch.py + volweb.py) become redundant safety nets;
    # `docker load` is idempotent so re-loading costs nothing.
    if package_dir:
        try:
            from .base import load_all_bundled_images
            load_all_bundled_images(package_dir, logger=log, run_id=run_id)
        except Exception as _e:
            log(f"Pre-load of bundled images raised "
                f"({type(_e).__name__}: {_e}); per-module load "
                f"fallbacks will still run.", "warning")

    try:
        for module_name in upgrade_order:
            if module_name not in modules or module_name in completed_modules:
                continue

            target_version = modules[module_name]
            current = current_versions.get(module_name, {}).get('current', 'unknown')

            # Install-vs-upgrade dispatch: pick the install function
            # when the module's primary container is absent (fresh-
            # install Phase 2 case). Otherwise use the upgrade function
            # (the running-stack case the offline-upgrade flow was
            # originally designed for). Same logic as the main loop.
            install_fn = install_functions.get(module_name)
            module_present = _module_container_exists(module_name)
            if install_fn and module_present is False:
                action_word = "INSTALLING"
                upgrade_fn = install_fn
            else:
                action_word = "UPGRADING"
                upgrade_fn = upgrade_functions.get(module_name)

            log("", "info")
            log(f"{'='*50}", "info")
            log(f"{action_word}: {module_name.upper()}", "info")
            log(f"  Current version: {current}", "info")
            log(f"  Target version:  {target_version}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            # Stamp transitive container pins (postgres / opensearch /
            # redis / nginx / rabbitmq) from the bundled manifest into
            # modules/<module>/.env BEFORE compose up. Mirrors what
            # run_offline_upgrade_workflow's main loop does at the
            # equivalent spot; without it, compose's `${VAR:-default}`
            # interpolation falls back to the shipped DEFAULT tag
            # (e.g. `redis:${REDIS_VERSION:-7-alpine}` resolves to
            # `redis:7-alpine`) instead of the actually-bundled tag
            # (e.g. `redis:7.2.11-alpine`), and compose up fails with
            # "No such image" — operator hit this 2026-06-14 on a
            # fresh install run where Phase 1 intact triggered the
            # restart and Phase 2 timesketch's compose then asked for
            # an unbundled redis tag. Skipped for intact (no transitive
            # deps) and for any module without a transitive_versions
            # block in the manifest (no-op inside the helper).
            if module_name != 'intact' and package_dir:
                try:
                    from .base import stamp_transitive_env_from_manifest
                    stamp_transitive_env_from_manifest(
                        module_name, package_dir, logger=log,
                    )
                except Exception as _e:
                    log(f"  transitive .env stamp raised "
                        f"({type(_e).__name__}: {_e}); proceeding with "
                        f"existing .env values", "warning")

            try:
                if module_name == 'intact':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed_modules.add(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Write back version + flip enabled flag in config.yaml.
                    # Mirrors run_offline_upgrade_workflow's main loop
                    # (the equivalent block ~line 1157). resume_upgrade_workflow
                    # is the Phase-2-after-restart path; modules installed
                    # here (e.g. volweb selected in the apply modal) were
                    # NOT getting modules.<name>.enabled=true set, so the
                    # containers came up but the UI still showed the
                    # module disabled — operator hit this 2026-06-16 with
                    # "Memory module is not enabled" after a successful
                    # volweb install. Same three-copies-drift class as the
                    # upgrade_order bug. Keep in sync with the main loop.
                    try:
                        from .base import set_module_version_in_config, set_module_enabled_in_config
                        yaml_key = 'backend' if module_name == 'intact' else module_name
                        if target_version and target_version != 'from_package':
                            try:
                                set_module_version_in_config(yaml_key, target_version, logger=log)
                            except Exception as _ve:
                                log(f"  config.yaml version-writeback failed for {module_name}: {_ve}", "warning")
                        if action_word == 'INSTALLING' and module_name != 'intact':
                            try:
                                set_module_enabled_in_config(module_name, logger=log)
                            except Exception as _ee:
                                log(f"  config.yaml enable-flip failed for {module_name}: {_ee}", "warning")
                    except Exception as _ce:
                        log(f"  config.yaml writeback raised for {module_name}: {_ce}", "warning")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    update_upgrade_phase(run_id, 'phase2', list(completed_modules))
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"
                    # Per-module config.yaml revert: drop only the failing
                    # module's pin family (timesketch + timesketch_*) back
                    # to the pre-merge values so a re-run starts from a
                    # clean state for THIS module while keeping pins for
                    # modules that succeeded.
                    try:
                        from .intact import revert_module_versions_from_backup
                        revert_module_versions_from_backup(
                            module_name,
                            os.path.join(WORKDIR, 'config.yaml'),
                            logger=log,
                        )
                    except Exception as _re:
                        log(f"  [config-rollback {module_name}] revert raised "
                            f"({type(_re).__name__}: {_re}); pins left as-is",
                            "warning")

            except Exception as e:
                # Per-module try/except is what gives the apply step
                # cascade resilience: one module's crash never kills
                # the run. The MODULE_FAILED log marker is what
                # operators grep for in the install log.
                import traceback as _tb
                log(f"MODULE_FAILED: {module_name.upper()} — exception: {str(e)}", "error")
                log(f"  Traceback: {_tb.format_exc()[:600]}", "error")
                log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"
                # Per-module config.yaml revert (same as above, exception path)
                try:
                    from .intact import revert_module_versions_from_backup
                    revert_module_versions_from_backup(
                        module_name,
                        os.path.join(WORKDIR, 'config.yaml'),
                        logger=log,
                    )
                except Exception as _re:
                    log(f"  [config-rollback {module_name}] revert raised "
                        f"({type(_re).__name__}: {_re}); pins left as-is",
                        "warning")

    except Exception as unexpected_error:
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING PHASE 2", "info")
        log(f"{'='*50}", "info")

        # Cleanup extracted package directory
        if extract_dir and os.path.exists(extract_dir):
            log("Cleaning up extracted package...", "info")
            run_command(f"rm -rf {extract_dir}", logger=log)

        # Cleanup uploaded package file
        if package_path and os.path.exists(package_path):
            try:
                os.remove(package_path)
                log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
            except Exception as e:
                log(f"Warning: Could not remove package file: {e}", "warning")

        # Final nginx restart
        restart_nginx(log)

        # Mark complete and clear state
        update_upgrade_phase(run_id, 'completed')
        clear_upgrade_state(run_id)

        # Print summary
        log("", "info")
        log(f"{'='*50}", "info")
        log(f"PHASE 2 COMPLETE - Status: {overall_status}", "info")
        log(f"{'='*50}", "info")

        for module_name, result in results.items():
            if module_name.startswith("_"):
                continue
            icon = "OK" if result.get('success') else "FAILED"
            log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")

        log(f"{'='*50}", "info")

    # Workflow done. Clean up the config.yaml pre-merge backup (if any
    # — only the online flow creates one). Per-module reverts have
    # already run for each FAILED module via the orchestrator's
    # MODULE_FAILED branches above, so the operator's config.yaml is
    # in the right shape regardless of outcome.
    try:
        from .intact import cleanup_config_yaml_backup
        cleanup_config_yaml_backup(
            os.path.join(WORKDIR, 'config.yaml'), logger=log,
        )
    except Exception as _e:
        log(f"  [config-cleanup] post-workflow cleanup raised "
            f"({type(_e).__name__}: {_e}); harmless leftover at "
            f"config.yaml.pre-upgrade-backup", "warning")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "phase": "completed",
        "results": results
    }


def run_offline_upgrade_workflow(package_path: Optional[str] = None,
                                  run_id: str = None, logger: Callable = None,
                                  db_overwrite: Dict = None,
                                  selected_modules: Optional[list] = None,
                                  *,
                                  prebuilt_package_dir: Optional[str] = None,
                                  prebuilt_manifest: Optional[Dict] = None,
                                  workflow_label: str = "OFFLINE UPGRADE WORKFLOW") -> Dict:
    """Run the apply-upgrade orchestration with two-phase support.

    Two entry modes, same orchestration body:
    - **Offline (default):** pass `package_path` to an uploaded tar.gz.
      The function calls `verify_upgrade_package()` to gzip-t-check
      and extract the archive, then runs the per-module loop.
    - **Online:** pass `prebuilt_package_dir` + `prebuilt_manifest`
      (both already populated by `prepare_upgrade_package(compress=False)`).
      The function skips verification + extraction and runs the same
      per-module loop directly. `workflow_label` lets the caller
      override the banner so operators reading logs can tell the two
      flows apart.

    Two-Phase Upgrade (unchanged for both modes):
    - If Intact.AI source is in package, it's upgraded first (Phase 1)
    - State is saved, backend restarts
    - On startup, Phase 2 resumes with remaining modules
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    db_overwrite = db_overwrite or {}

    log("=" * 50, "info")
    log(workflow_label, "info")
    log("=" * 50, "info")

    # Two-mode entry: tar.gz extraction (offline, legacy) OR pre-built
    # package_dir from the online flow.
    if prebuilt_package_dir and prebuilt_manifest:
        package_dir = prebuilt_package_dir
        manifest = prebuilt_manifest
        verify_result = {
            'success': True,
            'package_dir': package_dir,
            'extract_dir': package_dir,
            'manifest': manifest,
        }
        log(f"  Online mode: using pre-built package_dir={package_dir}", "info")
    else:
        # Offline flow — clean up previous remnants (skipped for online
        # because its fresh-timestamped build dir would get nuked).
        import glob
        old_dirs = glob.glob('/app/data/tmp/intact-upgrade-*') + glob.glob('/data/tmp/intact-upgrade-*') + glob.glob('/tmp/intact-upgrade-*')
        if old_dirs:
            log("Cleaning up previous installation remnants...", "info")
            for old_dir in old_dirs:
                log(f"  Removing: {old_dir}", "info")
                run_command(f"rm -rf {old_dir}", logger=log)

        # Verify and extract package
        verify_result = verify_upgrade_package(package_path, logger=log)
        if not verify_result['success']:
            if package_path and os.path.exists(package_path):
                try:
                    os.remove(package_path)
                    log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
                except Exception:
                    pass
            return {"success": False, "error": verify_result.get('error', 'Package verification failed')}

        package_dir = verify_result['package_dir']
        manifest = verify_result['manifest']

    versions = manifest.get('versions', {})

    # Get current versions for comparison
    current_versions = get_current_versions()

    # Log current vs target versions. Distinguish a fresh install
    # ("Not installed -> X" looks awkward; say "installing X") from an
    # actual upgrade ("X -> Y"). The current_versions reader returns
    # 'Not installed' for modules whose primary container or version pin
    # is absent on this host.
    log("", "info")
    log("VERSION SUMMARY:", "info")
    log("-" * 40, "info")
    for module, target_ver in versions.items():
        current_ver = current_versions.get(module, {}).get('current', 'Not installed')
        if current_ver in ('Not installed', 'unknown'):
            log(f"  {module.upper()}: installing {target_ver} (fresh install)", "info")
        elif current_ver == target_ver:
            log(f"  {module.upper()}: reinstalling {target_ver} (same version)", "info")
        else:
            log(f"  {module.upper()}: {current_ver} -> {target_ver} (upgrade)", "info")
    log("-" * 40, "info")
    log("", "info")

    offline_upgrade_functions = {
        'elk': upgrade_elk_offline,
        'timesketch': upgrade_timesketch_offline,
        'plaso': upgrade_plaso_offline,
        'iris': upgrade_iris_offline,
        'velociraptor': upgrade_velociraptor_offline,
        'prowler': upgrade_aws_offline,
        'o365rc': upgrade_azure_offline,
        'intact': upgrade_intact_offline,
        'volweb': upgrade_volweb_offline,
    }

    # Fresh-install functions — picked by the dispatcher when the module's
    # primary container is absent. Modules not listed here fall back to
    # their upgrade function (or have no install/upgrade decision —
    # aws/azure/plaso/intact don't deploy a standalone container stack).
    offline_install_functions = {
        'elk':          install_elk_offline,
        'timesketch':   install_timesketch_offline,
        'iris':         install_iris_offline,
        'velociraptor': install_velociraptor_offline,
        'volweb':       install_volweb_offline,
        # On-demand modules — same function handles both install and
        # upgrade (the only difference is whether PROWLER_VERSION /
        # DFIR_O365RC_VERSION was already pinned). Registering them here
        # lets the install-vs-upgrade dispatcher show "INSTALLING" on
        # fresh deploys and "UPGRADING" on version bumps. _module_container_exists
        # now reads the .env pin for these so the False-vs-True branch
        # actually fires.
        'prowler':      upgrade_aws_offline,
        'o365rc':       upgrade_azure_offline,
    }

    # Container existence detector — reuses _MODULE_PRIMARY_CONTAINERS
    # from base.py. Falls back to True ("module is installed") for
    # modules without a container concept.
    from .base import _module_container_exists

    # Intact.AI must be first so backend code is updated before modules.
    # VolWeb is at the end so its install (a multi-container compose) runs
    # last when the operator is adding VolWeb to an existing install.
    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'prowler', 'o365rc', 'volweb']

    results = {}
    total = 0
    completed = 0
    completed_modules = []
    overall_status = "success"
    awaiting_restart = False  # Flag to prevent cleanup when Phase 2 pending
    extract_dir = verify_result.get('extract_dir')

    # Build modules dict for state tracking
    modules_dict = {k: v for k, v in versions.items()}

    # Refuse a package that would move any module BACKWARDS, before the loop
    # touches anything — a rejected run leaves the platform exactly as it was.
    # The database-backed modules are the reason: OpenSearch and Postgres
    # migrate their on-disk schema forward and an older engine cannot read a
    # migrated volume, which is not recoverable after the fact.
    _fmt = check_package_format(manifest, logger=log)
    if _fmt:
        log(f"PACKAGE FORMAT UNSUPPORTED — {_fmt}", "error")
        return {"success": False, "status": "failed", "error": _fmt,
                "results": {}, "completed": 0, "total": 0, "versions": {}}

    _dg = _reject_downgrades(modules_dict, current_versions, logger=log)
    if _dg:
        log("DOWNGRADE REFUSED — aborting with the platform untouched.", "error")
        log(f"  {_dg}", "error")
        return {"success": False, "status": "failed", "error": _dg,
                "results": {}, "completed": 0, "total": 0, "versions": {}}

    if 'intact' not in modules_dict:
        # Check if intact source exists in package (not just empty dirs).
        # Try the new GitHub-tarball layout first (`source/intact/`) and
        # fall back to the legacy `source/backend` + `source/frontend`
        # split for packages built before that change.
        intact_root = os.path.join(package_dir, 'source', 'intact')
        if os.path.isdir(intact_root):
            backend_source = os.path.join(intact_root, 'modules', 'backend')
            frontend_source = os.path.join(intact_root, 'modules', 'nginx', 'html')
        else:
            backend_source = os.path.join(package_dir, 'source', 'backend')
            frontend_source = os.path.join(package_dir, 'source', 'frontend')
        has_backend = os.path.exists(backend_source) and os.listdir(backend_source)
        has_frontend = os.path.exists(frontend_source) and os.listdir(frontend_source)
        if has_backend or has_frontend:
            modules_dict['intact'] = 'from_package'

    # Apply Uploaded Package can pass an operator-chosen subset. When
    # set, modules in the manifest NOT in this set are skipped and the
    # final summary shows them under "skipped: N". When None, every
    # module in the manifest is applied (legacy behavior — keeps
    # external automation working).
    selected_set = set(selected_modules) if selected_modules else None
    if selected_set is not None:
        log(f"Operator-selected subset: {sorted(selected_set)}", "info")

    # Count `total` against modules the operator ACTUALLY intends to
    # apply. Without this, a 1-module apply with intact deselected
    # reports "1/2 modules" because the manifest's intact entry was
    # counted in the denominator even though we'll skip it. The
    # denominator should reflect the operator's intent, not the
    # tarball's contents.
    for module in upgrade_order:
        if module not in modules_dict:
            continue
        if selected_set is not None and module not in selected_set:
            continue
        total += 1

    # 0615B backport (QA finding F1): state persisted across the intact restart
    # must carry ONLY the operator-selected modules. The online-download path
    # passes selected_modules = the installed+opted set (a SUBSET of the CI
    # package's full manifest); without this, the Phase-2 resume applies
    # state['target_modules'] = the FULL manifest and installs modules the
    # operator never selected. Fall back to the full set only when nothing was
    # explicitly selected.
    state_modules = ({k: v for k, v in modules_dict.items() if k in selected_set}
                     if selected_set is not None else modules_dict)

    # Save initial state if we have a run_id (include package_path for cleanup after Phase 2)
    extract_dir = verify_result.get('extract_dir')
    if run_id:
        save_upgrade_state(run_id, 'phase1', state_modules, [], 'offline', extract_dir, package_path,
                           db_overwrite=db_overwrite)

    # STRUCTURAL: see comment at the equivalent spot in
    # resume_upgrade_workflow. Same rationale, same idempotency.
    # This call covers the Phase 1 leg (intact upgrade + any
    # modules that run before the backend restart). After restart,
    # resume_upgrade_workflow re-runs the pre-load (cheap no-op
    # for already-loaded images), keeping both Phase-1-only and
    # Phase-2-resume paths self-contained.
    if package_dir:
        try:
            from .base import load_all_bundled_images
            load_all_bundled_images(package_dir, logger=log, run_id=run_id)
        except Exception as _e:
            log(f"Pre-load of bundled images raised "
                f"({type(_e).__name__}: {_e}); per-module load "
                f"fallbacks will still run.", "warning")

    try:
        for module_name in upgrade_order:
            version = versions.get(module_name)

            # Operator subset filter — silently skip anything the
            # operator unchecked at apply time. Recorded as skipped so
            # the summary still mentions them.
            if selected_set is not None and module_name not in selected_set:
                if version or module_name == 'intact':
                    results[module_name] = {"success": True, "skipped": True,
                                             "reason": "deselected by operator"}
                continue

            # For intact, check if source exists — try new layout first.
            if module_name == 'intact':
                intact_root = os.path.join(package_dir, 'source', 'intact')
                if os.path.isdir(intact_root):
                    backend_source = os.path.join(intact_root, 'modules', 'backend')
                    frontend_source = os.path.join(intact_root, 'modules', 'nginx', 'html')
                else:
                    backend_source = os.path.join(package_dir, 'source', 'backend')
                    frontend_source = os.path.join(package_dir, 'source', 'frontend')
                if not os.path.exists(backend_source) and not os.path.exists(frontend_source):
                    continue
            elif not version:
                continue

            # Install-or-upgrade detection: pick the install function
            # (when registered) if the module's primary container is
            # absent on the host. Otherwise use the upgrade function as
            # before. This is what lets an operator package a module
            # their current install doesn't have and have it deployed
            # cleanly via the same Apply Upgrade flow.
            install_fn = offline_install_functions.get(module_name)
            module_present = _module_container_exists(module_name)
            if install_fn and module_present is False:
                action_word = "INSTALLING"
                upgrade_fn = install_fn
            else:
                action_word = "UPGRADING"
                upgrade_fn = offline_upgrade_functions.get(module_name)

            log("", "info")
            log(f"{'='*50}", "info")
            log(f"{action_word}: {module_name.upper()} -> {version or 'from source'}", "info")
            log(f"{'='*50}", "info")

            # Fresh install: remove database volumes if requested for this module
            if db_overwrite.get(module_name, False):
                reset_module_database(module_name, logger=log)

            if not upgrade_fn:
                log(f"Unknown module: {module_name}", "error")
                results[module_name] = {"success": False, "error": "Unknown module"}
                overall_status = "completed_with_errors"
                continue

            # Check Stop before each module — gives a quick exit even when
            # the per-module function isn't fully cancellation-aware.
            try:
                from services.workflow_service import is_cancelled
                if run_id and is_cancelled(run_id):
                    log("Offline upgrade cancelled by user before module dispatch", "warning")
                    overall_status = "cancelled"
                    break
            except Exception:
                pass

            # Stamp transitive container pins (postgres / opensearch /
            # redis / nginx / rabbitmq versions) from the bundled
            # manifest into modules/<module>/.env BEFORE compose up. The
            # prepare side wrote them; without this stamp the compose's
            # `${VAR:-default}` resolves to the shipped default rather
            # than the tag actually bundled, and air-gapped installs
            # fail to start the stack. No-op for pre-refactor packages
            # (manifest has no transitive_versions block) and for
            # modules without transitive deps. Apply-side only — no
            # network access.
            if module_name != 'intact':
                try:
                    from .base import stamp_transitive_env_from_manifest
                    stamp_transitive_env_from_manifest(
                        module_name, package_dir, logger=log,
                    )
                except Exception as _e:
                    log(f"  transitive .env stamp raised "
                        f"({type(_e).__name__}: {_e}); proceeding with "
                        f"existing .env values", "warning")

            try:
                if module_name == 'intact':
                    result = upgrade_fn(package_dir, logger=log, run_id=run_id)
                else:
                    # Note: Plaso is handled as its own module, not bundled with Timesketch
                    result = upgrade_fn(package_dir, version, logger=log, run_id=run_id)

                # Defensive: if a module function returns None (bug)
                # treat it as a failure rather than crashing on
                # .get(). Without this guard, a buggy upgrade_fn
                # takes down the whole orchestrator and leaves later
                # modules un-attempted.
                if result is None:
                    result = {"success": False, "error": f"{module_name} returned None (bug in upgrade function)"}

                results[module_name] = result
                if not result.get('skipped'):
                    completed += 1
                    completed_modules.append(module_name)

                if result.get('success'):
                    log(f"{module_name.upper()} upgrade completed", "success")

                    # Bump versions.<key> in config.yaml so the next
                    # track-based upgrade's diff is correct. Partial
                    # failure safety: only successful modules' versions
                    # get bumped — a failed module's row stays at the
                    # old version so re-running the upgrade retries
                    # exactly the right thing. The 'intact' module
                    # writes to the 'backend' key per the existing
                    # config_key_map in base.get_latest_versions.
                    # We also flip modules.<name>.enabled=true when
                    # this was a fresh INSTALL (not an upgrade) — that
                    # covers both the new track-flow opt-in checkbox
                    # AND the legacy flow where an operator typed in
                    # a module they don't currently have.
                    from .base import set_module_version_in_config, set_module_enabled_in_config
                    yaml_key = 'backend' if module_name == 'intact' else module_name
                    if version and version != 'from_package':
                        try:
                            set_module_version_in_config(yaml_key, version, logger=log)
                        except Exception as e:
                            log(f"  config.yaml version-writeback failed for {module_name}: {e}", "warning")
                    if action_word == 'INSTALLING' and module_name not in ('intact',):
                        try:
                            set_module_enabled_in_config(module_name, logger=log)
                        except Exception as e:
                            log(f"  config.yaml enable-flip failed for {module_name}: {e}", "warning")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    # Special handling for Intact.AI - trigger backend restart.
                    # See run_upgrade_workflow's twin block for the full
                    # "why always-restart" rationale; short version: the
                    # container's Python interpreter cached the OLD
                    # services/upgrade/*.py at startup, so without a restart
                    # any module work in this run (Phase 2) OR any module
                    # work in a future separate run still executes old
                    # in-memory code. Restart unconditionally — the split-run
                    # footgun on 2026-06-14 bundled the wrong opensearch
                    # version because run #1 was intact-alone and never
                    # restarted, so run #2's timesketch prepare ran the old
                    # in-memory TRANSITIVE_DEFAULTS.
                    if module_name == 'intact' and run_id and not result.get('skipped'):
                        remaining = [m for m in upgrade_order if m in modules_dict and m not in completed_modules]
                        if result.get('needs_swap'):
                            # Full-mode image swap -> RECREATE (not restart): a
                            # `docker restart` cannot apply a new image, and this
                            # release's backend runs its code FROM the image.
                            # Persist resume state even with NO remaining modules so
                            # the recreated container's boot runs the Phase-2
                            # finalizer rather than leaving the run "running".
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded (Full-mode image swap)", "info")
                            if remaining:
                                log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")
                            _saved = save_upgrade_state(run_id, 'awaiting_restart', state_modules, completed_modules, 'offline',
                                                        extract_dir, package_path, db_overwrite=db_overwrite)
                            if not _saved:
                                _saved = save_upgrade_state(run_id, 'awaiting_restart', state_modules, completed_modules, 'offline',
                                                            extract_dir, package_path, db_overwrite=db_overwrite)
                            if not _saved:
                                return {"success": False,
                                        "error": "failed to persist Phase-2 resume state; recreate aborted"}
                            log(f"Backend will RECREATE from intact-backend:{result.get('target_tag')}. "
                                f"Upgrade will resume automatically after the new image boots.", "info")
                            if not prepare_recreate_handoff(run_id, result, logger=log):
                                # Spawn failed — undo the .env stamp + resume state; the
                                # OLD container is still running untouched.
                                from .base import restore_env_file
                                _be = os.path.join(WORKDIR, 'modules', 'backend', '.env')
                                restore_env_file(_be, _be + '.pre-upgrade-backup', logger=log)
                                clear_upgrade_state(run_id)
                                return {"success": False,
                                        "error": "recreate handoff could not be spawned; platform untouched — retry the upgrade"}
                            awaiting_restart = True
                            return {
                                "success": True, "phase": "awaiting_restart", "status": "awaiting_restart",
                                "message": "Phase 1 complete. Backend recreating from new image. Phase 2 will resume automatically.",
                                "results": results, "completed": completed, "total": total, "versions": versions,
                            }
                        if remaining:
                            # In-run Phase 2: save state, restart, resume after boot.
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            save_upgrade_state(run_id, 'awaiting_restart', state_modules, completed_modules, 'offline',
                                               extract_dir, package_path, db_overwrite=db_overwrite)
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart()

                            # Set flag to prevent cleanup in finally block
                            awaiting_restart = True

                            return {
                                "success": True,
                                "phase": "awaiting_restart",
                                "status": "awaiting_restart",
                                "message": "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.",
                                "results": results,
                                "completed": completed,
                                "total": total,
                                "versions": versions
                            }
                        else:
                            # Intact-alone run: still restart, but no Phase 2
                            # to resume. The schedule_backend_restart's
                            # sleep-3 delay lets this workflow finish its
                            # own cleanup (nginx refresh, final summary)
                            # and return before docker restart kicks in.
                            # Next upgrade run starts with the new code
                            # already loaded in memory.
                            log("Backend will restart to load new code so the "
                                "next upgrade picks up new module-integration "
                                "logic. (Sleep-3 delay lets this workflow "
                                "finish + return first.)", "info")
                            schedule_backend_restart()

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"
                    # Per-module config.yaml revert: drop only the failing
                    # module's pin family (timesketch + timesketch_*) back
                    # to the pre-merge values so a re-run starts from a
                    # clean state for THIS module while keeping pins for
                    # modules that succeeded.
                    try:
                        from .intact import revert_module_versions_from_backup
                        revert_module_versions_from_backup(
                            module_name,
                            os.path.join(WORKDIR, 'config.yaml'),
                            logger=log,
                        )
                    except Exception as _re:
                        log(f"  [config-rollback {module_name}] revert raised "
                            f"({type(_re).__name__}: {_re}); pins left as-is",
                            "warning")

            except Exception as e:
                # Per-module try/except is what gives the apply step
                # cascade resilience: one module's crash never kills
                # the run. The MODULE_FAILED log marker is what
                # operators grep for in the install log.
                import traceback as _tb
                log(f"MODULE_FAILED: {module_name.upper()} — exception: {str(e)}", "error")
                log(f"  Traceback: {_tb.format_exc()[:600]}", "error")
                log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                results[module_name] = {"success": False, "error": str(e)}
                overall_status = "completed_with_errors"
                # Per-module config.yaml revert (same as above, exception path)
                try:
                    from .intact import revert_module_versions_from_backup
                    revert_module_versions_from_backup(
                        module_name,
                        os.path.join(WORKDIR, 'config.yaml'),
                        logger=log,
                    )
                except Exception as _re:
                    log(f"  [config-rollback {module_name}] revert raised "
                        f"({type(_re).__name__}: {_re}); pins left as-is",
                        "warning")

    except Exception as unexpected_error:
        # Catch any unexpected error in the workflow itself
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        # ==============================================================
        # THIS BLOCK RUNS NO MATTER WHAT - SUCCESS, FAILURE, OR EXCEPTION
        # ==============================================================

        # Skip cleanup if awaiting restart (Phase 2 needs the extracted files)
        if not awaiting_restart:
            log("", "info")
            log(f"{'='*50}", "info")
            log("FINALIZING OFFLINE UPGRADE WORKFLOW", "info")
            log(f"{'='*50}", "info")

            # Cleanup extracted package
            log("Cleaning up...", "info")
            if extract_dir and os.path.exists(extract_dir):
                run_command(f"rm -rf {extract_dir}", logger=log)

            # Cleanup uploaded package file to free disk space
            if package_path and os.path.exists(package_path):
                try:
                    os.remove(package_path)
                    log(f"Removed uploaded package: {os.path.basename(package_path)}", "info")
                except Exception as e:
                    log(f"Warning: Could not remove package file: {e}", "warning")

            # Restart nginx
            restart_nginx(log)

            # Clear upgrade state on completion
            if run_id:
                clear_upgrade_state(run_id)

            # Print summary with explicit succeeded/failed/skipped
            # counts so the operator can see at a glance which of N
            # modules made it. A "completed_with_errors" run that
            # successfully deployed 5/6 modules is very different from
            # one that failed all 6 — the count surfaces the difference
            # the status field alone can't.
            succeeded = [m for m, r in results.items()
                         if not m.startswith("_") and r.get('success') and not r.get('skipped')]
            failed = [m for m, r in results.items()
                      if not m.startswith("_") and not r.get('success') and not r.get('skipped')]
            skipped = [m for m, r in results.items()
                       if not m.startswith("_") and r.get('skipped')]

            log("", "info")
            log(f"{'='*50}", "info")
            log(f"OFFLINE UPGRADE COMPLETE - Status: {overall_status}", "info")
            log(f"  succeeded: {len(succeeded)}    failed: {len(failed)}    skipped: {len(skipped)}", "info")
            log(f"{'='*50}", "info")

            for module_name, result in results.items():
                if module_name.startswith("_"):
                    continue
                # Skipped takes precedence over the success/fail icon —
                # an operator-deselected module is neither a win nor a
                # loss, and showing [OK] for it implies it was actually
                # applied (which it wasn't).
                if result.get('skipped'):
                    reason = result.get('reason') or 'skipped'
                    log(f"  [SKIPPED] {module_name}: {reason}", "info")
                    continue
                icon = "OK" if result.get('success') else "FAILED"
                log(f"  [{icon}] {module_name}: {'success' if result.get('success') else 'failed'}", "info")
                if result.get('rolled_back'):
                    log(f"       -> Rolled back to {result.get('restored_version')}", "warning")

            log(f"{'='*50}", "info")

            # ─── version table: before → after ────────────────────────
            # The opening "VERSION SUMMARY" earlier in this run logged
            # current → target. This one logs the OBSERVED after-state
            # (re-reads .env so we see what the upgrade functions
            # actually wrote, not what was planned) next to the BEFORE
            # state we captured at the top of the run. Same module list,
            # same order, so the operator can scan the two tables side
            # by side. Shows ✗ when a planned upgrade didn't change the
            # observed version — a silent partial failure that the
            # success summary above would hide.
            try:
                after_versions = get_current_versions()
            except Exception as _e:
                after_versions = {}

            log("", "info")
            log("FINAL VERSION TABLE:", "info")
            log("-" * 64, "info")
            # Iterate over a stable, predictable order that matches the
            # VERSION SUMMARY at run start.
            row_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris',
                         'velociraptor', 'prowler', 'o365rc', 'volweb']
            for mod in row_order:
                before = current_versions.get(mod, {}).get('current', '?') if isinstance(current_versions, dict) else '?'
                after = after_versions.get(mod, {}).get('current', '?') if isinstance(after_versions, dict) else '?'
                before_s = str(before)
                after_s = str(after)
                # Format per the operator-readable style:
                #   <module>: <before> -> <after>   (<status>)
                # When unchanged, collapse to a single version + the
                # word "unchanged" instead of repeating the version on
                # both sides — easier to scan.
                if before_s == after_s:
                    status = 'unchanged'
                    version_part = before_s
                    log(f"  {mod}: {version_part}   ({status})", "info")
                else:
                    if before_s in ('Not installed', 'unknown'):
                        status = 'installed'
                    elif after_s in ('Not installed', 'unknown'):
                        # Module went from installed → not — shouldn't
                        # happen in an upgrade. Loud signal that
                        # something is wrong.
                        status = 'REMOVED'
                    else:
                        status = 'upgraded'
                    log(f"  {mod}: {before_s} -> {after_s}   ({status})", "info")
            log("-" * 64, "info")

    # Workflow done. Clean up the config.yaml pre-merge backup (if any
    # — only the online flow creates one). Per-module reverts have
    # already run for each FAILED module via the orchestrator's
    # MODULE_FAILED branches above, so the operator's config.yaml is
    # in the right shape regardless of outcome.
    try:
        from .intact import cleanup_config_yaml_backup
        cleanup_config_yaml_backup(
            os.path.join(WORKDIR, 'config.yaml'), logger=log,
        )
    except Exception as _e:
        log(f"  [config-cleanup] post-workflow cleanup raised "
            f"({type(_e).__name__}: {_e}); harmless leftover at "
            f"config.yaml.pre-upgrade-backup", "warning")

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "results": results,
        "completed": completed,
        "total": total,
        "versions": versions
    }


# ============================================================================
# Online Upgrade — combined prepare + apply in a single workflow
# ============================================================================

def run_online_upgrade_workflow(modules: Dict[str, str], run_id: str = None,
                                 logger: Callable = None,
                                 db_overwrite: Dict = None) -> Dict:
    """Run prepare-then-apply in a single workflow with no tar.gz round-trip.

    For internet-connected machines. Combines the two-card flow
    ("Prepare Upgrade Package" + "Import Upgrade Package") into one
    workflow. The prepare step builds the package_dir directly at
    the persistent path the apply side already uses
    (``/app/data/tmp/intact-upgrade-<ts>/``) — no compression, no
    decompression, no tar.gz hand-off. The apply orchestration is
    the SAME loop the offline flow uses, so install-or-upgrade
    auto-detection, Phase-1/Phase-2 restart, and cascade-resilient
    per-module try/except all carry over verbatim.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    log("=" * 50, "info")
    log("ONLINE UPGRADE WORKFLOW", "info")
    log("=" * 50, "info")
    log("  Mode: prepare + apply in one run (no intermediate tar.gz)", "info")
    log("", "info")

    # DOWNLOAD-ONLY: the online upgrade installs the CI-built release package
    # and nothing else. CI builds that package from the TARGET release's OWN
    # code, so it can never drop a module an older on-box backend fails to
    # recognise (the factor-5 / "Unknown module" class). There is deliberately
    # NO on-box build fallback — building on the operator's machine is exactly
    # what produced that bug class. /api/upgrade/refs only offers releases that
    # ship a package, so a missing one here means the release was retargeted or
    # its CI build has not run yet.
    _intact_ref = modules.get('intact')
    _pkg = None
    try:
        from services.upgrade.download import (
            download_release_package, PackageDownloadCancelled)
        os.makedirs('/data/uploads', exist_ok=True)  # ALLOWED_PACKAGE_DIR
        _pkg = download_release_package(
            _intact_ref, dest_dir='/data/uploads', run_id=run_id, logger=log)
    except PackageDownloadCancelled:
        log("Upgrade cancelled during package download.", "warning")
        return {"success": False, "status": "cancelled", "cancelled": True,
                "error": "cancelled", "results": {}, "completed": 0,
                "total": 0, "versions": {}}
    except Exception as _de:
        log(f"Could not download the pre-built release package "
            f"({type(_de).__name__}: {_de}).", "error")
        _pkg = None

    if not _pkg:
        _msg = (f"Release '{_intact_ref}' ships no downloadable upgrade "
                f"package. Upgrades install the CI-built package only — "
                f"nothing is built on this machine. Pick a release that ships "
                f"a package, or run the build-release-package workflow for "
                f"this tag first.")
        log(_msg, "error")
        return {"success": False, "status": "failed", "error": _msg,
                "results": {}, "completed": 0, "total": 0, "versions": {}}

    log("", "info")
    log("=" * 50, "info")
    log("Using pre-built CI release package (no on-box build).", "success")
    log("=" * 50, "info")
    log("", "info")
    # Rejoin the SAME apply engine the offline flow uses; it extracts, verifies
    # every file against the in-package manifest, and drives the Phase-1/Phase-2
    # restart + resume. Restrict apply to the modules the operator selected
    # (the CI package always carries all of them).
    return run_offline_upgrade_workflow(
        package_path=_pkg,
        run_id=run_id,
        logger=log,
        db_overwrite=db_overwrite,
        selected_modules=list(modules.keys()),
        workflow_label="ONLINE UPGRADE (download CI package + apply)",
    )


# Backwards compatibility - expose private names as well
_run_command = run_command
_read_env_file = read_env_file
_update_env_file = update_env_file
_compare_versions = compare_versions


__all__ = [
    # Base utilities
    'WORKDIR',
    'HOST_PATH',
    'run_command',
    'read_env_file',
    'update_env_file',
    'compare_versions',
    'get_current_versions',
    'get_latest_versions',
    'load_docker_image',
    'verify_upgrade_package',
    'get_package_info',
    # Online upgrade functions
    'upgrade_elk',
    'upgrade_timesketch',
    'upgrade_plaso',
    'upgrade_iris',
    'upgrade_velociraptor',
    'upgrade_aws',
    'upgrade_azure',
    'upgrade_intact',
    # Offline upgrade functions
    'upgrade_elk_offline',
    'upgrade_timesketch_offline',
    'upgrade_plaso_offline',
    'upgrade_iris_offline',
    'upgrade_velociraptor_offline',
    'upgrade_aws_offline',
    'upgrade_azure_offline',
    'upgrade_intact_offline',
    # Workflow functions
    'run_upgrade_workflow',
    'run_offline_upgrade_workflow',
    'run_online_upgrade_workflow',
    'resume_upgrade_workflow',
    # State management
    'get_pending_upgrade',
    # Backwards compatibility
    '_run_command',
    '_read_env_file',
    '_update_env_file',
    '_compare_versions',
]
