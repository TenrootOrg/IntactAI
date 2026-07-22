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
    ensure_module_enabled_in_config,
    sweep_stale_upgrade_staging,
)

# Module-specific upgrade functions
from .elk import upgrade_elk, upgrade_elk_offline
from .cve import upgrade_cve, upgrade_cve_offline
from .timesketch import upgrade_timesketch, upgrade_timesketch_offline
from .iris import upgrade_iris, upgrade_iris_offline
from .velociraptor import upgrade_velociraptor, upgrade_velociraptor_offline
from .intact import (
    upgrade_intact, upgrade_intact_offline,
    backend_target_tag, backend_full_mode, running_backend_image,
)
from .plaso import upgrade_plaso, upgrade_plaso_offline
from .aws import upgrade_aws, upgrade_aws_offline
from .azure import upgrade_azure, upgrade_azure_offline
from .volweb import upgrade_volweb, upgrade_volweb_offline, install_volweb_offline
from .portainer import upgrade_portainer, upgrade_portainer_offline, install_portainer_offline
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


# Single source of truth for module upgrade order. Intact (the backend) MUST be
# first so backend code is updated before the modules it drives. This list was
# previously duplicated in three functions (run/resume/offline); a 2026-06-16
# drift incident — a module present in one copy but missing from another — is
# why it now lives in exactly one place, referenced everywhere.
UPGRADE_ORDER = ['intact', 'elk', 'timesketch', 'plaso', 'iris',
                 'velociraptor', 'aws_sigma', 'o365rc', 'volweb', 'cve_scan',
                 'portainer']

# Module ids renamed across releases. Old-code Phase-1 resume state, manifests
# inside packages prepared by OLD releases, and legacy API callers still carry
# the old id — normalize wherever a persisted/foreign module key meets
# UPGRADE_ORDER, or the module silently never dispatches (the 2026-06-16
# volweb-drift bug class). Drop an alias one release after its rename ships.
LEGACY_MODULE_ALIASES = {'cloudtrail': 'aws_sigma'}


def _normalize_legacy_module_keys(modules):
    """Return `modules` (a {module_id: version} dict) with legacy ids renamed
    to their current ones. If both old and new keys are present, the NEW key's
    value wins (old data already migrated)."""
    if not isinstance(modules, dict) or not any(k in modules for k in LEGACY_MODULE_ALIASES):
        return modules
    out = {}
    for k, v in modules.items():
        out[LEGACY_MODULE_ALIASES.get(k, k)] = v
    # New-key-wins on collision: re-apply values whose key was already current.
    for k, v in modules.items():
        if k not in LEGACY_MODULE_ALIASES:
            out[k] = v
    return out

# Run types that hold the single-writer upgrade lock. NOTE: the prepare route
# creates 'prepare_package' runs — prepare mutates staging + the config.yaml
# versions block, so it must be serialized with upgrades too.
UPGRADE_LOCK_RUN_TYPES = ("upgrade", "online_upgrade", "prepare_package")
# A lone running RUN (no upgrade_state row) older than this is presumed dead
# (crashed thread / dead prepare) and is auto-cleared at request time.
UPGRADE_STALE_RUN_HOURS = 4


def check_upgrade_lock(force: bool = False, logger: Callable = None) -> Dict:
    """Single-writer gate for the upgrade/prepare entry routes.

    Two upgrades running concurrently _mirror_tree the SAME live backend
    source tree and both rewrite config.yaml — install corruption. Blocked
    when:
      (a) any automation run of type UPGRADE_LOCK_RUN_TYPES is running/pending, OR
      (b) an upgrade_state row exists in ANY phase (get_active_upgrade_state) —
          rows exist for the whole workflow and survive the Phase-1 restart,
          which a threading lock would not.

    Returns {"ok": True} or {"ok": False, "reason", "blocking_run_id", "stale"}.

    Staleness escape: when the ONLY blocker is a run with NO state row and it
    hasn't been updated for UPGRADE_STALE_RUN_HOURS, it is presumed dead —
    auto-cleared (marked failed) and the gate opens. A blocker WITH a state
    row is never auto-cleared here (a legit awaiting_restart/phase2 may be
    mid-flight); only force=True clears it, loudly.

    The boot resume path never calls this (it continues an existing run).
    """
    log = logger or (lambda m, l="info": print(f"[{l}] {m}", flush=True))
    try:
        from services.workflow_service import get_all_automation_runs, update_run_status
        from services.storage.base import get_active_upgrade_state
        from datetime import datetime as _dt

        state = get_active_upgrade_state()
        blocking_run = None
        for run in (get_all_automation_runs() or []):
            if (run.get('automation_type') in UPGRADE_LOCK_RUN_TYPES
                    and run.get('status') in ('running', 'pending')):
                blocking_run = run
                break

        if not state and not blocking_run:
            return {"ok": True}

        if force:
            # Explicit operator override — clear both blockers, loudly.
            if blocking_run:
                log(f"FORCE-CLEARING in-progress upgrade run "
                    f"{blocking_run.get('run_id')} at operator request", "warning")
                update_run_status(blocking_run.get('run_id'), "failed",
                                  error="Force-cleared by a new upgrade request")
            if state:
                log(f"FORCE-CLEARING upgrade state for run {state.get('run_id')} "
                    f"(phase={state.get('phase')}) at operator request", "warning")
                clear_upgrade_state(state.get('run_id'))
            return {"ok": True}

        # Staleness escape — run-only blocker (no state row) presumed dead.
        if blocking_run and not state:
            try:
                updated = blocking_run.get('updated_at') or blocking_run.get('created_at')
                age_h = ((_dt.now() - _dt.fromisoformat(updated)).total_seconds() / 3600
                         if updated else 0)
            except Exception:
                age_h = 0
            if age_h >= UPGRADE_STALE_RUN_HOURS:
                log(f"Auto-clearing stale upgrade run {blocking_run.get('run_id')} "
                    f"(running {age_h:.1f}h with no upgrade state — presumed dead)",
                    "warning")
                update_run_status(blocking_run.get('run_id'), "failed",
                                  error=f"Stale upgrade run auto-cleared after "
                                        f"{age_h:.1f}h by a new upgrade request")
                return {"ok": True}

        blocker_id = ((blocking_run or {}).get('run_id')
                      or (state or {}).get('run_id'))
        phase = (state or {}).get('phase')
        return {
            "ok": False,
            "blocking_run_id": blocker_id,
            "stale": False,
            "reason": (f"An upgrade is already in progress (run {blocker_id}"
                       + (f", phase {phase}" if phase else "")
                       + "). Wait for it to finish, or pass force:true to clear it."),
        }
    except Exception as e:
        # The lock must never make upgrades impossible — fail open with a log.
        log(f"check_upgrade_lock errored ({type(e).__name__}: {e}); "
            f"allowing the request", "warning")
        return {"ok": True}


# An IMMUTABLE ref: a release tag (intact-YYYYMMDD, optional suffix) or a raw
# commit sha. Re-applying one of these is genuinely a no-op. A rolling ref
# (`development`, any branch) is NOT immutable — the same name resolves to new
# code over time — so it must always refresh.
_IMMUTABLE_REF_RE = re.compile(r'^(intact-\d{8}[A-Za-z0-9._-]*|[0-9a-f]{7,40})$')


def _intact_ref_is_noop(target_ref: str) -> bool:
    """True iff re-applying ``target_ref`` for `intact` would do nothing.

    Requires BOTH:
      * the ref is immutable (release tag / commit sha) — a rolling ref like
        `development` always refreshes, since the same name resolves to
        different code over time;
      * WORKDIR/VERSION already records that exact ref. VERSION is stamped only
        once that release's intact upgrade COMPLETED, so a match means the
        release is fully applied, not merely started.

    This lets an operator install a module they don't yet have, from a package
    for the release they are ALREADY on, without dragging the backend through a
    pointless mirror + restart — which also collapses the run to a single
    phase, because that restart is what forces Phase 2.
    """
    ref = (target_ref or '').strip()
    if not ref or not _IMMUTABLE_REF_RE.match(ref):
        return False              # rolling / unrecognised ref -> always refresh
    try:
        with open(os.path.join(WORKDIR, 'VERSION')) as f:
            running = f.read().strip()
    except Exception:
        return False              # can't tell -> do the work
    return bool(running) and running == ref



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




def preflight_package(package_path: str, logger: Callable = None) -> Dict:
    """Answer "would this package apply cleanly here?" WITHOUT touching anything.

    Every check below is the SAME function the real apply calls, so this cannot
    drift into a reassuring lie: verify_upgrade_package for structure/integrity,
    _reject_downgrades for ordering, required_free_gb_for_manifest +
    preflight_environment for disk/docker, backend_full_mode +
    ensure_backend_runtime_image's own precondition for the backend image.

    STRICTLY READ-ONLY. It extracts to a scratch dir under /app/data/tmp and
    removes it again; it never mirrors source, never loads an image, never
    writes config.yaml, never touches a container. A preflight that can change
    state is worse than no preflight, so the only writes are inside the scratch
    dir it owns and deletes.

    Returns {"ok": bool, "checks": [{name, ok, detail}], "blocking": [str]}.
    """
    import shutil as _sh
    import tempfile as _tf
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

        # verify_upgrade_package chooses its own extract dir under
        # /app/data/tmp (Phase 2 needs it to survive a restart). We do not get
        # to pick it, so capture what it created and delete exactly that —
        # a preflight must leave no residue behind.
        os.makedirs('/app/data/tmp', exist_ok=True)
        vr = verify_upgrade_package(package_path, logger=None)
        scratch = vr.get('extract_dir') or vr.get('package_dir')
        if not vr.get('success'):
            add("archive integrity + manifest", False, str(vr.get('error'))[:160])
            return {"ok": False, "checks": checks,
                    "blocking": [f"package failed verification: {vr.get('error')}"]}
        manifest = vr.get('manifest') or {}
        package_dir = vr.get('package_dir') or scratch
        add("archive integrity + manifest", True,
            f"{len(manifest.get('versions') or {})} module(s)")

        versions = _normalize_legacy_module_keys(manifest.get('versions', {}))
        current = get_current_versions()

        dg = _reject_downgrades(versions, current, logger=None)
        add("no module downgrades", dg is None, dg[:200] if dg else "")

        from .config_validate import (required_free_gb_for_manifest,
                                      preflight_environment as _pe)
        need = required_free_gb_for_manifest(manifest, pkg_bytes)
        env_ok, env_errs = _pe(logger=None, min_free_gb=need)
        add(f"disk + docker (needs ~{need} GiB)", env_ok,
            "; ".join(env_errs)[:200] if env_errs else "")

        # Backend image: the single most common silent defect — a Full-mode
        # release whose image is absent or named for a different tag makes the
        # box rebuild from source. Checked by INSPECTION only, no docker load.
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
            present = os.path.exists(img_tar)
            if not present:
                shipped = []
                idir = os.path.join(package_dir, 'images')
                if os.path.isdir(idir):
                    shipped = [f for f in os.listdir(idir)
                               if f.startswith('intact-backend-')]
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


def post_upgrade_health_gate(logger: Callable = None, budget_s: int = 45) -> Dict:
    """Observe whether the platform is actually serving after an upgrade.

    Every module reporting success is not the same as a working platform. On
    2026-07-22 a run finished `completed 100% · 0 errors` while the backend was
    still on the OLD image — every per-module claim was true and the overall
    verdict was wrong. This looks at the result instead of the intentions.

    Strictly observational: it NEVER fails a run, reverts anything, or blocks.
    The worst it does is downgrade the reported status to DEGRADED so the
    operator is told to look. Hard-bounded by `budget_s` (default 45s) because a
    health check that hangs is worse than one that is briefly wrong.

    Returns {"healthy": bool, "checked": int, "problems": [str]}.
    """
    import time as _t
    log = logger or (lambda m, l="info": None)
    started = _t.time()
    problems = []
    checked = 0

    def _left():
        return max(0.0, budget_s - (_t.time() - started))

    # 1. Container health — anything created but not running, or reporting
    #    unhealthy. `docker ps -a` so a container that died is not invisible.
    try:
        r = run_command(
            "docker ps -a --filter name=intact_ --format "
            "'{{.Names}}\t{{.State}}\t{{.Status}}'",
            logger=None, timeout=min(15, max(5, int(_left()))))
        for line in (r.get('stdout') or '').splitlines():
            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            name, state, status = parts[0], parts[1], parts[2]
            checked += 1
            if state != 'running':
                problems.append(f"{name} is {state} ({status[:40]})")
            elif 'unhealthy' in status.lower():
                problems.append(f"{name} reports unhealthy ({status[:40]})")
    except Exception as e:
        log(f"  [health] container check skipped ({type(e).__name__}: {e})", "warning")

    # 2. The backend is actually serving its own API — the single most useful
    #    signal, and the one a per-module success can never establish.
    if _left() > 2:
        try:
            import urllib.request
            for path in ('/api/health', '/api/upgrade/current-versions'):
                if _left() <= 2:
                    break
                checked += 1
                try:
                    with urllib.request.urlopen(
                            f'http://127.0.0.1:5001{path}',
                            timeout=min(10, max(2, int(_left())))) as resp:
                        if resp.status != 200:
                            problems.append(f"{path} returned HTTP {resp.status}")
                except Exception as e:
                    problems.append(f"{path} unreachable ({type(e).__name__})")
        except Exception as e:
            log(f"  [health] api check skipped ({type(e).__name__}: {e})", "warning")

    healthy = not problems
    if healthy:
        log(f"  Post-upgrade health: OK ({checked} checks, "
            f"{_t.time() - started:.1f}s)", "success")
    else:
        log(f"  Post-upgrade health: DEGRADED — {len(problems)} problem(s) after "
            f"an otherwise successful upgrade:", "warning")
        for pr in problems[:8]:
            log(f"    - {pr}", "warning")
        log("    The upgrade itself completed; these are runtime symptoms worth "
            "checking before you rely on the platform.", "warning")
    return {"healthy": healthy, "checked": checked, "problems": problems}


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


def _upgrade_noop_module(module_name: str, target_ref: str = None) -> bool:
    """True iff this module needs NOTHING done this upgrade — it's already
    installed and none of its version pins changed (the primary pin `M` OR any
    transitive sidecar pin `M_*`, e.g. timesketch_opensearch / iris_rabbitmq /
    volweb_postgres). Such a module is skipped so we don't pointlessly re-load
    images + recreate its containers for an identical version.

    How "changed" is decided: the config-merge writes the release's target pins
    into config.yaml during Phase 1 and leaves the operator's pre-merge pins in
    config.yaml.pre-upgrade-backup. So comparing the two, per key, is an exact
    delta — a primary bump OR any sidecar bump for this module counts as a
    change. `intact` ALWAYS refreshes (rolling refs). Returns False (i.e. DO
    process) whenever we can't tell — module absent (that's an install, per the
    operator's package selection) or the backup is missing — so we never skip
    something that actually needed work.
    """
    if module_name == 'intact':
        # Rolling refs always refresh; an immutable tag already recorded in
        # VERSION is a true no-op (see _intact_ref_is_noop).
        return _intact_ref_is_noop(target_ref)
    from .base import _module_container_exists
    if _module_container_exists(module_name) is False:
        return False
    import yaml
    try:
        with open(os.path.join(WORKDIR, 'config.yaml')) as f:
            target = (yaml.safe_load(f) or {}).get('versions') or {}
        with open(os.path.join(WORKDIR, 'config.yaml.pre-upgrade-backup')) as f:
            pre_merge = (yaml.safe_load(f) or {}).get('versions') or {}
    except Exception:
        return False   # no reliable comparison -> don't skip
    if not pre_merge:
        return False
    for key, tgt in target.items():
        if key != module_name and not key.startswith(module_name + '_'):
            continue
        if str(pre_merge.get(key)).strip() != str(tgt).strip():
            return False   # primary or a sidecar pin changed / was added
    return True

# Database volumes that can be reset for fresh install (schema compatibility)
RESET_VOLUMES = {
    'timesketch': ['timesketch_timesketch_postgres_data', 'timesketch_timesketch_opensearch_data'],
    'iris': ['iris_iris_db_data'],
    'elk': ['elk_elasticsearch_data'],
}


def reset_module_database(module_name: str, logger: Callable = None) -> bool:
    """DISABLED: the 'start fresh' (db_overwrite) feature has been removed.

    Upgrades always preserve data via DB migrations (e.g. Timesketch's alembic
    `tsctl db upgrade`), and downgrades are not supported, so a destructive volume
    wipe is never needed. This is now a hard no-op so any stale `db_overwrite` flag
    or persisted upgrade state can NEVER delete a module's data.

    (The Timesketch major-Postgres migration in timesketch.py does its own
    backup-first dump->wipe->restore and is unaffected by this.)
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log(f"'Start fresh' is disabled — no data wipe performed for {module_name}", "info")
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


def schedule_backend_restart(run_id: str = None, logger: Callable = None) -> bool:
    """DEPRECATED — UNREACHABLE in a Full-mode-only fleet.

    `docker restart` reuses the container's existing image, so it can never
    apply a new backend image or a changed compose file. Every supported
    release now runs the backend from intact-backend:<release>, and
    upgrade_intact_offline REFUSES a legacy source-mounted target outright
    (see the LEGACY TARGET REJECTED branch in intact.py), so needs_swap is
    always True and the swap dispatch always wins.

    Kept, not deleted, because it is still the correct primitive for the
    non-upgrade restart cases and because deleting a function this deep in the
    dispatch while the retrofit is still being validated buys nothing. It
    should be removed once a full release cycle has shipped with no legacy
    target reaching it.

    Original behaviour, retained: schedules a backend restart after a short
    delay using a detached process.

    Hardened (G4): previously fire-and-forget with output DEVNULL'd — a failed
    `docker restart` (socket busy/denied) left the OLD code running with the
    run parked at 50% forever, silently. Now:
      - restart output is appended to /app/data/tmp/restart-<run_id|ts>.log
        so a failed restart is diagnosable post-mortem;
      - a 90s self-check watchdog fires if THIS process is still alive (the
        restart never happened): logs to the run, retries `docker restart`
        once synchronously, and if a second 90s window also passes, marks the
        run failed with manual-recovery guidance. The upgrade_state row is
        deliberately KEPT so a manual `docker restart intact_backend` still
        resumes Phase 2.
    Returns False if the restart could not even be spawned.
    """
    import threading as _threading
    log = logger or (lambda m, l="info": print(f"[{l}] {m}", flush=True))
    tag = run_id or datetime_now_tag()
    log_path = f"/app/data/tmp/restart-{tag}.log"

    def _spawn() -> bool:
        try:
            os.makedirs("/app/data/tmp", exist_ok=True)
            with open(log_path, 'a') as lf:
                subprocess.Popen(
                    ['sh', '-c', 'sleep 3 && docker restart intact_backend intact_tusd'],
                    stdout=lf, stderr=lf, start_new_session=True,
                )
            return True
        except Exception as e:
            log(f"Could not spawn backend restart ({type(e).__name__}: {e})", "error")
            return False

    def _still_alive_check(attempt: int):
        # If we're executing this, docker restart did NOT kill us.
        try:
            from services.workflow_service import add_log_to_run, update_run_status
            if attempt == 1:
                add_log_to_run(run_id, "Backend restart did not occur within 90s — "
                                        "retrying docker restart once", "error")
                run_command("docker restart intact_backend intact_tusd",
                            logger=None, timeout=120)
                t = _threading.Timer(90, _still_alive_check, args=(2,))
                t.daemon = True
                t.start()
            else:
                update_run_status(
                    run_id, "failed",
                    error="Backend restart could not be performed — check the "
                          "docker socket mount/permissions (see "
                          f"{log_path}). Upgrade state is preserved: restart "
                          "intact_backend manually and Phase 2 will resume.")
        except Exception as e:
            print(f"[UPGRADE] restart watchdog error: {e}", flush=True)

    ok = _spawn()
    if ok and run_id:
        t = _threading.Timer(90, _still_alive_check, args=(1,))
        t.daemon = True
        t.start()
    return ok


# ── Wave F: recreate handoff (Full-mode image swap) ─────────────────────────
# The swap counterpart of schedule_backend_restart. `docker restart` cannot apply
# a new image, and a compose-up issued from inside the backend dies mid-stop with
# its own container (platform stuck DOWN). So a DETACHED HELPER CONTAINER, run
# from the OLD image (guaranteed present, ships docker + compose v2), recreates
# backend+tusd from the new image, health-polls the container's own healthcheck,
# and on failure rolls the source tree + image back. All resume state is on host
# binds, so the recreated container's boot resumes Phase 2 exactly like a restart.

# Helper/recover scripts are templated with sentinel tokens (sh uses $ and {}
# heavily, which would fight f-strings / .format()).
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
def self_heal_backend_swap(logger: Callable = None, parent_run_id: str = None) -> Dict:
    """Detect + fix a backend stuck on the wrong image for a Full-mode
    release — covers BOTH the tag-mismatch case (e.g. still on 1.0.0 when
    config.yaml wants 'development') AND the same-tag-but-stale-content case
    ('development' is a documented MUTABLE tag: a box can already show
    'intact-backend:development' while the branch has moved forward since
    that image was baked — an operator deliberately re-running an upgrade to
    the same tag, e.g. after a partial failure or to pick up a forgotten
    module, needs this to actually refresh, not silently no-op).

    `parent_run_id`: when this fires from INSIDE an already-tracked workflow
    (e.g. the Phase-2 finalizer's convergence check), pass that run's ID so
    the swap continues logging into the SAME tracked run instead of minting
    a second, disconnected "Backend self-heal (image swap)" entry next to
    the "Online Upgrade" the operator is already watching. Only a genuine
    cold-boot self-heal (no caller run to attach to) creates a fresh run.

    Drift detection deliberately does NOT compare built Docker image IDs —
    those are sensitive to file mtimes in the build context (a routine git
    checkout or chown touches mtimes with zero content change) and are not
    guaranteed reproducible across separate `docker build` invocations even
    for byte-identical source; comparing them produced false positives on
    every boot in testing. Instead: a cheap tag-string comparison catches the
    original bug for free, and a content fingerprint (sha256 over the actual
    backend source bytes, recorded at every successful swap) catches
    same-tag drift — only computed when tags already match, so the common
    case costs nothing extra. Bounded to one automatic attempt per target tag
    via a marker file — a repeat mismatch after that means something is
    genuinely broken and needs a human, not a retry-loop."""
    log = logger or (lambda m, l="info": print(f"[{l}] {m}", flush=True))
    compose_path = os.path.join(WORKDIR, 'modules', 'backend', 'docker-compose.yaml')
    if not backend_full_mode(compose_path):
        return {"healed": False, "reason": "legacy (mount-based) release — no swap needed"}

    target_tag = backend_target_tag()
    target_image = f"intact-backend:{target_tag}"
    running_ref = running_backend_image()
    if not running_ref:
        return {"healed": False, "reason": "could not determine the running backend image"}

    tag_mismatch = running_ref != target_image
    content_drift = False
    if not tag_mismatch:
        from .intact import backend_source_fingerprint, read_recorded_backend_source_fingerprint
        recorded_fp = read_recorded_backend_source_fingerprint()
        if recorded_fp:
            current_fp = backend_source_fingerprint()
            content_drift = bool(current_fp) and current_fp != recorded_fp

    if not tag_mismatch and not content_drift:
        return {"healed": False, "reason": "already on target image (content current)"}

    marker = f"/app/data/tmp/backend-selfheal-{target_tag}.attempted"
    if os.path.exists(marker):
        log(f"Backend {'content drift' if content_drift else 'image mismatch'} "
            f"(running {running_ref}, target {target_image}) was already auto-healed "
            f"once for this target and is STILL mismatched — not retrying automatically. "
            f"This needs manual investigation (remove {marker} to allow one more attempt).",
            "error")
        return {"healed": False, "reason": "already attempted; needs manual investigation"}

    # Create the tracked run BEFORE the marker so its ID can be embedded —
    # the recreate is asynchronous (a detached helper does the actual swap
    # after this function returns), so this run can't be marked "completed"
    # synchronously here. It's finalized on the NEXT boot by app.py checking
    # this same marker: if the running image matches by then, the swap
    # worked and the run is marked completed instead of being reaped as a
    # generic "orphaned by restart" by the unrelated upgrade-watchdog.
    #
    # (That boot-time finalize step is a no-op when parent_run_id was used
    # and the parent already finished — it only flips a still-pending/running
    # run to completed, which a caller-owned run already isn't by then.)
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    if parent_run_id:
        run_id = parent_run_id
    else:
        run_id = create_automation_run(
            automation_type="online_upgrade",
            name="Backend self-heal (image swap)",
            details={"trigger": "boot-self-heal", "target_tag": target_tag,
                     "old_image": running_ref, "content_drift": content_drift},
        )
        update_run_status(run_id, "running", progress=5)
    try:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, 'w') as f:
            f.write(f"run_id={run_id}\ntarget_tag={target_tag}\n")
    except Exception as e:
        log(f"  (could not write self-heal marker: {e})", "warning")

    def _dual_log(m, l="info"):
        # log() is whatever the caller passed as `logger`. For a cold-boot
        # self-heal, that's a plain console printer with no run attached —
        # add_log_to_run() below is the ONLY thing that gets the message
        # into the (freshly created) tracked run. But when parent_run_id is
        # used, `logger` IS the finalizer's own log(), which already writes
        # to this exact run_id — calling add_log_to_run() again here would
        # double every line in that run's log (seen as literal duplicate
        # consecutive lines in production).
        log(m, l)
        if not parent_run_id:
            add_log_to_run(run_id, m, l)

    if content_drift:
        _dual_log(f"Refreshing {target_image} (content changed since it was built)...", "info")
    else:
        _dual_log(f"Converging backend onto {target_image}...", "info")

    # Build if the target tag isn't present locally, OR if content drifted —
    # an existing same-tagged image is exactly what's stale in that case.
    need_build = content_drift or not run_command(
        f"docker image inspect {target_image}", logger=None, timeout=30).get('success')
    if need_build:
        backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
        update_env_file(backend_env, 'BACKEND_VERSION', target_tag, logger=None)
        _dual_log(f"Baking {target_image} from the live source tree (no package "
                   f"available at boot — building from what's already on disk)...", "info")
        build = run_command("docker compose build backend",
                            cwd=os.path.join(WORKDIR, 'modules', 'backend'),
                            timeout=900, logger=lambda m, l="info": _dual_log(m, l))
        # A non-zero/timed-out `docker compose build` does NOT prove the image
        # is missing. Observed 2026-07-22 on a live convergence: the image was
        # committed fine but the compose CLI never exited (a `docker` child went
        # zombie), so run_command hit its 900s timeout — and this branch would
        # have declared failure and left the box on the OLD image with a
        # perfectly good new one sitting in the local store. Trust the image
        # store, not the exit code: re-inspect and carry on if it's really there.
        if not build.get('success') and run_command(
                f"docker image inspect {target_image}", logger=None,
                timeout=30).get('success'):
            _dual_log(f"  `compose build` reported failure ({(build.get('error') or '')[:120]}) "
                      f"but {target_image} IS present in the image store — continuing "
                      f"with the swap.", "warning")
            build = {"success": True}

        if not build.get('success'):
            _err = (f"Self-heal image build FAILED: {(build.get('error') or '')[:300]} — "
                    f"platform stays on the old image; investigate manually")
            _dual_log(_err, "error")
            # Only flip status here for a standalone (cold-boot) self-heal run.
            # A parent_run_id belongs to the caller (e.g. the Online Upgrade
            # finalizer), which force-completes it right after this returns —
            # that would silently clobber a "failed" set here. The caller
            # reflects this failure in its own outcome instead (see
            # resume_upgrade_workflow's finalizer).
            if not parent_run_id:
                update_run_status(run_id, "failed", error=_err)
            return {"healed": False, "reason": "image build failed", "run_id": run_id}

    ok = prepare_recreate_handoff(
        run_id,
        {"target_tag": target_tag, "old_image": running_ref, "snapshot": None},
        logger=lambda m, l="info": add_log_to_run(run_id, m, l),
    )
    if not ok:
        _err = "Self-heal recreate handoff could not be spawned"
        _dual_log(_err, "error")
        if not parent_run_id:
            update_run_status(run_id, "failed", error=_err)
        return {"healed": False, "reason": "recreate handoff failed to spawn", "run_id": run_id}
    return {"healed": True, "run_id": run_id}


def shlex_quote(s: str) -> str:
    import shlex as _shlex
    return _shlex.quote(s)


def datetime_now_tag() -> str:
    from datetime import datetime as _dt
    return _dt.now().strftime('%Y%m%d_%H%M%S')


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
    upgrade_order = list(UPGRADE_ORDER)
    upgrade_functions = {
        'elk': upgrade_elk,
        'timesketch': upgrade_timesketch,
        'plaso': upgrade_plaso,
        'iris': upgrade_iris,
        'velociraptor': upgrade_velociraptor,
        'aws_sigma': upgrade_aws,
        'o365rc': upgrade_azure,
        'volweb': upgrade_volweb,
        'intact': upgrade_intact,
        'cve_scan': upgrade_cve,
        'portainer': upgrade_portainer,
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

            # A2: skip a module that needs nothing done — already installed and
            # neither its primary version nor any sidecar pin changed. intact
            # refreshes unless the target is an immutable tag already applied
            # (see _upgrade_noop_module / _intact_ref_is_noop).
            if _upgrade_noop_module(module_name, target_version):
                log(f"  {module_name.upper()}: already at {target_version} — no version/sidecar change, skipping", "info")
                results[module_name] = {"success": True, "skipped": True,
                                        "reason": "already up to date (no change)"}
                continue

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
                    # Pass the target version (kwarg — the offline intact handler
                    # is a **kw lambda) so the handler can stamp WORKDIR/VERSION
                    # even when the source tree has no release-stamped VERSION
                    # file (dev-built packages / non-release branches).
                    result = upgrade_fn(version=target_version, logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed += 1
                    completed_modules.append(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Surface an honest health verdict (G5): success with a
                    # degraded/down module is visible, never silent. WARNING
                    # level on purpose — an error-level line would auto-flip
                    # the completed run to failed (workflow_service:428).
                    if result.get('health') in ('degraded', 'down'):
                        log(f"MODULE_DEGRADED: {module_name.upper()} — "
                            f"{result.get('health')}: {result.get('health_detail', '')}",
                            "warning")

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

                            # The resume state MUST be persisted before we
                            # restart — a restart without it means Phase 2
                            # silently never runs (remaining modules vanish).
                            _saved = save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode,
                                                        db_overwrite=db_overwrite)
                            if not _saved:
                                log("Retrying resume-state persist...", "warning")
                                _saved = save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode,
                                                            db_overwrite=db_overwrite)
                            if not _saved:
                                log("Could not persist Phase-2 resume state — ABORTING "
                                    "before restart (a restart now would silently drop "
                                    "the remaining modules). Check data/intact.db "
                                    "writability and re-run the upgrade.", "error")
                                return {"success": False,
                                        "error": "failed to persist Phase-2 resume state; "
                                                 "restart aborted"}
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart(run_id=run_id, logger=log)

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
                            schedule_backend_restart(logger=log)

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

    if state['phase'] not in ('awaiting_restart', 'phase2'):
        # 'phase2' is accepted: it means the previous backend process died
        # MID-Phase-2 and this boot is re-entering the loop. completed_modules
        # is re-read from state so finished modules are skipped; the in_flight
        # module (if any) bypasses its noop shortcut below.
        return {"success": False, "error": f"Upgrade not resumable from phase: {state['phase']}"}

    log("", "info")
    log(f"{'='*50}", "info")
    log("PHASE 2 - RESUMING UPGRADE AFTER RESTART", "info")
    log(f"Run ID: {run_id}", "info")
    log(f"{'='*50}", "info")

    # Restart nginx first (for new UI code)
    restart_nginx(log)

    # Mark as phase 2 in progress
    update_upgrade_phase(run_id, 'phase2')

    # Old-code Phase 1 may have saved legacy module ids (e.g. 'cloudtrail')
    modules = _normalize_legacy_module_keys(state['target_modules'])
    completed_modules = set(state['completed_modules'])
    mode = state.get('mode', 'online')
    db_overwrite = state.get('db_overwrite', {})  # Per-module fresh install flags
    # Module that was mid-dispatch when the previous process died (crash
    # between .env pin bump and compose-up makes it LOOK already-upgraded);
    # it must bypass the noop shortcut and re-run its down->up (idempotent).
    in_flight_module = state.get('in_flight')

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

    # ── Phase 2 (NEW code) finalizes intact's version + config pin ───────────
    # Phase 1 copied the package source and restarted; we are now executing the
    # JUST-INSTALLED code. Re-stamp WORKDIR/VERSION and re-write config.yaml's
    # backend pin HERE so the SHIPPING release governs them — a fix landed in the
    # new code (e.g. a VERSION-stamping or writeback change) takes effect on the
    # very upgrade that delivers it, not one upgrade later. The package-source
    # COPY + the restart are the only intact steps that must run in the old
    # pre-restart code; everything else is the new code's job. Idempotent: Phase
    # 1 may already have done this in the old code — re-doing it just lets the
    # newest logic win.
    intact_target = (modules or {}).get('intact')
    if intact_target:
        try:
            from .intact import stamp_intact_version
            stamp_intact_version(package_dir, intact_target, logger=log)
        except Exception as e:
            log(f"  Phase-2 VERSION stamp raised ({type(e).__name__}: {e})", "warning")
        if intact_target != 'from_package':
            try:
                from .base import set_module_version_in_config
                set_module_version_in_config('backend', intact_target, logger=log)
            except Exception as e:
                log(f"  Phase-2 backend config writeback raised ({type(e).__name__}: {e})", "warning")

    # Config schema migrations — run HERE (Phase 2, new code, post-restart) and
    # BEFORE the module loop, so any structural config change (renames, retired
    # keys) is applied before an upgrader reads a migrated key. This is a
    # separate step from the versions-merge (which ran in Phase 1, pre-restart)
    # with its own backup/rollback, so the two never observe each other's
    # writes. Idempotent: a re-resume finds schema already bumped and no-ops.
    # With an empty registry this is a clean no-op; it exists so future
    # migrations have a wired, tested home.
    def _fail_phase2(reason):
        """Mark the run failed and clear the pending state before returning."""
        try:
            from services.workflow_service import update_run_status
            update_run_status(run_id, "failed", error=reason)
        except Exception:
            pass
        try:
            clear_upgrade_state(run_id)
        except Exception:
            pass
        return {"success": False, "error": reason}

    try:
        from .config_migrations import apply_config_migrations
        _cfg_path = os.path.join(WORKDIR, 'config.yaml')
        _mig = apply_config_migrations(_cfg_path, logger=log)
        if not _mig.get('success'):
            log(f"Config migration failed ({_mig.get('error')}); aborting Phase 2 "
                f"before any module upgrade. config.yaml was restored from backup.",
                "error")
            return _fail_phase2(f"config migration failed: {_mig.get('error')}")
        # Re-validate the (possibly migrated) config before the loop reads it.
        from .config_validate import validate_config
        _ok, _errs = validate_config(_cfg_path, logger=log, require_pins=False)
        if not _ok:
            log("Post-migration config.yaml validation failed:", "error")
            for _e in _errs:
                log(f"  - {_e}", "error")
            return _fail_phase2("post-migration validation failed: " + "; ".join(_errs))
    except Exception as e:
        log(f"  Config migration step raised ({type(e).__name__}: {e}); "
            f"continuing without migrations", "warning")

    # aws_sigma reassurance: an OLDER release's prepare can't recognize the
    # renamed 'aws_sigma' module and logs a scary "Unknown module" while
    # bundling. That's harmless on a connected box — aws_sigma reads its rules
    # LIVE from /opt/sigma-rules/rules/cloud/aws (populated at install), so once
    # enabled it just works; the bundled rule pack only matters for air-gap.
    # Emit a clear confirmation here (Phase 2 = new code, so it shows even on
    # the transitional upgrade) so the operator isn't left thinking aws_sigma
    # failed. Best-effort; never affects the upgrade.
    try:
        import yaml as _yaml
        with open(os.path.join(WORKDIR, 'config.yaml')) as _cf:
            _cfg = _yaml.safe_load(_cf) or {}
        _aws = (_cfg.get('modules') or {}).get('aws_sigma') or {}
        if isinstance(_aws, dict) and _aws.get('enabled'):
            _rules_dir = '/opt/sigma-rules/rules/cloud/aws'
            if os.path.isdir(_rules_dir):
                _n = sum(1 for _r, _d, _fs in os.walk(_rules_dir)
                         for _f in _fs if _f.endswith(('.yml', '.yaml')))
                log(f"aws_sigma is enabled and its detection rules are present "
                    f"({_n} rules at {_rules_dir}) — active. (Any 'Unknown "
                    f"module: aws_sigma' from prepare is expected on a "
                    f"cross-version upgrade and is harmless here.)", "success")
    except Exception as _ae:
        log(f"  (aws_sigma status check skipped: {_ae})", "info")

    # 2026-06-16 incident: volweb was silently dropped from Phase 2
    # because resume_upgrade_workflow's upgrade_order didn't include it,
    # even though run_offline_upgrade_workflow and run_online_upgrade
    # (the other two copies of this list) DID. Operator selected volweb,
    # Phase 1 ran, backend restarted, this loop iterated — volweb wasn't
    # in the list, never got dispatched, never appeared in the summary.
    # All three copies of upgrade_order must include the same modules;
    # this one drifted. Keep them in sync.
    upgrade_order = list(UPGRADE_ORDER)

    # Pick functions by the mode SAVED IN THE STATE — which matters for
    # BACKWARD COMPATIBILITY: when upgrading FROM an older release, Phase 1 runs
    # on the OLD code and saves this resume state in the OLD release's format/
    # mode, then the backend restarts into the NEW code and THIS function reads
    # that old state. A modern upgrade (online OR offline) saves mode='offline'
    # with a persistent package_dir — both take the offline branch (online =
    # prepare + offline-apply, so no duplicate path in practice). But an OLDER
    # release whose online upgrade saved mode='online' (no package_dir) MUST
    # still resume via the online image-pull functions — hence the branch stays.
    if mode == 'offline':
        upgrade_functions = {
            'elk': lambda v, **kw: upgrade_elk_offline(package_dir, v, **kw),
            'timesketch': lambda v, **kw: upgrade_timesketch_offline(package_dir, v, **kw),
            'plaso': lambda v, **kw: upgrade_plaso_offline(package_dir, v, **kw),
            'iris': lambda v, **kw: upgrade_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: upgrade_velociraptor_offline(package_dir, v, **kw),
            'aws_sigma': lambda v, **kw: upgrade_aws_offline(package_dir, v, **kw),
            'o365rc': lambda v, **kw: upgrade_azure_offline(package_dir, v, **kw),
            'volweb': lambda v, **kw: upgrade_volweb_offline(package_dir, v, **kw),
            'intact': lambda **kw: upgrade_intact_offline(package_dir, **kw),
            'cve_scan': lambda v, **kw: upgrade_cve_offline(package_dir, v, **kw),
            'portainer': lambda v, **kw: upgrade_portainer_offline(package_dir, v, **kw),
        }
        # Install-vs-upgrade dispatch: when a module's container doesn't exist
        # yet (fresh install via the upgrade flow) Phase-2 must run the INSTALL
        # fn, not the upgrade fn — otherwise it docker-execs into a missing
        # container and crashes / reports false success (the 2026-06-08
        # fresh-install iris/timesketch incident).
        install_functions = {
            'elk':          lambda v, **kw: install_elk_offline(package_dir, v, **kw),
            'timesketch':   lambda v, **kw: install_timesketch_offline(package_dir, v, **kw),
            'iris':         lambda v, **kw: install_iris_offline(package_dir, v, **kw),
            'velociraptor': lambda v, **kw: install_velociraptor_offline(package_dir, v, **kw),
            'volweb':       lambda v, **kw: install_volweb_offline(package_dir, v, **kw),
            'portainer':    lambda v, **kw: install_portainer_offline(package_dir, v, **kw),
        }
    else:
        # Backward-compat path for older-release states saved as mode='online'
        # (those upgrades pulled images directly, no package_dir). Modern
        # online upgrades never reach here — they save 'offline' above.
        upgrade_functions = {
            'elk': upgrade_elk,
            'timesketch': upgrade_timesketch,
            'plaso': upgrade_plaso,
            'iris': upgrade_iris,
            'velociraptor': upgrade_velociraptor,
            'intact': upgrade_intact,
            'cve_scan': upgrade_cve,
        }
        install_functions = {}  # old online flow had no upgrade-as-install

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

    # Per-module progress for the UI: Phase 1 parked the run at 50%; walk
    # 50 -> 95% across Phase 2's remaining modules so the operator isn't
    # staring at a frozen bar for the whole resume (G7).
    _p2_total = len([m for m in upgrade_order
                     if m in modules and m not in completed_modules]) or 1
    _p2_done = 0

    def _p2_progress():
        try:
            from services.workflow_service import update_run_status
            update_run_status(run_id, "running",
                              progress=min(95, 50 + int(45 * _p2_done / _p2_total)))
        except Exception:
            pass

    try:
        for module_name in upgrade_order:
            if module_name not in modules or module_name in completed_modules:
                continue

            # Check Stop before each module — mirrors the offline loop's
            # check; gives a quick exit even when the per-module function
            # isn't fully cancellation-aware (cancel event is registered by
            # app.py's resume thread).
            try:
                from services.workflow_service import is_cancelled
                if run_id and is_cancelled(run_id):
                    log("Phase 2 cancelled by user before module dispatch", "warning")
                    overall_status = "cancelled"
                    break
            except Exception:
                pass

            target_version = modules[module_name]
            current = current_versions.get(module_name, {}).get('current', 'unknown')

            # A2: skip a module that needs nothing done — already installed and
            # neither its primary version nor any sidecar pin changed. intact
            # always refreshes (see _upgrade_noop_module). EXCEPTION: the
            # module that was in_flight when the previous process died must
            # NOT take this shortcut — a crash after its pin bump makes it
            # look done while the old containers still run; its down->up is
            # idempotent, so re-running is always safe.
            if (_upgrade_noop_module(module_name, target_version)
                    and module_name != in_flight_module):
                log(f"  {module_name.upper()}: already at {target_version} — no version/sidecar change, skipping", "info")
                results[module_name] = {"success": True, "skipped": True,
                                        "reason": "already up to date (no change)"}
                continue
            if module_name == in_flight_module:
                log(f"  {module_name.upper()}: was mid-dispatch when the previous "
                    f"process died — re-running its upgrade (noop shortcut bypassed)", "warning")

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

            # Mark this module in_flight so a process death mid-dispatch is
            # detectable on resume (see the noop-shortcut bypass above).
            try:
                from services.storage.base import set_upgrade_in_flight
                set_upgrade_in_flight(run_id, module_name)
            except Exception:
                pass

            try:
                if module_name == 'intact':
                    # Pass the target version (kwarg — the offline intact handler
                    # is a **kw lambda) so the handler can stamp WORKDIR/VERSION
                    # even when the source tree has no release-stamped VERSION
                    # file (dev-built packages / non-release branches).
                    result = upgrade_fn(version=target_version, logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed_modules.add(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Surface an honest health verdict (G5): success with a
                    # degraded/down module is visible, never silent. WARNING
                    # level on purpose — an error-level line would auto-flip
                    # the completed run to failed (workflow_service:428).
                    if result.get('health') in ('degraded', 'down'):
                        log(f"MODULE_DEGRADED: {module_name.upper()} — "
                            f"{result.get('health')}: {result.get('health_detail', '')}",
                            "warning")

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
                        from .base import set_module_version_in_config, ensure_module_enabled_in_config
                        yaml_key = 'backend' if module_name == 'intact' else module_name
                        if target_version and target_version != 'from_package':
                            try:
                                set_module_version_in_config(yaml_key, target_version, logger=log)
                            except Exception as _ve:
                                log(f"  config.yaml version-writeback failed for {module_name}: {_ve}", "warning")
                        if action_word == 'INSTALLING' and module_name != 'intact':
                            try:
                                # ensure_* both CREATES a missing block AND
                                # enables it — a brand-new module the target's
                                # config.yaml never had now lands enabled:true
                                # rather than silently no-op'ing (flip-only).
                                ensure_module_enabled_in_config(module_name, logger=log)
                            except Exception as _ee:
                                log(f"  config.yaml enable failed for {module_name}: {_ee}", "warning")
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

            # One module finished (success OR handled failure) — clear the
            # in_flight marker (only a real process death leaves it set) and
            # advance the bar.
            try:
                from services.storage.base import set_upgrade_in_flight
                set_upgrade_in_flight(run_id, None)
            except Exception:
                pass
            _p2_done += 1
            _p2_progress()

    except Exception as unexpected_error:
        log(f"UNEXPECTED WORKFLOW ERROR: {unexpected_error}", "error")
        overall_status = "failed"
        results["_workflow_error"] = str(unexpected_error)

    finally:
        log("", "info")
        log(f"{'='*50}", "info")
        log("FINALIZING PHASE 2", "info")
        log(f"{'='*50}", "info")

        # Wave-F: LOAD the baked backend image into the docker store BEFORE the
        # extracted package is deleted below. `docker load` puts the image in the
        # local store where it PERSISTS after the package dir is gone, so the
        # convergence self-heal (both the one a few lines down AND the boot-time
        # safety net in app.py) finds intact-backend:<tag> already present and
        # RECREATES onto it with --no-build. Without this, convergence had no
        # image to inspect and fell back to `docker compose build backend`; that
        # source rebuild stalled (bounded to 900s by run_command, then failed)
        # and stranded boxes on the old intact-backend:1.0.0 image at ~95%.
        try:
            from .intact import (backend_full_mode as _bfm,
                                 backend_target_tag as _btt,
                                 ensure_backend_runtime_image as _ebri)
            _cp0 = os.path.join(WORKDIR, 'modules', 'backend', 'docker-compose.yaml')
            if extract_dir and os.path.isdir(extract_dir) and _bfm(_cp0):
                _tt0 = _btt()
                _ens = _ebri(extract_dir, _tt0, run_id=run_id, logger=log)
                if _ens.get("available"):
                    log(f"  Backend image intact-backend:{_tt0} loaded from package "
                        f"— convergence will recreate, not rebuild.", "info")
                else:
                    log(f"  Backend image intact-backend:{_tt0} not pre-baked in this "
                        f"package — convergence will rebuild it from source (works, but "
                        f"slower). Prepare the package on a Full-mode release to bundle "
                        f"the image and skip the rebuild.", "info")
        except Exception as _pl:
            log(f"  (pre-cleanup backend image load skipped: {_pl})", "warning")

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
        # tusd sidecars (<upload>.info / .run) — small, but accumulate
        # forever in the upload_data volume if never reaped.
        for _side in (f"{package_path}.info", f"{package_path}.run"):
            try:
                if _side and os.path.exists(_side):
                    os.remove(_side)
            except Exception:
                pass

        # Final nginx restart
        restart_nginx(log)

        # Phase 2 is running ON the new code — reaching this finalizer is the
        # proof it boots. The anti-brick rollback snapshot has served its
        # purpose; reclaim the space. (A FAILED intact gate never reaches
        # Phase 2 — its snapshot is kept for recovery, swept after 168h.)
        try:
            from .intact import cleanup_rollback_snapshots
            cleanup_rollback_snapshots(logger=log)
        except Exception as _rs:
            log(f"  rollback-snapshot cleanup skipped ({_rs})", "warning")

        # Wave F: reaching this finalizer on a swap run proves the new image boots.
        # Drop the .env pre-upgrade backup (success), and CONVERGENCE SAFETY-NET —
        # if an OLD Phase 1 applied a Full-mode release (mirror+restart, no swap),
        # the box is on the old image with the new full-mode compose on disk and
        # code running from the (now-removed-in-compose) mounts. That's functional
        # but not converged.
        #
        # Previously this only WARNED the operator to manually re-run the whole
        # upgrade to converge — a real gap: the warning is easy to miss (buried in
        # a long log), and until the operator notices and acts, the box silently
        # stays on the old install-day image indefinitely (nothing else triggers a
        # backend restart on its own). Now triggers self_heal_backend_swap()
        # directly instead: it's the exact same mechanism boot-time self-heal
        # already uses successfully, is bounded to one automatic attempt per
        # target tag via its own marker file (so this can never loop), and only
        # SPAWNS a detached helper container that does the actual recreate a few
        # seconds later — it does not recreate the currently-running container
        # synchronously from within itself. This whole finalizer already runs in
        # a background thread (Phase 2 resume is launched via threading.Thread in
        # app.py), so blocking here for the image build is safe.
        try:
            from .base import cleanup_backup
            _be_bak = os.path.join(WORKDIR, 'modules', 'backend', '.env.pre-upgrade-backup')
            if os.path.exists(_be_bak):
                cleanup_backup(_be_bak, logger=log)
        except Exception as _cb:
            log(f"  .env backup cleanup skipped ({_cb})", "warning")
        try:
            from .intact import backend_full_mode, backend_target_tag, running_backend_image
            _cp = os.path.join(WORKDIR, 'modules', 'backend', 'docker-compose.yaml')
            if backend_full_mode(_cp):
                _tt = backend_target_tag()
                _run_img = running_backend_image() or ''
                if _run_img != f"intact-backend:{_tt}":
                    # self_heal_backend_swap() logs its own "Converging backend
                    # onto..." line — no separate announcement needed here (it
                    # used to be worded differently, so this wasn't visible as
                    # a literal duplicate; now that both are short and plain,
                    # logging it twice read as a bug).
                    # parent_run_id=run_id: keep this as ONE workflow from the
                    # operator's perspective — continue logging into this same
                    # "Online Upgrade" run instead of spawning a second,
                    # disconnected "Backend self-heal (image swap)" entry.
                    _heal = self_heal_backend_swap(logger=log, parent_run_id=run_id)
                    if _heal.get("healed"):
                        log("  Self-heal swap triggered — backend will recreate onto "
                            "the new image within the next ~10-60s (this same "
                            "workflow's log will continue to show its progress).",
                            "success")
                    else:
                        log(f"  Self-heal swap could not be triggered automatically "
                            f"({_heal.get('reason')}) — re-run this upgrade, or "
                            f"restart the backend, to converge onto intact-backend:"
                            + _tt + ".", "warning")
                        # Since this run's outcome no longer gets its own separate
                        # workflow entry, fold the failure into `results` so the
                        # shared run's final status reflects it (app.py's caller
                        # force-completes on `result['success']`, computed from
                        # `results` — without this, a synchronous self-heal
                        # failure would be logged but the run would still show a
                        # plain green "completed").
                        results['_backend_selfheal'] = {
                            'success': False,
                            'error': f"Backend did not converge onto intact-backend:"
                                     f"{_tt} ({_heal.get('reason')}) — still running "
                                     f"{_run_img}",
                        }
        except Exception as _cv:
            log(f"  Full-mode convergence check skipped ({_cv})", "warning")

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

    # Pre-flight: fail fast on a structurally-broken operator config.yaml
    # BEFORE any extraction/mutation, so a corrupt/incomplete config surfaces
    # as a clear message rather than a cryptic crash mid-apply. Structural
    # only (require_pins=False): the apply side sources sidecar tags from the
    # bundled manifest, not config.yaml, so pin-completeness isn't the failure
    # mode here and a merge/manifest-supplied pin must not false-positive.
    from .config_validate import validate_config, preflight_environment, APPLY_MIN_FREE_GB
    _cfg_ok, _cfg_errs = validate_config(logger=log, require_pins=False)
    _env_ok, _env_errs = preflight_environment(logger=log, min_free_gb=APPLY_MIN_FREE_GB)
    if not (_cfg_ok and _env_ok):
        log("Pre-upgrade validation failed:", "error")
        for _e in _cfg_errs + _env_errs:
            log(f"  - {_e}", "error")
        return {"success": False,
                "error": "pre-upgrade validation failed: " + "; ".join(_cfg_errs + _env_errs)}

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

    # Packages prepared by OLD releases carry legacy module ids in their
    # manifest (e.g. 'cloudtrail') — normalize before matching UPGRADE_ORDER.
    versions = _normalize_legacy_module_keys(manifest.get('versions', {}))

    # Forward-compat guard: a manifest module this installer doesn't know is
    # NEVER iterated by the module loop (it walks UPGRADE_ORDER), so without
    # this line it would be silently skipped — the operator would believe it
    # was applied. Warn loudly instead.
    _unknown_manifest_modules = [m for m in versions if m not in UPGRADE_ORDER]
    if _unknown_manifest_modules:
        log(f"WARNING: package contains module(s) this installer does not "
            f"know and will NOT apply: {', '.join(sorted(_unknown_manifest_modules))}. "
            f"Upgrade 'intact' first (or use a newer installer), then re-apply "
            f"the package for these modules.", "warning")

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
        'aws_sigma': upgrade_aws_offline,
        'o365rc': upgrade_azure_offline,
        'intact': upgrade_intact_offline,
        'volweb': upgrade_volweb_offline,
        'cve_scan': upgrade_cve_offline,
        'portainer': upgrade_portainer_offline,
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
        'portainer':    install_portainer_offline,
        # On-demand modules — same function handles both install and
        # upgrade (the only difference is whether CLOUDTRAIL_VERSION /
        # DFIR_O365RC_VERSION was already pinned). Registering them here
        # lets the install-vs-upgrade dispatcher show "INSTALLING" on
        # fresh deploys and "UPGRADING" on version bumps. _module_container_exists
        # now reads the .env pin for these so the False-vs-True branch
        # actually fires.
        'aws_sigma':       upgrade_aws_offline,
        'o365rc':       upgrade_azure_offline,
    }

    # Container existence detector — reuses _MODULE_PRIMARY_CONTAINERS
    # from base.py. Falls back to True ("module is installed") for
    # modules without a container concept.
    from .base import _module_container_exists

    # Intact.AI must be first so backend code is updated before modules.
    # VolWeb is at the end so its install (a multi-container compose) runs
    # last when the operator is adding VolWeb to an existing install.
    upgrade_order = list(UPGRADE_ORDER)

    results = {}
    total = 0
    completed = 0
    completed_modules = []
    overall_status = "success"
    awaiting_restart = False  # Flag to prevent cleanup when Phase 2 pending
    extract_dir = verify_result.get('extract_dir')

    # Second disk check, now sized from THIS package instead of a fixed floor.
    # The early check ran before extraction, when the real requirement was still
    # unknown; a big package can clear a 10 GiB floor and then die of ENOSPC
    # halfway through `docker load`. Advisory-but-blocking here is the right
    # trade: it fails before the module loop, so nothing is half-applied.
    try:
        from .config_validate import required_free_gb_for_manifest, preflight_environment as _pe
        _pkg_bytes = os.path.getsize(package_path) if (package_path and os.path.exists(package_path)) else 0
        _need = required_free_gb_for_manifest(manifest, _pkg_bytes)
        _ok2, _errs2 = _pe(logger=None, min_free_gb=_need)
        if not _ok2:
            log(f"Insufficient disk for this package (~{_need} GiB needed, "
                f"sized from this package rather than a fixed floor):", "error")
            for _e in _errs2:
                log(f"  - {_e}", "error")
            return {"success": False, "status": "failed",
                    "error": "; ".join(_errs2),
                    "results": {}, "completed": 0, "total": 0, "versions": {}}
        log(f"  Disk preflight: ~{_need} GiB required for this package, satisfied.", "info")
    except Exception as _de:
        log(f"  manifest-sized disk check skipped ({type(_de).__name__}: {_de})", "warning")

    # Build modules dict for state tracking
    modules_dict = {k: v for k, v in versions.items()}
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

    # CVE Scan is versionless, so it's never in the package's `versions:`
    # block — but if the package bundled the prebuilt CVE database, surface
    # it as an applicable module so the dispatch enables cve_scan + installs
    # cves.db on the target. Keyed 'latest' (no version pin). Skipped here
    # when the package carries no CVE data (nothing to install).
    if 'cve_scan' not in modules_dict and os.path.exists(
            os.path.join(package_dir, 'cve', 'cves.db')):
        modules_dict['cve_scan'] = 'latest'

    # Refuse a package that would move any module BACKWARDS. Checked here —
    # after the module set is known, before the loop touches anything — so a
    # rejected run leaves the platform exactly as it was.
    _dg = _reject_downgrades(modules_dict, current_versions, logger=log)
    if _dg:
        log("DOWNGRADE REFUSED — aborting with the platform untouched.", "error")
        log(f"  {_dg}", "error")
        return {"success": False, "status": "failed", "error": _dg,
                "results": {}, "completed": 0, "total": 0, "versions": {}}

    # Apply Uploaded Package can pass an operator-chosen subset. When
    # set, modules in the manifest NOT in this set are skipped and the
    # final summary shows them under "skipped: N". When None, every
    # module in the manifest is applied (legacy behavior — keeps
    # external automation working).
    selected_set = set(selected_modules) if selected_modules else None
    if selected_set is not None:
        log(f"Operator-selected subset: {sorted(selected_set)}", "info")

    # State persisted across the intact restart must carry ONLY the modules the
    # operator selected. The Phase-2 resume (resume_upgrade_workflow) applies
    # state['target_modules'] with NO further selection filter, so persisting the
    # FULL manifest here would make the resume INSTALL every module in the package
    # after the intact restart. That's the bug where a 1-module online-download
    # upgrade (whole package downloaded, `intact` selected) went on to install
    # elk/volweb/timesketch/… on resume. Fall back to the full set only when
    # nothing was explicitly selected (automation / legacy).
    state_modules = ({k: v for k, v in modules_dict.items() if k in selected_set}
                     if selected_set is not None else modules_dict)

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

            # A2: a module that needs nothing done — already installed and
            # neither its primary version nor any sidecar pin changed (intact is
            # handled above and always refreshes).
            #
            # Only AUTO-skip when the caller gave NO explicit module selection
            # (automation / legacy API). When there IS a selection (the operator
            # picked in the online plan or the apply modal, or a track), an
            # unchanged module only reaches here because the operator explicitly
            # TICKED it to force a reinstall — unchanged modules are excluded
            # from the selection by default — so honor that and re-apply it
            # (recovery path for a corrupted/half-broken module at the same
            # version).
            if _upgrade_noop_module(module_name):
                if selected_set is None:
                    log(f"  {module_name.upper()}: already at {version} — no version/sidecar change, skipping", "info")
                    results[module_name] = {"success": True, "skipped": True,
                                            "reason": "already up to date (no change)"}
                    continue
                log(f"  {module_name.upper()}: already at {version}, but you selected it — reinstalling", "info")

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

                    # Surface an honest health verdict (G5): success with a
                    # degraded/down module is visible, never silent. WARNING
                    # level on purpose — an error-level line would auto-flip
                    # the completed run to failed (workflow_service:428).
                    if result.get('health') in ('degraded', 'down'):
                        log(f"MODULE_DEGRADED: {module_name.upper()} — "
                            f"{result.get('health')}: {result.get('health_detail', '')}",
                            "warning")

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
                    from .base import set_module_version_in_config, ensure_module_enabled_in_config
                    yaml_key = 'backend' if module_name == 'intact' else module_name
                    if version and version != 'from_package':
                        try:
                            set_module_version_in_config(yaml_key, version, logger=log)
                        except Exception as e:
                            log(f"  config.yaml version-writeback failed for {module_name}: {e}", "warning")
                    if action_word == 'INSTALLING' and module_name not in ('intact',):
                        try:
                            # CREATE-then-enable: a module the target never
                            # had in config.yaml is both spliced in and set
                            # enabled:true (flip-only used to no-op on it).
                            ensure_module_enabled_in_config(module_name, logger=log)
                        except Exception as e:
                            log(f"  config.yaml enable failed for {module_name}: {e}", "warning")

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
                            # ── Wave F: Full-mode image swap → RECREATE (not restart).
                            # Persist resume state even with NO remaining modules, so
                            # the recreated container's boot runs the Phase-2 finalizer
                            # (records the swap, marks the run complete/failed via the
                            # helper's health marker) rather than leaving it "running".
                            log("", "info"); log(f"{'='*50}", "info")
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

                            # The resume state MUST be persisted before we
                            # restart — a restart without it means Phase 2
                            # silently never runs (remaining modules vanish).
                            _saved = save_upgrade_state(run_id, 'awaiting_restart', state_modules, completed_modules, 'offline',
                                                        extract_dir, package_path, db_overwrite=db_overwrite)
                            if not _saved:
                                log("Retrying resume-state persist...", "warning")
                                _saved = save_upgrade_state(run_id, 'awaiting_restart', state_modules, completed_modules, 'offline',
                                                            extract_dir, package_path, db_overwrite=db_overwrite)
                            if not _saved:
                                log("Could not persist Phase-2 resume state — ABORTING "
                                    "before restart (a restart now would silently drop "
                                    "the remaining modules). Check data/intact.db "
                                    "writability and re-run the upgrade.", "error")
                                return {"success": False,
                                        "error": "failed to persist Phase-2 resume state; "
                                                 "restart aborted"}
                            log("Backend will restart to load new code. Upgrade will resume automatically.", "info")
                            schedule_backend_restart(run_id=run_id, logger=log)

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
                            schedule_backend_restart(logger=log)

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
            # tusd sidecars (<upload>.info / .run) — small, but accumulate
            # forever in the upload_data volume if never reaped.
            for _side in (f"{package_path}.info", f"{package_path}.run"):
                try:
                    if _side and os.path.exists(_side):
                        os.remove(_side)
                except Exception:
                    pass

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

            # Did the platform actually come back? Per-module success does not
            # establish that (see post_upgrade_health_gate's docstring). Purely
            # observational — it can only downgrade the verdict to degraded.
            try:
                _hg = post_upgrade_health_gate(logger=log)
                results["_health"] = _hg
                if not _hg.get("healthy") and overall_status == "success":
                    overall_status = "completed_with_warnings"
            except Exception as _he:
                log(f"  post-upgrade health gate skipped "
                    f"({type(_he).__name__}: {_he})", "warning")

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
                         'velociraptor', 'aws_sigma', 'o365rc', 'volweb']
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

    # Disk preflight for the download + extract (the apply engine re-checks
    # with the same floor once the package is in hand). The old PREPARE floor
    # of 25 GiB was sized for an on-box image build, which no longer happens.
    from .config_validate import preflight_environment, APPLY_MIN_FREE_GB
    _env_ok, _env_errs = preflight_environment(logger=log,
                                               min_free_gb=APPLY_MIN_FREE_GB)
    if not _env_ok:
        for _e in _env_errs:
            log(f"  - {_e}", "error")
        return {"success": False, "status": "failed",
                "error": "environment preflight failed: " + "; ".join(_env_errs),
                "results": {}, "completed": 0, "total": 0, "versions": {}}

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
    'preflight_package',
    'post_upgrade_health_gate',
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
