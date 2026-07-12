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
from .intact import upgrade_intact, upgrade_intact_offline
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


# Single source of truth for module upgrade order. Intact (the backend) MUST be
# first so backend code is updated before the modules it drives. This list was
# previously duplicated in three functions (run/resume/offline); a 2026-06-16
# drift incident — a module present in one copy but missing from another — is
# why it now lives in exactly one place, referenced everywhere.
UPGRADE_ORDER = ['intact', 'elk', 'timesketch', 'plaso', 'iris',
                 'velociraptor', 'cloudtrail', 'o365rc', 'volweb', 'cve_scan']


def _upgrade_noop_module(module_name: str) -> bool:
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
        return False
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


def schedule_backend_restart():
    """Schedule backend restart after short delay using detached process."""
    subprocess.Popen(
        ['sh', '-c', 'sleep 3 && docker restart intact_backend intact_tusd'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )


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
        'cloudtrail': upgrade_aws,
        'o365rc': upgrade_azure,
        'volweb': upgrade_volweb,
        'intact': upgrade_intact,
        'cve_scan': upgrade_cve,
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
            # always refreshes (see _upgrade_noop_module).
            if _upgrade_noop_module(module_name):
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
            'cloudtrail': lambda v, **kw: upgrade_aws_offline(package_dir, v, **kw),
            'o365rc': lambda v, **kw: upgrade_azure_offline(package_dir, v, **kw),
            'volweb': lambda v, **kw: upgrade_volweb_offline(package_dir, v, **kw),
            'intact': lambda **kw: upgrade_intact_offline(package_dir, **kw),
            'cve_scan': lambda v, **kw: upgrade_cve_offline(package_dir, v, **kw),
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
            # always refreshes (see _upgrade_noop_module).
            if _upgrade_noop_module(module_name):
                log(f"  {module_name.upper()}: already at {target_version} — no version/sidecar change, skipping", "info")
                results[module_name] = {"success": True, "skipped": True,
                                        "reason": "already up to date (no change)"}
                continue

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

            # One module finished (success OR failure) — advance the bar.
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

    versions = manifest.get('versions', {})

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
        'cloudtrail': upgrade_aws_offline,
        'o365rc': upgrade_azure_offline,
        'intact': upgrade_intact_offline,
        'volweb': upgrade_volweb_offline,
        'cve_scan': upgrade_cve_offline,
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
        # upgrade (the only difference is whether CLOUDTRAIL_VERSION /
        # DFIR_O365RC_VERSION was already pinned). Registering them here
        # lets the install-vs-upgrade dispatcher show "INSTALLING" on
        # fresh deploys and "UPGRADING" on version bumps. _module_container_exists
        # now reads the .env pin for these so the False-vs-True branch
        # actually fires.
        'cloudtrail':      upgrade_aws_offline,
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

    # Save initial state if we have a run_id (include package_path for cleanup after Phase 2)
    extract_dir = verify_result.get('extract_dir')
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules_dict, [], 'offline', extract_dir, package_path,
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

            # A2: skip a module that needs nothing done — already installed and
            # neither its primary version nor any sidecar pin changed. intact is
            # handled above and always refreshes; absent modules still install
            # per the operator's package selection (see _upgrade_noop_module).
            if _upgrade_noop_module(module_name):
                log(f"  {module_name.upper()}: already at {version} — no version/sidecar change, skipping", "info")
                results[module_name] = {"success": True, "skipped": True,
                                        "reason": "already up to date (no change)"}
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
                        if remaining:
                            # In-run Phase 2: save state, restart, resume after boot.
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            save_upgrade_state(run_id, 'awaiting_restart', modules_dict, completed_modules, 'offline',
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
                         'velociraptor', 'cloudtrail', 'o365rc', 'volweb']
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

    from services.upgrade.package import prepare_upgrade_package

    # Build directly into /app/data/tmp/ — the persistent host-mounted
    # path. /tmp/ would break Phase 2 because intact's backend restart
    # between Phase 1 and Phase 2 wipes the container's /tmp.
    from datetime import datetime as _dt
    package_name = f"intact-upgrade-{_dt.now().strftime('%Y%m%d_%H%M%S')}"
    persistent_work_dir = f"/app/data/tmp/{package_name}"
    os.makedirs("/app/data/tmp", exist_ok=True)

    # Pre-prepare config.yaml merge: fetch the target intact ref's
    # config.yaml from GitHub and merge its `versions:` block into the
    # operator's local config.yaml BEFORE the prepare step reads it.
    # Without this, prepare reads the operator's STALE versions:
    # block — an operator on test-1 (timesketch_opensearch: 2.11.0)
    # who triggers an upgrade to test-2 (which ships 2.19.5) would
    # otherwise bundle opensearch:2.11.0 because the prepare side
    # reads config.yaml BEFORE the apply-side intact-step's merge
    # has run. Operator hit this 2026-06-15. Skipped when intact
    # isn't in the modules dict.
    intact_ref = modules.get('intact')
    if intact_ref:
        try:
            from services.upgrade.resolver import fetch_upstream_config
            from services.upgrade.intact import merge_versions_from_new_config
            import tempfile, yaml as _yaml
            log(f"Fetching target config.yaml from intact @ {intact_ref} "
                f"for pre-prepare versions: merge...", "info")
            target_cfg = fetch_upstream_config(intact_ref, user_action='submit')
            # Write the dict to a temp file so the text-level merge
            # helper can read it (it operates on file paths, not dicts,
            # to keep the merge logic uniform between online + offline
            # flows). Dump preserves the source structure well enough
            # for the helper's regex extractors.
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.yaml', delete=False) as tmp:
                _yaml.safe_dump(target_cfg, tmp, sort_keys=False,
                                default_flow_style=False)
                tmp_path = tmp.name
            operator_config = os.path.join(WORKDIR, 'config.yaml')
            merge_result = merge_versions_from_new_config(
                tmp_path, operator_config, logger=log,
            )
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            if merge_result.get('success'):
                upd = merge_result.get('updated') or {}
                add = merge_result.get('added') or {}
                if upd or add:
                    log(f"Pre-prepare config.yaml merge: "
                        f"{len(upd)} updated, {len(add)} added — "
                        f"prepare will now read the new versions",
                        "success")
                else:
                    log(f"Pre-prepare config.yaml merge: already up-to-date",
                        "info")
        except Exception as e:
            log(f"Pre-prepare config.yaml merge failed "
                f"({type(e).__name__}: {e}); prepare will use the "
                f"operator's existing versions — pins may be stale",
                "warning")

    # Pre-flight: now that the target's version pins are merged into the
    # operator's config.yaml (pre-prepare merge above), validate it fully —
    # including primary + sidecar pin completeness — BEFORE prepare reads it.
    # This pre-empts the operator-facing get_transitive_tag KeyError
    # (package.py) that prepare would otherwise raise mid-run. require_pins=True
    # is safe here: any pin the merge would supply is already present.
    # Environment preflight uses the PREPARE floor: this flow pulls + saves
    # multi-GB images before applying.
    from .config_validate import validate_config, preflight_environment, PREPARE_MIN_FREE_GB
    _cfg_ok, _cfg_errs = validate_config(logger=log, require_pins=True)
    _env_ok, _env_errs = preflight_environment(logger=log, min_free_gb=PREPARE_MIN_FREE_GB)
    _cfg_errs = _cfg_errs + _env_errs
    if not (_cfg_ok and _env_ok):
        log("Pre-prepare validation failed:", "error")
        for _e in _cfg_errs:
            log(f"  - {_e}", "error")
        if os.path.exists(persistent_work_dir):
            try:
                shutil.rmtree(persistent_work_dir)
            except Exception:
                pass
        return {
            "success": False,
            "status": "failed",
            "error": "config.yaml validation failed: " + "; ".join(_cfg_errs),
            "results": {},
            "completed": 0,
            "total": 0,
            "versions": {},
        }

    prepare_result = prepare_upgrade_package(
        modules=modules,
        run_id=run_id,
        logger=log,
        compress=False,
        work_dir=persistent_work_dir,
    )

    if not prepare_result.get('success'):
        if os.path.exists(persistent_work_dir):
            try:
                shutil.rmtree(persistent_work_dir)
            except Exception:
                pass
        return {
            "success": False,
            "status": "failed",
            "error": prepare_result.get('error', 'Prepare step failed'),
            "results": {},
            "completed": 0,
            "total": 0,
            "versions": {},
        }

    package_dir = prepare_result['package_dir']
    manifest = prepare_result['manifest']

    log("", "info")
    log("=" * 50, "info")
    log("HAND-OFF TO APPLY (no compression step)", "success")
    log("=" * 50, "info")
    log("", "info")

    return run_offline_upgrade_workflow(
        package_path=None,
        run_id=run_id,
        logger=log,
        db_overwrite=db_overwrite,
        prebuilt_package_dir=package_dir,
        prebuilt_manifest=manifest,
        workflow_label="ONLINE UPGRADE WORKFLOW (Phase 2 of 2: apply)",
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
