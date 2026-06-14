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
)

# Module-specific upgrade functions
from .elk import upgrade_elk, upgrade_elk_offline
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


def _read_current_intact_version() -> str:
    """Read the on-disk intact VERSION (the running backend's release)."""
    try:
        with open(os.path.join(WORKDIR, 'VERSION'), 'r') as f:
            return f.read().strip()
    except Exception:
        return ''


def _intact_bootstrap_needed(modules: Dict[str, str]) -> bool:
    """True iff intact is being upgraded to a DIFFERENT version than what's
    running. When True, the orchestrator should apply intact + restart
    BEFORE preparing the rest of the modules — so the prepare runs with
    the new backend's code (new version pins, new artifact-bundling logic).
    Avoids the "old code prepares with old pins" bootstrap bug.
    """
    if 'intact' not in modules:
        return False
    target = str(modules.get('intact') or '').strip()
    if not target:
        return False
    current = _read_current_intact_version()
    return target != current


def _bootstrap_intact_and_restart(modules: Dict[str, str], run_id: str,
                                   logger: Callable,
                                   mode: str,
                                   db_overwrite: Optional[Dict] = None) -> Dict:
    """Phase 1 of every intact-bumping workflow.

    Downloads JUST the new intact source (small — ~2 MB), applies it,
    saves resume state, and triggers a backend restart. After the restart
    `resume_upgrade_workflow` picks up via the saved `mode` and runs the
    remainder (`online_bootstrap` → prepare+apply remaining modules;
    `prepare_bootstrap` → prepare+compress remaining modules into a
    downloadable tar.gz).

    This is what unblocks: prepare in Phase 2 runs with the NEW backend
    code, so version pins/artifact-bundling fixes that ship in the new
    intact take effect on the same upgrade that delivers them.
    """
    from datetime import datetime as _dt
    from .package import prepare_upgrade_package
    from .intact import upgrade_intact_offline

    log = logger
    log("=" * 50, "info")
    log("PHASE 1 - BOOTSTRAPPING INTACT BACKEND", "info")
    log("=" * 50, "info")
    log("(Downloading new intact source so Phase 2 runs the new code)", "info")

    intact_version = str(modules['intact']).strip()
    current_version = _read_current_intact_version() or 'unknown'
    log(f"  Current: {current_version}  →  Target: {intact_version}", "info")

    # Build a small intact-only package under the persistent /app/data/tmp
    # path (survives the backend restart, unlike /tmp).
    os.makedirs("/app/data/tmp", exist_ok=True)
    bootstrap_dir = (f"/app/data/tmp/intact-bootstrap-"
                     f"{_dt.now().strftime('%Y%m%d_%H%M%S')}")

    log(f"PHASE 1a - Fetching intact source @ {intact_version}", "info")
    prep = prepare_upgrade_package(
        modules={'intact': intact_version},
        run_id=run_id,
        logger=log,
        compress=False,
        work_dir=bootstrap_dir,
    )
    if not prep.get('success'):
        return {
            "success": False,
            "error": f"Bootstrap fetch failed: {prep.get('error', 'unknown')}",
            "results": {},
        }

    boot_pkg_dir = prep['package_dir']

    log("PHASE 1b - Applying intact source (replacing backend code)", "info")
    apply_res = upgrade_intact_offline(
        boot_pkg_dir, intact_version, logger=log, run_id=run_id,
    )
    if not apply_res.get('success'):
        return {
            "success": False,
            "error": f"Intact apply failed: {apply_res.get('error', 'unknown')}",
            "results": {},
        }

    # Also bump versions.backend in config.yaml so the post-restart code's
    # "is this a bump?" detector agrees (without this, resume would re-
    # detect the bump and loop forever).
    try:
        from .base import set_module_version_in_config
        set_module_version_in_config('backend', intact_version, logger=log)
    except Exception as e:
        log(f"  config.yaml backend version-writeback failed: {e}", "warning")

    # Save resume state. `mode` distinguishes online (prepare+apply remaining)
    # from prepare (prepare+compress remaining). `completed_modules=['intact']`
    # tells the Phase 2 apply loop to skip intact (it already ran).
    save_upgrade_state(
        run_id, 'awaiting_restart',
        modules, ['intact'], mode,
        package_dir=None, package_path=None,
        db_overwrite=db_overwrite,
    )

    log("PHASE 1c - Restarting backend (Phase 2 will resume automatically)",
        "info")
    schedule_backend_restart()

    return {
        "success": True,
        "phase": "awaiting_restart",
        "status": "awaiting_restart",
        "message": (f"Phase 1 complete (intact bootstrapped {current_version} "
                    f"→ {intact_version}). Backend restarting; Phase 2 will "
                    f"resume automatically."),
        "results": {"intact": {"success": True, "version": intact_version}},
    }


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

                    # Special handling for Intact.AI - trigger Phase 2
                    if module_name == 'intact' and run_id:
                        # Check if there are more modules to upgrade
                        remaining = [m for m in upgrade_order if m in modules and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume (include db_overwrite)
                            save_upgrade_state(run_id, 'awaiting_restart', modules, completed_modules, mode,
                                               db_overwrite=db_overwrite)

                            # Schedule backend restart (nginx will restart at Phase 2 start)
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

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"

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

    all_success = all(r.get('success', False) for r in results.values() if not isinstance(r, str))
    return {
        "success": all_success,
        "status": overall_status,
        "results": results,
        "completed": completed,
        "total": total
    }


def _resume_after_intact_bootstrap(run_id: str,
                                    modules: Dict[str, str],
                                    completed_modules: set,
                                    mode: str,
                                    db_overwrite: Dict,
                                    log: Callable) -> Dict:
    """Phase 2 for `mode in (online_bootstrap, prepare_bootstrap)`.

    This code runs under the NEW backend (intact was applied + restarted
    in Phase 1). Re-runs prepare for the remaining modules using the
    NEW code's pins + bundling logic, then either applies them
    (online_bootstrap) or compresses to a downloadable tar.gz
    (prepare_bootstrap).

    Why this exists: without the bootstrap+re-prepare, the original
    Phase 1 prepare ran under the OLD backend code and the operator
    got a package built against the OLD version pins/artifact logic
    even on the upgrade that was supposed to deliver the new ones.
    """
    from datetime import datetime as _dt
    from .package import prepare_upgrade_package

    log("", "info")
    log(f"{'='*50}", "info")
    log("PHASE 2 (bootstrap mode) - REPREPARE WITH NEW CODE", "info")
    log(f"{'='*50}", "info")
    log(f"  Mode: {mode}", "info")
    log(f"  Modules already done: {sorted(completed_modules) or ['(none)']}",
        "info")

    restart_nginx(log)
    update_upgrade_phase(run_id, 'phase2')

    # Skip intact (already applied in Phase 1) — prepare only the rest.
    modules_minus_intact = {k: v for k, v in modules.items()
                            if k not in completed_modules}
    if not modules_minus_intact:
        log("No remaining modules after intact bootstrap — clearing state.",
            "info")
        clear_upgrade_state(run_id)
        return {
            "success": True,
            "status": "success",
            "message": "Intact bootstrapped; no other modules selected.",
            "results": {"intact": {"success": True}},
        }

    log(f"  Remaining: {', '.join(modules_minus_intact.keys())}", "info")
    log("", "info")
    log("PHASE 2a - Preparing remaining modules with NEW backend code",
        "info")

    # Persistent work dir under /app/data/tmp so the path survives any
    # future restart and the apply step can find the package_dir.
    persistent_work_dir = (f"/app/data/tmp/intact-upgrade-"
                           f"{_dt.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs("/app/data/tmp", exist_ok=True)

    # online_bootstrap leaves the package_dir raw (apply consumes it
    # directly); prepare_bootstrap compresses into a tar.gz that the
    # operator downloads.
    compress = (mode == 'prepare_bootstrap')

    prep = prepare_upgrade_package(
        modules=modules_minus_intact,
        run_id=run_id,
        logger=log,
        compress=compress,
        work_dir=persistent_work_dir,
    )
    if not prep.get('success'):
        clear_upgrade_state(run_id)
        return {
            "success": False,
            "status": "failed",
            "error": (f"Phase 2 prepare failed: "
                      f"{prep.get('error', 'unknown')}"),
            "results": {},
        }

    if mode == 'online_bootstrap':
        # Phase 2b — hand off to the existing offline-apply orchestrator
        # with prebuilt package_dir + manifest. The orchestrator's
        # per-module loop runs intact LAST in upgrade_order, so by saving
        # state that already marks intact as completed we just need to
        # make sure intact isn't re-run. The offline workflow checks
        # `completed_modules` via `get_upgrade_state` only for Phase 1/2
        # resume — but here we pass the FULL `modules_minus_intact` dict
        # via `prebuilt_manifest['versions']`, and since intact isn't in
        # that dict the loop skips it cleanly.
        log("", "info")
        log("PHASE 2b - Applying remaining modules", "info")
        result = run_offline_upgrade_workflow(
            package_path=None,
            run_id=run_id,
            logger=log,
            db_overwrite=db_overwrite,
            prebuilt_package_dir=prep['package_dir'],
            prebuilt_manifest=prep['manifest'],
            workflow_label="ONLINE UPGRADE (Phase 2b: apply remaining)",
        )
        # Mark our state cleared either way (offline workflow may save
        # its own state on the rare second restart path).
        if result.get('success'):
            clear_upgrade_state(run_id)
        return result

    # mode == 'prepare_bootstrap' — compress is True so prep already
    # produced a tar.gz. Register it as the latest prepared package so
    # the Downloads endpoint exposes it.
    _save_prepared_package_info({
        'run_id': run_id,
        'path': prep['package_path'],
        'name': prep['package_name'],
        'size': prep['package_size'],
        'created_at': _dt.now().timestamp(),
    })
    log("", "info")
    log("PHASE 2 complete — package ready for download.", "success")
    log(f"  {prep['package_name']} ({prep['package_size']/(1024*1024):.1f} MB)",
        "info")
    clear_upgrade_state(run_id)
    return {
        "success": True,
        "status": "success",
        "message": "Prepare-package bootstrap complete.",
        "package_path": prep['package_path'],
        "package_name": prep['package_name'],
        "package_size": prep['package_size'],
        "results": {"intact": {"success": True}},
    }


def _save_prepared_package_info(info: Dict) -> None:
    """Write the prepared-package metadata so /api/upgrade/list-packages
    surfaces it. Mirrors `_save_package_info` in routes/upgrade_routes.py;
    duplicated here to avoid importing the route module from the service
    layer (the route imports this service, so the reverse would be a
    cycle)."""
    PACKAGE_INFO_FILE = "/data/db/prepared_package.json"
    try:
        os.makedirs(os.path.dirname(PACKAGE_INFO_FILE), exist_ok=True)
        with open(PACKAGE_INFO_FILE, 'w') as f:
            json.dump(info, f, indent=2)
    except Exception as e:
        print(f"[WARN] _save_prepared_package_info failed: {e}", flush=True)


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

    # Bootstrap modes (online_bootstrap, prepare_bootstrap): Phase 1 only
    # applied intact + restarted; the heavy prepare still has to run, but
    # now under the NEW backend code. Dispatch to the bootstrap-resume
    # path which (re)builds the package for the remaining modules and
    # then either applies them (online) or compresses them (prepare).
    if mode in ('online_bootstrap', 'prepare_bootstrap'):
        return _resume_after_intact_bootstrap(
            run_id, modules, completed_modules, mode, db_overwrite, log,
        )

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

    upgrade_order = ['intact', 'elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'prowler', 'o365rc']

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

            try:
                if module_name == 'intact':
                    result = upgrade_fn(logger=log)
                else:
                    result = upgrade_fn(target_version, logger=log)

                results[module_name] = result

                if result.get('success'):
                    completed_modules.add(module_name)
                    log(f"{module_name.upper()} upgrade completed: {current} -> {target_version}", "success")

                    # Recreate Timesketch user after fresh install
                    if module_name == 'timesketch' and db_overwrite.get('timesketch', False):
                        recreate_timesketch_user(logger=log)

                    update_upgrade_phase(run_id, 'phase2', list(completed_modules))
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"

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

    # Save initial state if we have a run_id (include package_path for cleanup after Phase 2)
    extract_dir = verify_result.get('extract_dir')
    if run_id:
        save_upgrade_state(run_id, 'phase1', modules_dict, [], 'offline', extract_dir, package_path,
                           db_overwrite=db_overwrite)

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

                    # Special handling for Intact.AI - trigger Phase 2
                    if module_name == 'intact' and run_id and not result.get('skipped'):
                        remaining = [m for m in upgrade_order if m in modules_dict and m not in completed_modules]
                        if remaining:
                            log("", "info")
                            log(f"{'='*50}", "info")
                            log("PHASE 1 COMPLETE - Intact.AI upgraded", "info")
                            log(f"Remaining modules for Phase 2: {', '.join(remaining)}", "info")
                            log(f"{'='*50}", "info")

                            # Save state for Phase 2 resume (include package_path for cleanup)
                            save_upgrade_state(run_id, 'awaiting_restart', modules_dict, completed_modules, 'offline',
                                               extract_dir, package_path, db_overwrite=db_overwrite)

                            # Schedule backend restart (nginx will restart at Phase 2 start)
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

                    # Update state after each module
                    if run_id:
                        update_upgrade_phase(run_id, 'phase1', completed_modules)
                else:
                    log(f"MODULE_FAILED: {module_name.upper()} — {result.get('error', 'unknown')}", "error")
                    log(f"  Continuing with remaining modules; this failure does not stop the run.", "info")
                    overall_status = "completed_with_errors"

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

    # Bootstrap-first when intact is being bumped. This ensures the
    # heavy prepare step in Phase 2 runs with the NEW backend code —
    # so version pins (e.g. opensearch floor) + artifact-bundling
    # fixes that ship in the new intact actually take effect on the
    # upgrade that delivers them. Skipped when target intact ==
    # current (no code change → no chicken-and-egg risk).
    if _intact_bootstrap_needed(modules):
        return _bootstrap_intact_and_restart(
            modules, run_id, log,
            mode='online_bootstrap',
            db_overwrite=db_overwrite,
        )

    from services.upgrade.package import prepare_upgrade_package

    # Build directly into /app/data/tmp/ — the persistent host-mounted
    # path. /tmp/ would break Phase 2 because intact's backend restart
    # between Phase 1 and Phase 2 wipes the container's /tmp.
    from datetime import datetime as _dt
    package_name = f"intact-upgrade-{_dt.now().strftime('%Y%m%d_%H%M%S')}"
    persistent_work_dir = f"/app/data/tmp/{package_name}"
    os.makedirs("/app/data/tmp", exist_ok=True)

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
