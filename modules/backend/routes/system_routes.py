#!/usr/bin/env python3
"""
System Routes - Core system endpoints (health, test)

Other system endpoints have been split into:
- config_routes.py - Configuration endpoints
- maintenance_routes.py - Maintenance and tool management
- upgrade_routes.py - System upgrade endpoints
"""

from flask import Blueprint, jsonify, request

system_bp = Blueprint('system', __name__)


import subprocess

# Service ID to Container Name mapping
SERVICE_CONTAINERS = {
    'velociraptor': 'intact_velociraptor',
    'timesketch': 'intact_timesketch_web',
    'kibana': 'intact_kibana',
    'iris': 'intact_iris_app',
    'portainer': 'intact_portainer',
    # VolWeb in-tree memory-forensics stack — the backend is the
    # representative container (frontend + workers depend on it).
    'volweb': 'intact_volweb_backend',
}

# On-demand modules — no persistent container. Each scan is a one-shot
# `docker run` (o365rc) or runs in-process inside the backend
# (aws native CloudTrail collection). `docker ps -a` returns
# nothing for these, so the install state comes from the operator's
# explicit opt-in in config.yaml (modules.<name>.enabled). Used by the
# sidebar to hide Cloud > AWS / Microsoft 365 / CVE Scan when the
# customer didn't enable them.
ON_DEMAND_MODULES = ('aws_sigma', 'o365rc')

@system_bp.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"status": "ok", "method": request.method})


@system_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "intact-backend"})


@system_bp.route('/api/version', methods=['GET'])
def get_intact_version():
    """Return the current Intact.AI platform version.

    Reads the VERSION file at the repo root — stamped by
    .github/workflows/stamp-version-on-release.yml on every release.
    Mirrors the read logic in services.upgrade.base.get_current_versions
    but kept as a tiny standalone endpoint so the sidebar load doesn't
    pull in the upgrade machinery.
    """
    import os
    workdir = os.environ.get('INTACT_PATH', '/app/workdir')
    version_file = os.path.join(workdir, 'VERSION')
    try:
        with open(version_file) as f:
            version = f.read().strip()
        if version:
            return jsonify({"version": version})
    except Exception:
        pass
    return jsonify({"version": "unknown"})

@system_bp.route('/api/system/actions', methods=['GET'])
def get_system_actions():
    """System/admin run history — the runs tagged to the internal System workspace
    (maintenance, online/prepare/import upgrade, system purge, support bundle,
    settings saves, case import/export). Surfaced in Settings → Actions now that
    System is no longer a selectable case. Read-only; independent of the active
    workspace (does not use the X-Case-Id header)."""
    try:
        from services import workflow_service as ws
        from routes.dashboard_routes import _transform_run
        sid = ws._system_case_id()
        runs = ws.get_automation_runs_by_case(sid) if sid else []
    except Exception as e:
        return jsonify({"actions": [], "error": str(e)}), 200
    # Same shape as /api/dashboard/automations so Settings -> Actions can reuse the
    # Workflows list markup + the shared log modal / per-run download buttons.
    actions = [_transform_run(r) for r in runs
               if r.get("automation_type") not in ("case", "fusion_baseline")]
    # The server keeps only the LATEST prepared package (fixed filename), so an
    # older prepare_package run's tarball is gone once a newer prepare ran. Flag the
    # one run whose package is still on disk so the UI only shows a WORKING
    # "Package" download button instead of a dead one that 410s.
    try:
        import os as _os
        from routes.upgrade_routes import _get_package_info
        pkg = _get_package_info() or {}
        cur = pkg.get("run_id") if _os.path.exists(pkg.get("path", "") or "") else None
        if cur:
            for a in actions:
                if a.get("id") == cur:
                    if not isinstance(a.get("details"), dict):
                        a["details"] = {}
                    a["details"]["package_available"] = True
    except Exception:
        pass
    return jsonify({"actions": actions})

@system_bp.route('/api/system/containers', methods=['GET'])
def get_container_status():
    """Get status of core system containers.

    Returns one of three states per service so the dashboard can
    distinguish a stopped install from a never-installed module:

      - 'online'        — container exists and is running
      - 'stopped'       — container exists but is not running
      - 'not_installed' — container has never been created on this host

    Distinguishing 'stopped' from 'not_installed' lets the dashboard
    count modules that were deployed via online/offline upgrade (which
    creates the container at apply time) separately from modules that
    were never enabled. `docker ps -a` includes stopped containers so a
    single call covers both lifecycle states.

    Legacy callers that only checked for 'online' still work unchanged
    because that value's semantics are preserved.
    """
    results = {}
    try:
        cmd = ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"]
        output = subprocess.check_output(cmd, text=True)
        container_states = {}
        for line in output.strip().split('\n'):
            if '\t' not in line:
                continue
            name, state = line.split('\t', 1)
            container_states[name.strip()] = state.strip()

        for service_id, container_name in SERVICE_CONTAINERS.items():
            state = container_states.get(container_name)
            if state == 'running':
                results[service_id] = 'online'
            elif state is None:
                results[service_id] = 'not_installed'
            else:
                # exited, created, dead, paused, restarting, etc. — the
                # container exists on the host so the module IS installed
                results[service_id] = 'stopped'

        # On-demand modules don't have persistent containers — they're
        # one-shot `docker run` per scan. Treat config.yaml's enabled
        # flag as the install signal. No 'stopped' state for these
        # because there's nothing to be stopped.
        try:
            from config import is_module_enabled
            for module in ON_DEMAND_MODULES:
                if not is_module_enabled(module):
                    results[module] = 'not_installed'
                else:
                    results[module] = 'online'
        except Exception:
            # If config load fails for any reason, conservatively report
            # 'not_installed' so the sidebar doesn't show modules that
            # might not actually work.
            for module in ON_DEMAND_MODULES:
                results.setdefault(module, 'not_installed')

    except Exception as e:
        return jsonify({"error": f"Failed to query Docker: {str(e)}"}), 500

    return jsonify(results)
