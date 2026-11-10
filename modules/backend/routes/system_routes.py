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
# Status keys whose config.yaml module id differs. ELK is surfaced through
# its Kibana container, so the status key is 'kibana' while the operator
# enables/disables it as `modules.elk`.
STATUS_KEY_TO_MODULE = {'kibana': 'elk'}

ON_DEMAND_MODULES = ('aws_sigma', 'o365rc')

@system_bp.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"status": "ok", "method": request.method})


@system_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "intact-backend"})


def version_payload(workdir, backend_version) -> dict:
    """The decision itself, with no Flask around it — see tests/test_version_endpoint.py."""
    import os
    version = "unknown"
    try:
        with open(os.path.join(workdir, 'VERSION')) as f:
            version = f.read().strip() or "unknown"
    except Exception:
        pass
    backend = (backend_version or '').strip()
    hybrid = bool(backend) and backend != version
    return {
        "version": version,
        "backend": backend or None,
        "hybrid": hybrid,
        "display": f"{version} (backend {backend})" if hybrid else version,
    }


@system_bp.route('/api/version', methods=['GET'])
def get_intact_version():
    """Which release this is — and which backend is actually running it.

    `version` is the VERSION file at the repo root, stamped by
    .github/workflows/stamp-version-on-release.yml on every release. That is the
    release TREE, and on a box where a backend image has been deployed by hand it
    is not the code executing: VERSION is written by the installer and by nothing
    else, so a dev build reports the release it was dropped onto. The sidebar read
    `intact-20260903` for a box running main, and a support bundle from it said
    the same — which is how a fix that WAS deployed can look like one that was not.

    So `backend` names the running image tag, read from BACKEND_VERSION. Compose
    interpolates the very same variable into `image:`, so it cannot drift from
    what is running the way a stamped file can. `display` is what a human should
    be shown: the release alone when they agree (an ordinary appliance, no noise),
    and both when they do not.

    `version` keeps its exact old meaning — the upgrade dropdown filters releases
    on it and must never see a `main-*` tag.
    """
    import os
    return jsonify(version_payload(os.environ.get('INTACT_PATH', '/app/workdir'),
                                   os.environ.get('BACKEND_VERSION')))

# Public port of each tool: (key in the reply, config.yaml module, key, default).
# Defaults are the compose defaults, so a config.yaml without these keys (every
# box upgraded from before they existed) reports what nginx actually publishes.
SERVICE_PORT_KEYS = (
    ('kibana', 'elk', 'kibana_port', 5602),
    ('portainer', 'portainer', 'port', 9444),
    ('iris', 'iris', 'port', 8444),
    ('timesketch', 'timesketch', 'port', 5443),
    ('volweb', 'volweb', 'port', 8002),
    ('velociraptor_agent', 'velociraptor', 'agent_port', 8000),
)


def service_ports_payload(cfg) -> dict:
    """No Flask here either -- see tests/test_ui_service_ports.py."""
    modules = (cfg or {}).get('modules') or {}
    out = {}
    for key, module, field, default in SERVICE_PORT_KEYS:
        try:
            port = int(((modules.get(module) or {}).get(field)))
        except (TypeError, ValueError):
            port = default
        # A typo in config.yaml must not hand the dashboard a dead link.
        out[key] = port if 0 < port < 65536 else default
    return out


@system_bp.route('/api/system/service-ports', methods=['GET'])
def get_service_ports():
    """The public ports the dashboard tiles open, from config.yaml modules.*."""
    from config import load_main_config
    return jsonify(service_ports_payload(load_main_config()))

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
    # There used to be a block here that flagged which prepare_package run's
    # tarball was still on disk, so the UI could show a working "Package"
    # download button instead of a dead one. Prepare-package was part of the
    # dashboard upgrade flow and went with it -- air-gap packages are built
    # with scripts/prepare_package.sh now, and applied with
    # `sudo bash scripts/upgrade.sh --package`. Historical prepare_package runs stay in
    # the list as history; they simply have no download button.
    return jsonify({"actions": actions})

# --- Network (config.yaml domain + modules.*.port; services/network_settings.py)
@system_bp.route('/api/system/network', methods=['GET'])
def network_get():
    """The domain and each tool's public port as config.yaml has them now."""
    from services import network_settings as ns
    return jsonify(ns.current())


@system_bp.route('/api/system/network', methods=['POST'])
def network_change():
    """Save body {domain (or ip), ports:{kibana, portainer, iris, timesketch, volweb,
    velociraptor_agent}} to config.yaml and apply it with scripts/change_ip.sh
    on the host. 202 {run_id}: the run's log is in Settings -> Actions."""
    from services import network_settings as ns
    body = request.get_json(silent=True) or {}
    try:
        # The popup posts `ip`; `domain` is config.yaml's name for the same value.
        return jsonify(ns.start(body.get('domain') or body.get('ip'), body.get('ports'))), 202
    except ns.Busy as e:
        return jsonify({"error": str(e)}), 409
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500


# --- Data location (config.yaml data_path; services/data_location.py) ---------
@system_bp.route('/api/system/data-location', methods=['GET'])
def data_location_get():
    """Where the data is, the last move's status, and the data disk's usage
    (with the 80% / 90% warning level the dashboard shows)."""
    from services import data_location as dl
    return jsonify(dl.overview())


@system_bp.route('/api/system/data-location/disks', methods=['GET'])
def data_location_disks():
    """Mounted disks the data could move to (the Settings picker)."""
    from services import data_location as dl
    try:
        return jsonify({"disks": dl.disks()})
    except Exception as e:  # noqa: BLE001
        return jsonify({"disks": [], "error": str(e)})


@system_bp.route('/api/system/data-location/check', methods=['POST'])
def data_location_check():
    """Can the data go to body.path ('' = the system disk)? Changes nothing."""
    from services import data_location as dl
    try:
        path = dl.clean_path((request.get_json(silent=True) or {}).get('path'))
    except ValueError as e:
        return jsonify({"ok": False, "reason": str(e)}), 400
    return jsonify(dl.check(path))


@system_bp.route('/api/system/data-location/move', methods=['POST'])
def data_location_move():
    """Move every module's data and data/ to body.path ('' = back to the system
    disk). Every service stops while it copies; body.force goes ahead although
    runs are still going (they are cut off)."""
    from services import data_location as dl
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(dl.start_move(body.get('path'), force=body.get('force') is True)), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/system/data-location/undo', methods=['POST'])
def data_location_undo():
    """Switch back to the backup the last move kept. body.force as for move."""
    from services import data_location as dl
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(dl.start_undo(force=body.get('force') is True)), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/system/data-location/cleanup', methods=['POST'])
def data_location_cleanup():
    """Delete the old copy a finished move kept."""
    from services import data_location as dl
    try:
        return jsonify(dl.start_cleanup()), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500


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

        # `modules.<name>.enabled: false` hides a module EVEN IF its
        # containers are still up. Disabling is a statement of intent, not a
        # description of the host: it does not stop anything, so a module
        # disabled in config.yaml went on reporting 'online' from `docker ps`
        # and kept its sidebar entry and Settings tab. The operator had to
        # tear the stack down as well before the UI agreed with the config —
        # which makes "disable" look like it does nothing.
        #
        # Only ever downgrades to not_installed. is_module_enabled() defaults
        # to True for a module the config does not mention, so a config that
        # predates a module can never hide one that is actually installed.
        try:
            from config import is_module_enabled
            for service_id in list(SERVICE_CONTAINERS):
                # The status key is not always the config module id: ELK is
                # represented by its Kibana container, so `modules.elk` gates a
                # status reported under 'kibana'. Looking up the raw key would
                # ask for a module config.yaml has never heard of, get the
                # default True, and silently leave ELK visible after the
                # operator disabled it.
                module_id = STATUS_KEY_TO_MODULE.get(service_id, service_id)
                if not is_module_enabled(module_id):
                    results[service_id] = 'not_installed'
        except Exception:
            pass          # config unreadable -> leave the docker-derived state

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
