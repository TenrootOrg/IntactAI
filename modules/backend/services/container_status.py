"""Container-availability checks shared across routes.

Centralises the "is this module's container actually up?" lookup so each
automation route doesn't reimplement `docker ps`. Two layers:

1. ``container_running(name)`` — boolean primitive, same shape as the
   private copies that previously lived in ``routes/maintenance_routes.py``
   and ``scripts/run_maintenance.py``. Five-second timeout protects the
   request thread if the docker socket hangs.

2. ``require_velociraptor(workflow)`` — higher-level guard for routes
   that dispatch a Velociraptor hunt before doing their own work
   (Timesketch / Memory automations). Returns ``(error_dict, status)``
   when Velociraptor isn't reachable; returns ``(None, None)`` when the
   container is up. Callers do::

       err, status = require_velociraptor('timesketch')
       if err:
           return jsonify(err), status

The error payload names the specific Velociraptor artifact the workflow
would have collected so operators don't have to guess what's missing.
"""

import subprocess


_VELOCIRAPTOR_CONTAINER = 'intact_velociraptor'

# Maps workflow id -> (human label, Velociraptor artifact full name) for
# the require_velociraptor error message. Keep these in sync with the
# actual artifacts dispatched in services/timesketch_service.py and
# services/memory/acquire.py — the message tells the operator exactly
# which collection won't fire, so a stale name here is worse than no
# message at all.
_VELOCIRAPTOR_WORKFLOWS = {
    'timesketch': (
        'KAPE forensic-timeline collection',
        'Windows.KapeFiles.Targets',
    ),
    'memory': (
        'Memory acquisition',
        'Windows.Memory.Acquisition',
    ),
    'cve_scan': (
        'CVE inventory scan',
        # Primary artifact named; CVE Scan also queries DetectRaptor
        # Applications/LolRMM + Generic.Client.Info but listing four in
        # the error string is noise — operator only needs to know the
        # workflow involves a Velociraptor hunt.
        'Windows.Sys.Programs',
    ),
}


def container_running(name: str) -> bool:
    """Return True iff the named container is currently in running state."""
    try:
        result = subprocess.run(
            [
                'docker', 'ps',
                '--filter', f'name=^{name}$',
                '--filter', 'status=running',
                '--format', '{{.Names}}',
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return False
    return name in {line.strip() for line in result.stdout.splitlines() if line.strip()}


def require_velociraptor(workflow: str):
    """Pre-flight check for routes that dispatch a Velociraptor hunt.

    ``workflow`` is one of the keys in ``_VELOCIRAPTOR_WORKFLOWS``
    ('timesketch' / 'memory'). Returns ``(None, None)`` when Velociraptor
    is reachable, or a ``(error_payload, http_status)`` tuple naming the
    blocked artifact so the operator sees something actionable instead
    of "internal error".
    """
    if container_running(_VELOCIRAPTOR_CONTAINER):
        return None, None

    workflow_label, artifact = _VELOCIRAPTOR_WORKFLOWS.get(
        workflow, ('This automation', 'a Velociraptor artifact')
    )
    return (
        {
            'error': (
                f'Velociraptor is not installed or not running. '
                f'{workflow_label} cannot start because it '
                f'dispatches the `{artifact}` Velociraptor artifact to '
                f'the target endpoint via the Velociraptor server. '
                f'Install or start Velociraptor before re-running this '
                f'automation.'
            ),
            'workflow': workflow,
            'required_artifact': artifact,
            'reason': 'velociraptor_unavailable',
        },
        503,
    )
