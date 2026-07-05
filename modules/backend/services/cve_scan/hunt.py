"""Velociraptor CVE-hunt helpers.

Extracted from routes/cve_routes.py so both the CVE route (POST
/api/cve/scan/run-hunt) and the scheduler (a recurring CVE Management job) can
dispatch the same env-wide hunt without the scheduler importing the Flask routes
package. Pure service functions — no request/Flask dependency.
"""
from __future__ import annotations

from services.workflow_service import add_log_to_run


# Artifact set the cve_management blueprint collects. Re-declared here so the
# hunt works even on installs where the operator has renamed or deleted the YAML
# blueprint — the four canonical artifact names are what the downstream NVD
# pipeline actually consumes.
_CVE_HUNT_ARTIFACTS = [
    'Windows.Sys.Programs',
    'DetectRaptor.Windows.Detection.Applications',
    'DetectRaptor.Windows.Detection.LolRMM',
    'Generic.Client.Info',
]


def _dispatch_cve_hunt(run_id: str, description: str, max_wait_seconds: int = 3600) -> str | None:
    """Create a multi-artifact Velociraptor hunt with the cve_management
    artifact set. Returns the new hunt_id (H.xxx) or None on failure.
    Logs progress to the given workflow row.

    `max_wait_seconds` ties the hunt's `expires` to the operator's
    max-wait window from the UI. Past that point Velociraptor stops
    handing this hunt out to any newly-online client, so the operator
    doesn't end up with a hunt that lingers for hours after the
    auto-scan has already finished.

    Mirrors the bulk-hunt VQL the bestpractice route uses
    (routes/velociraptor_routes.py:217)."""
    import json as _json
    from services.velociraptor_service import setup_velociraptor_connection
    from pyvelociraptor import api_pb2, api_pb2_grpc

    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[CVE] Failed to connect to Velociraptor server", "error")
        return None
    try:
        stub = api_pb2_grpc.APIStub(channel)
        artifacts_list = _json.dumps(_CVE_HUNT_ARTIFACTS)
        spec_parts = ", ".join([f'`{a}`=dict()' for a in _CVE_HUNT_ARTIFACTS])
        # Hunt-side caps. expire_seconds == operator's max_wait so the
        # hunt self-closes when the polling window ends — no orphan
        # hunt picks up brand-new endpoints hours later. Per-client
        # collect timeout stays tight (5min) — these 4 artifacts are
        # registry/WMI lookups that finish in seconds on a healthy host.
        expire_seconds = max(60, int(max_wait_seconds))
        timeout_seconds = min(expire_seconds, 300)
        cpu_limit = 80
        flow_max_rows = 5_000_000
        flow_max_bytes = 10_240 * 1024 * 1024
        # Escape `description` for VQL single-quoted-literal embedding
        # (Mythos #4). Apostrophes legitimately appear in IR data
        # ("O'Brien Q4 sweep") so we can't shape-reject them; instead
        # we apply VQL's standard single-quote escape (double up `'`)
        # and strip control chars. See services/vql_safety.py for the
        # full rationale.
        from services.vql_safety import escape_vql_string
        _safe_description = escape_vql_string(description)
        query = f"""
LET collection = hunt(
    description='{_safe_description}',
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    max_rows={flow_max_rows},
    max_bytes={flow_max_bytes},
    cpu_limit={cpu_limit}
)
SELECT HuntId FROM collection
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=query)],
        )
        hunt_id = None
        for response in stub.Query(request_obj, timeout=120):
            if response.Response:
                try:
                    resp_data = _json.loads(response.Response)
                    if resp_data and len(resp_data) > 0:
                        hunt_id = resp_data[0].get('HuntId')
                        if hunt_id:
                            break
                except Exception:
                    continue
        return hunt_id
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _stop_hunt(run_id: str, hunt_id: str) -> bool:
    """Ask Velociraptor to stop a running hunt — used when the operator's
    max-wait window expires and we'd rather scan the partial results
    than throw them away. Best-effort; the pull path tolerates a hunt
    that's still in any state."""
    from services.velociraptor_service import setup_velociraptor_connection
    from pyvelociraptor import api_pb2, api_pb2_grpc

    channel = setup_velociraptor_connection()
    if not channel:
        return False
    try:
        stub = api_pb2_grpc.APIStub(channel)
        q = f"SELECT * FROM hunt_stop(hunt_id='{hunt_id}')"
        req = api_pb2.VQLCollectorArgs(max_wait=10, max_row=10, Query=[api_pb2.VQLRequest(VQL=q)])
        for _ in stub.Query(req, timeout=20):
            pass
        return True
    except Exception as e:
        add_log_to_run(run_id, f"[CVE] hunt_stop({hunt_id}) failed (continuing anyway): {e}", "warning")
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _wait_for_hunt(run_id: str, hunt_id: str, timeout_seconds: int = 7200, poll_seconds: int = 30) -> bool:
    """Poll Velociraptor until the hunt is no longer RUNNING. Returns
    True on STOPPED/PAUSED, False on timeout. Best-effort; on connection
    failures the polls keep retrying until the timeout."""
    import json as _json
    import time as _time
    from services.velociraptor_service import setup_velociraptor_connection
    from pyvelociraptor import api_pb2, api_pb2_grpc

    from services.workflow_service import is_cancelled as _is_cancelled

    start = _time.time()
    last_state = None
    while _time.time() - start < timeout_seconds:
        # Honour Stop during the 30s polling loop — without this, an
        # operator clicking Stop on a chain-mode CVE scan would still
        # have to wait up to 30s for the next poll tick to notice.
        if _is_cancelled(run_id):
            return False
        try:
            channel = setup_velociraptor_connection()
            if channel:
                try:
                    stub = api_pb2_grpc.APIStub(channel)
                    q = f"SELECT state FROM hunts() WHERE hunt_id='{hunt_id}'"
                    req = api_pb2.VQLCollectorArgs(
                        max_wait=10, max_row=10,
                        Query=[api_pb2.VQLRequest(VQL=q)],
                    )
                    for response in stub.Query(req, timeout=20):
                        if response.Response:
                            try:
                                rows = _json.loads(response.Response)
                                if rows and isinstance(rows, list):
                                    state = (rows[0].get('state') or '').upper()
                                    if state and state != last_state:
                                        add_log_to_run(run_id, f"[CVE] Hunt {hunt_id} state: {state}", "info")
                                        last_state = state
                                    # RUNNING keeps us polling; anything else means done.
                                    if state and state != 'RUNNING':
                                        return True
                            except Exception:
                                pass
                finally:
                    try:
                        channel.close()
                    except Exception:
                        pass
        except Exception as e:
            add_log_to_run(run_id, f"[CVE] Hunt poll error (will retry): {e}", "warning")
        _time.sleep(poll_seconds)
    add_log_to_run(run_id, f"[CVE] Hunt {hunt_id} did not finish within {timeout_seconds}s — leaving it running. "
                           f"Once it's done, use the 'Use existing hunt' tab to pull results.", "warning")
    return False
