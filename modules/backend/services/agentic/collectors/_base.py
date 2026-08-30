#!/usr/bin/env python3
"""
Agentic Collectors - Velociraptor artifact collection logic
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection
from services.workflow_service import add_log_to_run
from services.vql_safety import is_valid_client_id, is_valid_flow_id, is_valid_hunt_id


def _is_valid_hunt_or_derived_flow_id(value: str) -> bool:
    """True for a real hunt id (H.xxx) OR the hunt-derived flow-id shape
    (F.xxx.H) that get_existing_collection_results also accepts and
    normalizes into an H.xxx id before querying hunt_flows()."""
    if is_valid_hunt_id(value):
        return True
    if value.startswith('F.') and value.endswith('.H') and len(value) > 4:
        return is_valid_hunt_id('H.' + value[2:-2])
    return False

logger = logging.getLogger(__name__)


# Note: a blueprint may still bake its own `settings['time_filter']` default
# (used by calculate_time_range() below to build per-artifact DateAfter/
# DateBefore VQL for artifacts like Hayabusa). There is no runtime/per-request
# time filter anymore — collection is otherwise unbounded and unfiltered;
# Case Analysis (fusion) owns all time-window and severity filtering.

# Maximum rows fetched per artifact result query. Replaces a hard-coded
# 5000-row VQL LIMIT that was silently truncating any artifact whose
# source produced more rows — wrong analysis, no warning. The new
# ceiling is generous (200K rows fits ~99% of real hunts inside ~200MB
# memory) but still finite, and the loader logs a clear warning if a
# real hunt hits it. Override via env if a deployment routinely runs
# bigger hunts.
VELO_MAX_ROWS_PER_ARTIFACT = int(os.environ.get("VELO_MAX_ROWS_PER_ARTIFACT", "200000"))
VELO_QUERY_TIMEOUT_SECONDS = int(os.environ.get("VELO_QUERY_TIMEOUT_SECONDS", "300"))


def _distinct_artifacts(sources):
    """Artifact NAMES from a list of Velociraptor result SOURCES.

    `artifacts_with_results` names sources, not artifacts: one
    Generic.Forensic.SQLiteHunter collection contributes a dozen entries
    ("…/AllFiles", "…/Chromium Browser Cookies_Cookies", …). Counting that list
    as "artifacts completed" produced the warning QA reported —

        21 artifact(s) did not complete (…). 21/31 succeeded - pipeline continues.

    — where the first 21 counts artifact names and the second counts sources.
    They collided by coincidence, made the line read as a contradiction, and hid
    that only 10 of 31 artifacts had produced anything at all.
    """
    return set(str(a).split('/')[0] for a in (sources or []))


def check_flow_status(stub, client_id, flow_id):
    """Check the status of a Velociraptor flow.

    Returns tuple: (status, error_info)
        - status: 'RUNNING', 'FINISHED', 'ERROR', or None
        - error_info: dict with backtrace/context if ERROR, else None
    """
    try:
        # Use get_flow() VQL function (same as kape_service)
        query = f"LET flow <= get_flow(client_id='{client_id}', flow_id='{flow_id}') SELECT * FROM flow"
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=10,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )
        for response in stub.Query(request_obj, timeout=15):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    if resp_data and len(resp_data) > 0:
                        row = resp_data[0]
                        # Try both 'state' and 'State' field names
                        state = row.get('state') or row.get('State', '')
                        # Velociraptor flow states (case-insensitive check)
                        state_upper = str(state).upper()
                        if state_upper == 'FINISHED':
                            return 'FINISHED', None
                        elif state_upper in ('ERROR', 'CANCELLED', 'FAILED'):
                            # Extract error info for logging
                            backtrace = row.get('backtrace', '')
                            context = row.get('context', {})
                            artifacts_done = row.get('artifacts_with_results', [])
                            artifacts_requested = row.get('request', {}).get('artifacts', [])

                            # Find which artifact(s) failed. `artifacts_done` is
                            # a list of SOURCES — one artifact with twelve
                            # sub-sources appears twelve times — so it is
                            # collapsed to artifact names before either count is
                            # taken. See _distinct_artifacts.
                            done_set = _distinct_artifacts(artifacts_done)
                            failed_artifacts = []
                            if artifacts_requested and artifacts_done:
                                failed_artifacts = [a for a in artifacts_requested if a not in done_set]

                            # Try to extract error reason from backtrace
                            error_reason = None
                            if backtrace:
                                # Look for common error patterns
                                lines = backtrace.split('\n')
                                for line in lines:
                                    if 'error' in line.lower() or 'timeout' in line.lower():
                                        error_reason = line.strip()[:100]
                                        break

                            error_info = {
                                'backtrace': backtrace[:500] if backtrace else None,
                                'context': context,
                                'artifacts_completed': len(done_set),
                                'artifacts_requested': len(artifacts_requested) if artifacts_requested else 0,
                                'failed_artifacts': failed_artifacts,
                                'error_reason': error_reason
                            }
                            return 'ERROR', error_info
                        elif state_upper in ('RUNNING', 'IN_PROGRESS', 'WAITING'):
                            return 'RUNNING', None
                except Exception as e:
                    print(f"[AGENTIC] Flow status parse error: {e}", flush=True)
    except Exception as e:
        print(f"[AGENTIC] Flow status query error: {e}", flush=True)
    return None, None


def calculate_time_range(time_filter_settings):
    """Calculate start/end timestamps based on time filter settings.

    Supports two modes:
    - 'relative': Uses relative_range like '24h', '7d', '30d', '90d'
    - 'between': Uses explicit start_datetime and end_datetime (ISO 8601)

    Returns (start_iso, end_iso) tuple or (None, None) if not enabled.
    """
    if not time_filter_settings or not time_filter_settings.get('enabled'):
        return None, None

    mode = time_filter_settings.get('mode', 'relative')
    now = datetime.utcnow()

    if mode == 'between':
        # User-provided absolute dates
        start_iso = time_filter_settings.get('start_datetime')
        end_iso = time_filter_settings.get('end_datetime')

        # Default end to now if not provided
        if not end_iso:
            end_iso = now.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Normalize format (remove timezone suffix variations, ensure Z suffix)
        if start_iso:
            start_iso = start_iso.replace('+00:00', 'Z')
            if not start_iso.endswith('Z'):
                start_iso = start_iso + 'Z'
        if end_iso:
            end_iso = end_iso.replace('+00:00', 'Z')
            if not end_iso.endswith('Z'):
                end_iso = end_iso + 'Z'

        print(f"[AGENTIC] Time filter (between): {start_iso} to {end_iso}", flush=True)
        return start_iso, end_iso

    # Relative mode (default)
    # Support both 'relative_range' (new API) and 'default_range' (legacy)
    range_str = time_filter_settings.get('relative_range') or time_filter_settings.get('default_range', '7d')
    end_time = now

    # Parse range string (e.g., "24h", "7d", "30d", "90d")
    if range_str.endswith('h'):
        hours = int(range_str[:-1])
        start_time = now - timedelta(hours=hours)
    elif range_str.endswith('d'):
        days = int(range_str[:-1])
        start_time = now - timedelta(days=days)
    else:
        # Default to 7 days
        start_time = now - timedelta(days=7)

    # Format as ISO 8601 (Velociraptor format)
    start_iso = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_iso = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    print(f"[AGENTIC] Time filter (relative {range_str}): {start_iso} to {end_iso}", flush=True)
    return start_iso, end_iso


# Artifacts that accept VQL time-bound params — pushing the incident window into
# collection cuts row VOLUME at the source (e.g. Hayabusa parses fewer event-log
# entries), which is the biggest token/cost lever for the heaviest artifact. Add a
# one-line entry to extend; the post-collection Python time filter stays authoritative.
ARTIFACT_TIME_PARAMS = {
    "Windows.Hayabusa.Rules": {"date_after": "DateAfter", "date_before": "DateBefore",
                               "rule_level": "RuleLevel"},
}
_SEV_TO_RULELEVEL = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def _vql_quote(v) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def build_artifact_spec(artifacts, settings=None):
    """Build the per-artifact VQL spec string. Time-bound params (Hayabusa DateAfter/
    DateBefore + RuleLevel) are AUTO-DERIVED from the run's time_filter + min_severity for
    allow-listed artifacts; everything else stays `=dict()`. The post-collection Python
    filter (filter_results_by_time) still runs and is authoritative — these params only
    pre-trim volume. Operators can override via settings['artifact_params'][artifact]."""
    settings = settings or {}
    start_iso, end_iso = calculate_time_range(settings.get('time_filter'))
    min_sev = (settings.get('min_severity') or 'informational')
    overrides = settings.get('artifact_params') or {}
    parts = []
    for artifact in artifacts:
        params = {}
        spec = ARTIFACT_TIME_PARAMS.get(artifact)
        if spec:
            if start_iso and 'date_after' in spec:
                params[spec['date_after']] = start_iso
            if end_iso and 'date_before' in spec:
                params[spec['date_before']] = end_iso
            if 'rule_level' in spec and min_sev in _SEV_TO_RULELEVEL:
                params[spec['rule_level']] = _SEV_TO_RULELEVEL[min_sev]
        params.update(overrides.get(artifact) or {})        # operator escape-hatch wins
        if params:
            kv = ", ".join(f"{k}='{_vql_quote(v)}'" for k, v in params.items())
            parts.append(f'`{artifact}`=dict({kv})')
        else:
            parts.append(f'`{artifact}`=dict()')
    return ", ".join(parts)


def get_client_hostnames(stub, client_ids):
    """Get hostname mapping for a list of client IDs."""
    hostnames = {}
    # Defense-in-depth, same rule as get_existing_collection_results below:
    # these IDs are joined into a VQL string literal with no escaping, so one
    # quote breaks out of the IN (...) list. The scheduler's PUT route is
    # validated now, but a job POISONED BEFORE THAT FIX is still on disk and
    # will fire on its next tick — the route guard cannot reach it, this can.
    client_ids = [c for c in (client_ids or []) if is_valid_client_id(c)]
    if not client_ids:
        return hostnames
    try:
        # Query client info for all clients
        client_list = "', '".join(client_ids)
        query = f"""
SELECT client_id, os_info.hostname as Hostname
FROM clients()
WHERE client_id IN ('{client_list}')
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )
        for response in stub.Query(request_obj, timeout=30):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    for row in resp_data:
                        cid = row.get('client_id')
                        hostname = row.get('Hostname') or cid
                        if cid:
                            hostnames[cid] = hostname
                except Exception:
                    pass
    except Exception:
        pass
    return hostnames


def get_client_os(stub, client_ids):
    """Map client_id -> normalized OS ('windows'/'linux'/'darwin') from the
    server's enrollment record. Used to drop wrong-OS artifacts before tasking a
    client: a Windows-only artifact on a Linux endpoint logs hard VQL errors (and a
    broad Generic scanner crawls that endpoint's filesystem). Best-effort — clients
    we can't resolve are left out of the map and treated as 'unknown' by callers."""
    os_map = {}
    # Same VQL-literal join as get_client_hostnames — validate before building it.
    client_ids = [c for c in (client_ids or []) if is_valid_client_id(c)]
    if not client_ids:
        return os_map
    try:
        client_list = "', '".join(client_ids)
        query = f"""
SELECT client_id, os_info.system AS OS
FROM clients()
WHERE client_id IN ('{client_list}')
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )
        for response in stub.Query(request_obj, timeout=30):
            if response.Response:
                try:
                    for row in json.loads(response.Response):
                        cid = row.get('client_id')
                        osv = (row.get('OS') or '').strip().lower()
                        if cid and osv:
                            os_map[cid] = osv
                except Exception:
                    pass
    except Exception:
        pass
    return os_map


def resolve_hostnames(client_ids):
    """Public wrapper around get_client_hostnames() that handles its own
    gRPC connection. Designed for callers that don't have a stub in
    scope yet — e.g. routes building the workflow name BEFORE the
    pipeline thread starts.

    Returns: dict[client_id -> hostname]. Falls back to client_id on
    error or when the hostname isn't known, so callers can always do
    `names = [out.get(cid, cid) for cid in client_ids]`."""
    if not client_ids:
        return {}
    channel = None
    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return {cid: cid for cid in client_ids}
        stub = api_pb2_grpc.APIStub(channel)
        hostnames = get_client_hostnames(stub, client_ids)
    except Exception:
        hostnames = {}
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
    # Backfill any missing entries with the client_id so callers always
    # get one string per requested client.
    return {cid: hostnames.get(cid, cid) for cid in client_ids}


def create_collections(run_id, artifacts, settings, client_ids):
    """Create a collection on each selected client with all artifacts bundled.
    Returns list of {client_id, flow_id, hostname}."""
    # Defense-in-depth before ANY query runs: each id is interpolated into
    # `client_id='{client_id}'` below with no escaping. Reject loudly rather
    # than filtering silently — reaching here with a bad id means a job was
    # persisted before the scheduler's PUT route was validated, and the
    # operator needs to see which job to fix.
    bad = [c for c in (client_ids or []) if not is_valid_client_id(c)]
    if bad:
        add_log_to_run(run_id,
                       f"[Velociraptor] Rejecting invalid client_ids: {bad!r}", "error")
        return []

    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[Velociraptor] Failed to connect to server", "error")
        return []

    stub = api_pb2_grpc.APIStub(channel)
    timeout_seconds = settings.get('timeout', 3600)
    cpu_limit = settings.get('cpu_limit', 50)
    # Flow-level resource limits — without these the agentic per-client
    # collection inherits Velociraptor's daemon defaults (1 GiB upload, 1M rows)
    # and can be cancelled mid-flow on a real KAPE-class collection. Defaults
    # match the conservative ceilings shipped in default_blueprints.yaml.
    flow_max_rows      = settings.get('flow_max_rows', 10000000)
    flow_max_upload_mb = settings.get('flow_max_upload_mb', 51200)
    flow_max_bytes     = int(flow_max_upload_mb) * 1024 * 1024
    # `flow_max_logs` is in the blueprint for forward-compat but the current
    # Velociraptor `collect_client` rejects it ("Unexpected arg max_logs"),
    # so we deliberately don't pass it into the VQL.
    _ = settings.get('flow_max_logs', 1000000)

    # Get hostname + OS mapping for all clients. The OS map lets us drop wrong-OS
    # artifacts per client before tasking it (see artifacts_for_os): Windows-only
    # VQL on a Linux endpoint throws hard errors, and a broad Generic scanner would
    # crawl that live endpoint's filesystem.
    client_hostnames = get_client_hostnames(stub, client_ids)
    client_os = get_client_os(stub, client_ids)
    from services.offline_collector.constants import artifacts_for_os

    # Multi-client: make parallelism visible. The for-loop below just
    # submits gRPC create_collection requests (each returns in ms with a
    # flow_id); Velociraptor then runs the flows on the endpoints in
    # parallel. The previous logging made it look serial — fix that
    # without restructuring the loop.
    n_clients = len(client_ids)
    if n_clients > 1:
        names_for_log = [client_hostnames.get(cid, cid) for cid in client_ids]
        # "show up to 3 names then + N-3 more" — same rule as workflow name.
        if n_clients <= 3:
            names_str = ", ".join(names_for_log)
        else:
            names_str = ", ".join(names_for_log[:3]) + f" + {n_clients - 3} more"
        add_log_to_run(
            run_id,
            f"[Velociraptor] Launching {n_clients} collections in parallel: {names_str}",
            "info",
        )

    # Build spec with time filtering if enabled
    time_filter = settings.get('time_filter', {})
    if time_filter.get('enabled'):
        start_time, _ = calculate_time_range(time_filter)
        add_log_to_run(run_id, f"[Velociraptor] Time filter enabled: collecting data since {start_time}", "info")

    results = []
    for i, client_id in enumerate(client_ids):
        hostname = client_hostnames.get(client_id, client_id)
        try:
            # Per-client OS-aware artifact selection. For a Windows client (or an
            # unknown OS) the list is unchanged; for a Linux/macOS client we drop
            # Windows-only + heavy filesystem-scanning artifacts so the flow runs
            # clean instead of erroring and crawling the endpoint.
            target_os = client_os.get(client_id)
            if target_os in ('linux', 'darwin'):
                client_artifacts = artifacts_for_os(target_os, artifacts)
                dropped = [a for a in artifacts if a not in client_artifacts]
                if dropped:
                    add_log_to_run(
                        run_id,
                        f"[Velociraptor] {hostname} is {target_os}: removed "
                        f"{len(dropped)} wrong-OS artifact(s) before tasking "
                        f"(Windows-only VQL / accessors). Dropped: "
                        f"{', '.join(dropped[:8])}{' …' if len(dropped) > 8 else ''}",
                        "warning",
                    )
            else:
                client_artifacts = artifacts
            artifacts_list = json.dumps(client_artifacts)
            spec_str = build_artifact_spec(client_artifacts, settings)
            query = f"""
LET collection = collect_client(
    client_id='{client_id}',
    artifacts={artifacts_list},
    spec=dict({spec_str}),
    timeout={timeout_seconds},
    cpu_limit={cpu_limit},
    max_rows={flow_max_rows},
    max_bytes={flow_max_bytes}
)
SELECT * FROM collection
"""
            request_obj = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=100,
                Query=[api_pb2.VQLRequest(VQL=query)]
            )

            flow_id = None
            for response in stub.Query(request_obj, timeout=60):
                if response.Response:
                    try:
                        resp_data = json.loads(response.Response)
                        if resp_data and len(resp_data) > 0:
                            flow_id = resp_data[0].get('FlowId') or resp_data[0].get('flow_id')
                    except Exception:
                        pass

            if flow_id:
                add_log_to_run(run_id, f"[Velociraptor] [{i+1}/{len(client_ids)}] Collection started on {hostname} ({client_id}): {flow_id}", "info")
            else:
                add_log_to_run(run_id, f"[Velociraptor] [{i+1}/{len(client_ids)}] Failed to start collection on {hostname}", "warning")

            results.append({"client_id": client_id, "flow_id": flow_id, "hostname": hostname})

        except Exception as e:
            add_log_to_run(run_id, f"[Velociraptor] [{i+1}/{len(client_ids)}] Error on {client_id}: {str(e)}", "error")
            results.append({"client_id": client_id, "flow_id": None})

    channel.close()
    return results


def enumerate_flow_sources(stub, client_id, flow_id):
    """Enumerate all available artifact sources in a flow. Returns list of source names."""
    try:
        # Use enumerate_flow() to get all available sources
        query = f"""
SELECT * FROM enumerate_flow(client_id='{client_id}', flow_id='{flow_id}')
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )
        sources = []
        for response in stub.Query(request_obj, timeout=30):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    if isinstance(resp_data, list):
                        for row in resp_data:
                            # enumerate_flow returns Type="Result" rows with Data.VFSPath containing artifact name
                            # VFSPath formats:
                            # - artifacts/{artifact_name}/{flow_id}.json (main artifact)
                            # - artifacts/{artifact_name}/{flow_id}/{sub_source}.json (sub-source)
                            if row.get('Type') == 'Result':
                                vfs_path = row.get('Data', {}).get('VFSPath', '')
                                if '/artifacts/' in vfs_path:
                                    # Extract artifact name from path
                                    parts = vfs_path.split('/artifacts/')
                                    if len(parts) > 1:
                                        artifact_part = parts[1]
                                        # Parse path components
                                        path_parts = artifact_part.split('/')
                                        if len(path_parts) >= 2:
                                            artifact_name = path_parts[0]
                                            # Check for sub-source (path_parts[1] is flow_id, path_parts[2] would be sub-source)
                                            if len(path_parts) >= 3 and path_parts[2].endswith('.json'):
                                                sub_source = path_parts[2].replace('.json', '')
                                                artifact_name = f"{artifact_name}/{sub_source}"
                                            if artifact_name and artifact_name not in sources:
                                                sources.append(artifact_name)
                except Exception:
                    pass
        return sources
    except Exception as e:
        print(f"[AGENTIC] Error enumerating flow sources: {e}", flush=True)
        return []


def query_artifact_results(stub, client_id, flow_id, artifact, start_iso=None,
                           end_iso=None, start_row=0):
    """Query for available results from a specific artifact with optional VQL time filtering.

    Args:
        stub: gRPC stub
        client_id: Velociraptor client ID
        flow_id: Flow ID to query
        artifact: Artifact name (may include /source suffix)
        start_iso: Optional start time (ISO 8601) for VQL filtering
        end_iso: Optional end time (ISO 8601) for VQL filtering
        start_row: Skip this many rows server-side and return only what follows.

            THIS IS WHAT KEEPS A LONG COLLECTION FROM STRANGLING ITSELF. The
            poll loop used to re-download every source in full every 30 seconds,
            so each poll got slower as the data grew and the loop's own clock
            fell behind the wall clock — measured at 3x on a QA appliance, which
            pushed a 10-minute collection past its 25-minute watchdog and lost
            all 465,000 rows.

            Velociraptor's source() takes start_row, and the difference is not
            marginal. Measured against a real 354,831-row Windows.NTFS.MFT:

                full fetch                 354,831 rows   46.8s
                start_row=350000             4,831 rows    0.6s

            Same rows, 78x faster, and exact rather than sampled.

    Returns:
        List of rows or empty list
    """
    try:
        # No VQL LIMIT — the previous 5000-row cap silently truncated big
        # hunts and produced "complete" reports based on partial data.
        # gRPC streams responses in chunks; we cap server-side via
        # VELO_MAX_ROWS_PER_ARTIFACT and warn loudly on overflow.
        # Time filtering is still done client-side post-fetch.
        # start_row is an int we control (a count of rows we already hold), not
        # operator input, but it is formatted as one anyway so a malformed value
        # can never reach VQL.
        _offset = max(0, int(start_row or 0))
        query = (
            f"SELECT * FROM source("
            f"client_id='{client_id}', "
            f"flow_id='{flow_id}', "
            f"artifact='{artifact}'"
            + (f", start_row={_offset}" if _offset else "")
            + ")"
        )
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=VELO_MAX_ROWS_PER_ARTIFACT,
            Query=[api_pb2.VQLRequest(VQL=query)],
        )
        rows = []
        truncated = False
        for response in stub.Query(request_obj, timeout=VELO_QUERY_TIMEOUT_SECONDS):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    if isinstance(resp_data, list):
                        rows.extend(resp_data)
                        if len(rows) >= VELO_MAX_ROWS_PER_ARTIFACT:
                            truncated = True
                            break
                except Exception:
                    pass
        if truncated:
            logger.warning(
                "[Velociraptor] %s/%s rows hit ceiling (%d) — analysis on "
                "partial data; raise VELO_MAX_ROWS_PER_ARTIFACT to capture more",
                artifact, flow_id, VELO_MAX_ROWS_PER_ARTIFACT,
            )
        return rows
    except Exception:
        return []


def cancel_collections(run_id, collection_results):
    """Cancel running collections after time limit"""
    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[Velociraptor] Could not connect to cancel collections", "warning")
        return

    stub = api_pb2_grpc.APIStub(channel)

    cancelled = 0
    for col in collection_results:
        client_id = col.get('client_id')
        flow_id = col.get('flow_id')
        if not flow_id:
            continue
        try:
            query = f"SELECT cancel_flow(client_id='{client_id}', flow_id='{flow_id}') FROM scope()"
            request_obj = api_pb2.VQLCollectorArgs(
                max_wait=10,
                max_row=10,
                Query=[api_pb2.VQLRequest(VQL=query)]
            )
            for _ in stub.Query(request_obj, timeout=15):
                pass
            cancelled += 1
        except Exception as e:
            add_log_to_run(run_id, f"[Velociraptor] Could not cancel {flow_id} on {client_id}: {str(e)}", "warning")

    channel.close()
    add_log_to_run(run_id, f"[Velociraptor] Cancelled {cancelled} collection(s)", "info")


def _wanted_source(source_name, only_artifacts):
    """Should this result source be fetched at all?

    `only_artifacts` is a set of lowercase BASE artifact names. A source may be a
    sub-source ("Generic.Forensic.SQLiteHunter/AllFiles") or carry an export
    prefix ("All Windows.NTFS.MFT"), so it is normalized the same way the fusion
    allowlist normalizes its keys.
    """
    if not only_artifacts:
        return True
    n = str(source_name or "")
    if n[:4].lower() == "all ":
        n = n[4:]
    return n.split("/")[0].strip().lower() in only_artifacts


def get_existing_collection_results(run_id, flow_id=None, hunt_id=None, time_filter=None,
                                    client_ids=None, only_artifacts=None,
                                    progress_log=False):
    """Fetch results from an existing Velociraptor flow or hunt with optional time filtering.

    Args:
        run_id: Workflow run ID for logging
        flow_id: Flow ID (F.xxx) for single client collection
        hunt_id: Hunt ID (H.xxx OR F.xxx.H) for multi-client hunt
        time_filter: Optional time filter config for VQL-level filtering
        only_artifacts: Optional set of lowercase base artifact names. Sources
            outside it are never queried.

            FUSION PASSES ITS ALLOWLIST HERE, and the numbers are the argument.
            Measured on a real BestPractice collection: 38 sources, 713,520 rows
            fetched, of which fusion keeps 8 sources and 322 rows — 99.95%
            transferred over gRPC, held in memory and discarded. Two artifacts
            account for almost all of it (Windows.NTFS.MFT 354,831 and
            Windows.Forensics.Usn 353,367) and fusion supports neither.

            This is a fetch filter, not a policy change: those artifacts are
            still collected, still stored, still downloadable. Fusion simply
            stops asking for rows it is about to throw away.
        progress_log: Log a line per source as it lands.

            Off for fusion, which fetches quietly inside a fuse that has its own
            progress. On for the operator-facing "Fetch results", where the fetch
            IS the operation: a hunt keeps collecting after its window closes, so
            an operator re-fetches it repeatedly, and a button that prints one
            line and then goes silent for two minutes is indistinguishable from
            one that did nothing.
        client_ids: Optional list of Velociraptor client IDs to scope a hunt
            to. When non-empty, the hunt-flows enumeration query gets a
            ``WHERE ClientId IN (...)`` filter so only those clients' rows
            reach analysis. Ignored on the single-flow path.

    Returns:
        (all_results, artifacts, client_info)
        - all_results: dict of artifact_name -> [rows]
        - artifacts: list of artifact names found
        - client_info: dict of client_id -> {hostname, os, etc.}
    """
    all_results = {}
    artifacts = []
    client_info = {}

    # Defense-in-depth: flow_id/hunt_id/client_ids are interpolated directly
    # into VQL string literals throughout this function with no escaping.
    # This is reachable from an operator-supplied POST body (e.g.
    # a flow-id-driven fetch), so reject anything
    # that isn't shaped like a real Velociraptor id before any query runs.
    if hunt_id and not _is_valid_hunt_or_derived_flow_id(hunt_id):
        add_log_to_run(run_id, f"[Velociraptor] Rejecting invalid hunt_id: {hunt_id!r}", "error")
        return all_results, artifacts, client_info
    if client_ids:
        bad = [c for c in client_ids if not is_valid_client_id(c)]
        if bad:
            add_log_to_run(run_id, f"[Velociraptor] Rejecting invalid client_ids: {bad!r}", "error")
            return all_results, artifacts, client_info

    # Calculate time range (used for post-processing filter, not VQL)
    start_iso, end_iso = calculate_time_range(time_filter)

    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[Velociraptor] Could not establish connection", "error")
        return all_results, artifacts, client_info

    stub = api_pb2_grpc.APIStub(channel)

    try:
        # ---- Normalize flow_id to a list ---------------------------------
        # Accept three shapes from upstream callers:
        #   - None / "" / []             → empty (hunt path or no-op)
        #   - "F.xxx"                    → single-flow legacy path
        #   - ["F.A", "F.B"]             → multi-flow (new)
        #   - "F.A, F.B"                 → multi-flow string (UI back-compat)
        flow_ids = []
        if not hunt_id:
            if isinstance(flow_id, list):
                flow_ids = [str(f).strip() for f in flow_id if str(f).strip()]
            elif isinstance(flow_id, str) and flow_id.strip():
                flow_ids = [f.strip() for f in flow_id.split(',') if f.strip()]

        bad_flow_ids = [f for f in flow_ids if not is_valid_flow_id(f)]
        if bad_flow_ids:
            add_log_to_run(run_id, f"[Velociraptor] Rejecting invalid flow_id(s): {bad_flow_ids!r}", "error")
            return all_results, artifacts, client_info

        if flow_ids:
            # Pretty log for one-vs-many cases
            if len(flow_ids) == 1:
                add_log_to_run(run_id, f"[Velociraptor] Fetching results from flow: {flow_ids[0]}", "info")
            else:
                add_log_to_run(
                    run_id,
                    f"[Velociraptor] Fetching results from {len(flow_ids)} flows ({', '.join(flow_ids)})",
                    "info",
                )

            # Enumerate all clients ONCE (per-flow location lookup reuses this)
            clients_query = "SELECT client_id, os_info.hostname AS hostname FROM clients()"
            request_obj = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=1000,
                Query=[api_pb2.VQLRequest(VQL=clients_query)]
            )
            all_clients = []
            for response in stub.Query(request_obj, timeout=60):
                if response.Response:
                    try:
                        resp_data = json.loads(response.Response)
                        all_clients.extend(resp_data)
                    except Exception as e:
                        add_log_to_run(run_id, f"[Velociraptor] Error parsing clients response: {e}", "warning")
                if response.log:
                    add_log_to_run(run_id, f"[Velociraptor] Server log: {response.log}", "debug")
            add_log_to_run(run_id, f"[Velociraptor] Found {len(all_clients)} clients to search", "info")

            # ---- Per-flow loop (mirrors the hunt-flows loop further down) ---
            for fid in flow_ids:
                located_client_id = None
                located_hostname = "Unknown"

                # Search each client for this flow
                for client in all_clients:
                    cid = client.get('client_id')
                    if not cid:
                        continue

                    flow_check_query = f"SELECT session_id FROM flows(client_id='{cid}', flow_id='{fid}')"
                    check_req = api_pb2.VQLCollectorArgs(
                        max_wait=10,
                        max_row=1,
                        Query=[api_pb2.VQLRequest(VQL=flow_check_query)]
                    )
                    try:
                        for response in stub.Query(check_req, timeout=30):
                            if response.log:
                                add_log_to_run(run_id, f"[Velociraptor] Query log for {cid}: {response.log.strip()}", "debug")
                            if response.Response:
                                try:
                                    resp_data = json.loads(response.Response)
                                    add_log_to_run(run_id, f"[Velociraptor] Query result for {cid}: {len(resp_data)} rows", "debug")
                                    if resp_data and len(resp_data) > 0:
                                        located_client_id = cid
                                        located_hostname = client.get('hostname', 'Unknown')
                                        add_log_to_run(
                                            run_id,
                                            f"[Velociraptor] Found flow {fid} on client: {cid} ({located_hostname})",
                                            "info",
                                        )
                                        break
                                except Exception as e:
                                    add_log_to_run(run_id, f"[Velociraptor] Error parsing flow check for {cid}: {e}", "warning")
                    except Exception as e:
                        add_log_to_run(run_id, f"[Velociraptor] Error querying client {cid}: {e}", "warning")
                        continue
                    if located_client_id:
                        break

                # Fallback: check server flows
                if not located_client_id:
                    flow_info_query = f"SELECT client_id FROM flows(client_id='server', flow_id='{fid}')"
                    info_req = api_pb2.VQLCollectorArgs(
                        max_wait=30,
                        max_row=1,
                        Query=[api_pb2.VQLRequest(VQL=flow_info_query)]
                    )
                    for response in stub.Query(info_req, timeout=60):
                        if response.Response:
                            try:
                                resp_data = json.loads(response.Response)
                                if resp_data and len(resp_data) > 0:
                                    located_client_id = 'server'
                                    located_hostname = 'Server'
                                    add_log_to_run(run_id, f"[Velociraptor] Found server flow: {fid}", "info")
                            except Exception:
                                pass

                if not located_client_id:
                    # Don't abort the whole run — log the missing flow and
                    # continue with whatever flows we CAN find. Matches the
                    # hunt path's "skip empty flow" tolerance.
                    add_log_to_run(
                        run_id,
                        f"[Velociraptor] Flow {fid} not found on any of {len(all_clients)} clients or server",
                        "warning",
                    )
                    continue

                # List available sources in this flow
                sources_query = f"SELECT artifacts_with_results FROM flows(client_id='{located_client_id}', flow_id='{fid}')"
                sources_req = api_pb2.VQLCollectorArgs(
                    max_wait=30,
                    max_row=10,
                    Query=[api_pb2.VQLRequest(VQL=sources_query)]
                )

                flow_sources = []
                for response in stub.Query(sources_req, timeout=60):
                    if response.Response:
                        try:
                            resp_data = json.loads(response.Response)
                            if resp_data and len(resp_data) > 0:
                                artifacts_list = resp_data[0].get('artifacts_with_results', [])
                                if artifacts_list:
                                    flow_sources = artifacts_list
                                    add_log_to_run(run_id, f"[Velociraptor] Artifacts in flow {fid}: {artifacts_list}", "debug")
                        except Exception as e:
                            add_log_to_run(run_id, f"[Velociraptor] Error getting artifacts list: {e}", "warning")

                add_log_to_run(
                    run_id,
                    f"[Velociraptor] Flow {fid} has {len(flow_sources)} artifact source(s)",
                    "info",
                )

                # Pull rows for each artifact source, tag with client context
                # so per-client report filters and IRIS asset linking work.
                #
                # SECOND FETCH LOOP. The single-flow path inlines its VQL rather
                # than calling query_artifact_results, so a grep for that helper
                # does not find it — which is exactly how the first version of
                # the only_artifacts filter got applied to the hunt loop alone
                # and changed nothing for collections (measured: still 38
                # sources, 713,520 rows). Both loops honour it.
                _skipped = [x for x in flow_sources if not _wanted_source(x, only_artifacts)]
                if _skipped:
                    add_log_to_run(run_id, f"[Velociraptor] Skipping {len(_skipped)} source(s) "
                                           f"this consumer does not use", "info")
                _n_want = sum(1 for x in flow_sources if _wanted_source(x, only_artifacts))
                _done = 0
                for source in flow_sources:
                    if not _wanted_source(source, only_artifacts):
                        continue
                    query = f"SELECT * FROM source(client_id='{located_client_id}', flow_id='{fid}', artifact='{source}')"
                    src_req = api_pb2.VQLCollectorArgs(
                        max_wait=60,
                        max_row=50000,
                        Query=[api_pb2.VQLRequest(VQL=query)]
                    )

                    rows = []
                    for response in stub.Query(src_req, timeout=120):
                        if response.Response:
                            try:
                                resp_data = json.loads(response.Response)
                                rows.extend(resp_data)
                            except Exception:
                                pass

                    _done += 1
                    if progress_log:
                        add_log_to_run(
                            run_id,
                            f"[Fetch] {located_hostname}: {_done}/{_n_want} "
                            f"{source} — {len(rows or []):,} row(s)",
                            "info")
                    if not rows:
                        continue

                    # Tag every row with `_client_id` + `_hostname` — the
                    # multi-client merge logic in collectors/_stream.py relies
                    # on these to keep each client's rows distinct instead of
                    # one client's poll overwriting another's for the same
                    # artifact.
                    for r in rows:
                        r.setdefault('_client_id', located_client_id)
                        r.setdefault('_hostname', located_hostname)

                    # Append (not overwrite): multiple flows can contribute
                    # rows to the same artifact name (e.g. each client's
                    # copy of Generic.Client.Info/DetailedInfo).
                    all_results.setdefault(source, []).extend(rows)
                    if source not in artifacts:
                        artifacts.append(source)
                    add_log_to_run(
                        run_id,
                        f"[Velociraptor] Retrieved {len(rows)} rows from {source} (flow {fid})",
                        "info",
                    )

                # Track which client each flow came from. Multi-flow runs
                # populate one entry per distinct client; single-flow runs
                # produce exactly one entry (preserves the legacy output).
                if located_client_id not in client_info:
                    client_info[located_client_id] = {
                        "client_id": located_client_id,
                        "hostname": located_hostname,
                        "os": "Unknown",
                    }

        elif hunt_id:
            # Get results from a hunt (multiple clients)
            add_log_to_run(run_id, f"[Velociraptor] Fetching results from hunt: {hunt_id}", "info")

            # Velociraptor's hunt_flows() VQL plugin only accepts the actual
            # hunt ID (`H.<base>`); it returns nothing if you pass it the
            # hunt-DERIVED flow ID (`F.<base>.H`). Normalize here so an
            # operator pasting either format works. Examples:
            #   F.D7OB0S115JUTS.H  →  H.D7OB0S115JUTS
            #   H.D7OB0S115JUTS    →  H.D7OB0S115JUTS  (no change)
            velo_hunt_id = hunt_id
            if hunt_id.startswith('F.') and hunt_id.endswith('.H') and len(hunt_id) > 4:
                velo_hunt_id = 'H.' + hunt_id[2:-2]
                add_log_to_run(
                    run_id,
                    f"[Velociraptor] Hunt-derived flow ID detected — querying as {velo_hunt_id}",
                    "info",
                )

            # First, get all flows in this hunt using hunt_flows().
            # If the analyst picked specific clients, push a WHERE filter
            # into VQL so we never enumerate flows for clients we'll just
            # discard later — saves both bandwidth and analysis cost.
            if client_ids:
                # Velociraptor client IDs are alphanumerics + dot ('C.ABC123');
                # still single-quote each one to keep the f-string safe.
                quoted = ", ".join(f"'{cid}'" for cid in client_ids)
                flows_query = (
                    f"SELECT ClientId, FlowId FROM hunt_flows(hunt_id='{velo_hunt_id}') "
                    f"WHERE ClientId IN ({quoted})"
                )
                add_log_to_run(
                    run_id,
                    f"[Velociraptor] Hunt scoped to {len(client_ids)} selected client(s)",
                    "info",
                )
            else:
                flows_query = f"SELECT ClientId, FlowId FROM hunt_flows(hunt_id='{velo_hunt_id}')"
            request_obj = api_pb2.VQLCollectorArgs(
                max_wait=60,
                max_row=1000,
                Query=[api_pb2.VQLRequest(VQL=flows_query)]
            )

            hunt_flows = []
            for response in stub.Query(request_obj, timeout=120):
                if response.Response:
                    try:
                        resp_data = json.loads(response.Response)
                        hunt_flows.extend(resp_data)
                    except Exception as e:
                        add_log_to_run(run_id, f"[Velociraptor] Error parsing hunt flows: {e}", "warning")

            add_log_to_run(run_id, f"[Velociraptor] Found {len(hunt_flows)} flows in hunt", "info")

            # Offline-collector imports produce flows whose IDs happen to
            # end in `.H` (e.g. `F.D87HII4KI3BOO.H`), but they are *not*
            # hunt-derived — there's no underlying `H.xxx` hunt. The
            # block above converts `F.xxx.H` → `H.xxx` and queries
            # hunt_flows(), which legitimately returns 0 for these.
            # Detect that empty result and fall through to the flow-id
            # path (which searches every client for the flow). Closing
            # the channel first to avoid leaking — the recursive call
            # opens a fresh one.
            if not hunt_flows and hunt_id.startswith('F.') and hunt_id.endswith('.H'):
                add_log_to_run(
                    run_id,
                    f"[Velociraptor] '{hunt_id}' returned no hunt flows — retrying as a single-flow ID "
                    f"(common for offline-collector imports).",
                    "info",
                )
                try:
                    channel.close()
                except Exception:
                    pass
                return get_existing_collection_results(
                    run_id=run_id,
                    flow_id=hunt_id,
                    hunt_id=None,
                    time_filter=time_filter,
                    client_ids=client_ids,
                )

            # Resolve hostnames up-front for every client that contributed
            # a flow to this hunt. Without this, downstream consumers (CVE
            # Scan, per-client report filters, IRIS asset linking) see
            # `_hostname` = "Unknown" or missing and the final CSV ends up
            # with `(unknown)` in the HostName column.
            unique_hunt_client_ids = sorted({fi.get('ClientId') for fi in hunt_flows if fi.get('ClientId')})
            hunt_hostnames = get_client_hostnames(stub, unique_hunt_client_ids) if unique_hunt_client_ids else {}

            # Now fetch results from each flow
            for flow_info in hunt_flows:
                flow_client_id = flow_info.get('ClientId')
                flow_id = flow_info.get('FlowId')
                if not flow_client_id or not flow_id:
                    continue
                resolved_hostname = hunt_hostnames.get(flow_client_id, flow_client_id)

                # Get available sources in this flow
                sources = enumerate_flow_sources(stub, flow_client_id, flow_id)
                add_log_to_run(run_id, f"[Velociraptor] Flow {flow_id} has {len(sources)} sources", "info")

                # Track client info (with the real hostname this time).
                if flow_client_id not in client_info:
                    client_info[flow_client_id] = {
                        "client_id": flow_client_id,
                        "hostname": resolved_hostname,
                        "os": "Unknown"
                    }
                else:
                    # Backfill hostname on a pre-existing entry that may
                    # have been created with "Unknown" by earlier code.
                    if client_info[flow_client_id].get("hostname") in (None, "", "Unknown"):
                        client_info[flow_client_id]["hostname"] = resolved_hostname

                # Fetch results from each source with VQL time filtering
                _skipped = [x for x in sources if not _wanted_source(x, only_artifacts)]
                if _skipped:
                    add_log_to_run(run_id, f"[Velociraptor] Skipping {len(_skipped)} source(s) "
                                           f"this consumer does not use", "info")
                _n_want = sum(1 for x in sources if _wanted_source(x, only_artifacts))
                _done = 0
                for source_name in sources:
                    if not _wanted_source(source_name, only_artifacts):
                        continue
                    rows = query_artifact_results(stub, flow_client_id, flow_id, source_name, start_iso, end_iso)
                    _done += 1
                    if progress_log:
                        add_log_to_run(
                            run_id,
                            f"[Fetch] {resolved_hostname}: {_done}/{_n_want} "
                            f"{source_name} — {len(rows or []):,} row(s)",
                            "info")
                    if rows:
                        if source_name not in artifacts:
                            artifacts.append(source_name)
                        if source_name not in all_results:
                            all_results[source_name] = []
                        # Tag every row with client_id AND hostname — see
                        # the matching flow-id path at line 1253 for the
                        # reasoning (per-client report filter, IRIS, CVE
                        # Scan's HostName resolution all depend on this).
                        for row in rows:
                            row['_client_id'] = flow_client_id
                            row.setdefault('_hostname', resolved_hostname)
                        all_results[source_name].extend(rows)
                        add_log_to_run(run_id, f"[Velociraptor] Retrieved {len(rows)} rows from {source_name}", "info")

            add_log_to_run(run_id, f"[Velociraptor] Hunt contained {len(artifacts)} artifacts from {len(client_info)} clients", "info")

    except Exception as e:
        add_log_to_run(run_id, f"[Velociraptor] Error fetching existing results: {str(e)}", "error")

    finally:
        channel.close()

    return all_results, artifacts, client_info


def persist_pipeline_artifacts(run_id, all_results, *, fusion_only=False):
    """Save the raw row data for the fusion layer.

    Case Analysis (fusion) reads `raw_results.json` to build the cross-module
    / cross-host case graph — this is the bridge from a collection run into
    the case.

    File written to /data/downloads/<run_id>/raw_results.json:
    dict[artifact_name -> [row, ...]]

    `fusion_only=True` writes ONLY the artifacts fusion can actually ingest.
    Measured across this appliance's stored payloads: 581 MB of 1,158 MB — half
    the evidence store — is artifacts SUPPORTED_ARTIFACTS excludes and always
    will. Two runs were 100% waste: a 403 MB Windows.NTFS.MFT dump (354,831
    rows) and a 172 MB run that is almost entirely NTFS.MFT + Forensics.Usn.
    Those map to zero entities even when admitted. Not writing them halves the
    store AND the json.load cost that OOM-killed the backend.

    IT DEFAULTS TO FALSE, and that is deliberate. This file is what every
    RE-fuse reads, so filtering it is only safe where Velociraptor still holds
    the data and the Fetch button can re-pull it — collections, hunts, adopts,
    re-collects. An offline-collector UPLOAD has no such source: the zip is the
    only copy and is usually gone after import, so filtering there would make
    the excluded artifacts unrecoverable if the allowlist ever widens (its own
    comment invites exactly that: "add a line here when a new artifact gets a
    mapper"). Callers opt IN; a new caller that forgets keeps everything.

    Best-effort — a failure to persist this doesn't break the main pipeline.
    """
    if fusion_only and all_results:
        try:
            from services.fusion.mappers.agentic import (
                SUPPORTED_ARTIFACTS, _artifact_base)
            kept = {k: v for k, v in all_results.items()
                    if _artifact_base(k) in SUPPORTED_ARTIFACTS}
            dropped = [k for k in all_results if k not in kept]
            if dropped:
                print(f"[PIPELINE] {run_id}: storing {len(kept)} fusable "
                      f"artifact(s); not storing {len(dropped)} that fusion "
                      f"cannot ingest ({', '.join(sorted(dropped)[:4])}"
                      f"{'…' if len(dropped) > 4 else ''}) — they remain in "
                      f"Velociraptor and a Fetch re-pulls them", flush=True)
            all_results = kept
        except Exception as e:          # noqa: BLE001 — never lose the write
            print(f"[PIPELINE] {run_id}: fusion filter skipped ({e}); "
                  f"storing everything", flush=True)
    downloads_dir = f"/data/downloads/{run_id}"
    try:
        os.makedirs(downloads_dir, exist_ok=True)
        with open(f"{downloads_dir}/raw_results.json", "w") as f:
            # Use default=str so any non-serialisable values (datetimes,
            # bytes, etc.) degrade to a string rather than crashing the
            # whole save.
            json.dump(all_results or {}, f, default=str)
    except Exception as e:
        # Telemetry only — fusion will detect missing files and degrade.
        print(f"[PIPELINE] Failed to persist artifacts for {run_id}: {e}", flush=True)
