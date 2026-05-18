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

logger = logging.getLogger(__name__)


# Note: VQL-level time filtering was removed - each artifact uses different timestamp fields
# (EventTime, Timestamp, Created, etc.) making a universal VQL filter impractical.
# Time filtering is done post-query in Python using find_field_recursive() and TIMESTAMP_FIELDS.

# Maximum rows fetched per artifact result query. Replaces a hard-coded
# 5000-row VQL LIMIT that was silently truncating any artifact whose
# source produced more rows — wrong analysis, no warning. The new
# ceiling is generous (200K rows fits ~99% of real hunts inside ~200MB
# memory) but still finite, and the loader logs a clear warning if a
# real hunt hits it. Override via env if a deployment routinely runs
# bigger hunts.
VELO_MAX_ROWS_PER_ARTIFACT = int(os.environ.get("VELO_MAX_ROWS_PER_ARTIFACT", "200000"))
VELO_QUERY_TIMEOUT_SECONDS = int(os.environ.get("VELO_QUERY_TIMEOUT_SECONDS", "300"))


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

                            # Find which artifact(s) failed
                            failed_artifacts = []
                            if artifacts_requested and artifacts_done:
                                done_set = set(a.split('/')[0] for a in artifacts_done)  # Handle sub-sources
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
                                'artifacts_completed': len(artifacts_done) if artifacts_done else 0,
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


def build_artifact_spec(artifacts, settings=None):
    """Build the artifact spec dict for collection.
    Time filtering is done post-collection via filter_results_by_time().
    Returns a VQL-compatible spec string."""
    # All artifacts get empty spec - time/severity filtering done post-collection
    spec_parts = [f'`{artifact}`=dict()' for artifact in artifacts]
    return ", ".join(spec_parts)


def get_client_hostnames(stub, client_ids):
    """Get hostname mapping for a list of client IDs."""
    hostnames = {}
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


def create_collections(run_id, artifacts, settings, client_ids):
    """Create a collection on each selected client with all artifacts bundled.
    Returns list of {client_id, flow_id, hostname}."""
    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[Velociraptor] Failed to connect to server", "error")
        return []

    stub = api_pb2_grpc.APIStub(channel)
    timeout_seconds = settings.get('timeout', 3600)
    cpu_limit = settings.get('cpu_limit', 80)
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

    # Get hostname mapping for all clients
    client_hostnames = get_client_hostnames(stub, client_ids)

    # Build spec with time filtering if enabled
    time_filter = settings.get('time_filter', {})
    if time_filter.get('enabled'):
        start_time, _ = calculate_time_range(time_filter)
        add_log_to_run(run_id, f"[Velociraptor] Time filter enabled: collecting data since {start_time}", "info")

    artifacts_list = json.dumps(artifacts)
    spec_str = build_artifact_spec(artifacts, settings)

    results = []
    for i, client_id in enumerate(client_ids):
        hostname = client_hostnames.get(client_id, client_id)
        try:
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


def query_artifact_results(stub, client_id, flow_id, artifact, start_iso=None, end_iso=None):
    """Query for available results from a specific artifact with optional VQL time filtering.

    Args:
        stub: gRPC stub
        client_id: Velociraptor client ID
        flow_id: Flow ID to query
        artifact: Artifact name (may include /source suffix)
        start_iso: Optional start time (ISO 8601) for VQL filtering
        end_iso: Optional end time (ISO 8601) for VQL filtering

    Returns:
        List of rows or empty list
    """
    try:
        # No VQL LIMIT — the previous 5000-row cap silently truncated big
        # hunts and produced "complete" reports based on partial data.
        # gRPC streams responses in chunks; we cap server-side via
        # VELO_MAX_ROWS_PER_ARTIFACT and warn loudly on overflow.
        # Time filtering is still done client-side post-fetch.
        query = (
            f"SELECT * FROM source("
            f"client_id='{client_id}', "
            f"flow_id='{flow_id}', "
            f"artifact='{artifact}')"
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


def filter_by_severity(rows, severity_level):
    """Filter rows by minimum severity level with recursive field detection.
    Severity order: informational < low < medium < high < critical
    Searches nested objects for severity fields (e.g., Detection.Criticality)."""
    if severity_level == 'informational':
        return rows  # No filtering - show all

    if not rows:
        return rows

    from services.agentic.utils import find_field_recursive, get_nested_value, SEVERITY_FIELDS

    severity_order = ['informational', 'low', 'medium', 'high', 'critical']
    min_level_idx = severity_order.index(severity_level) if severity_level in severity_order else 2

    # Find severity field recursively from first row (handles nested objects)
    field_path, _ = find_field_recursive(rows[0], SEVERITY_FIELDS)
    if not field_path:
        return rows  # No severity field - keep all rows

    def normalize_level(value):
        """Normalize severity level string to standard names."""
        level_value = str(value or '').lower().strip()
        if level_value in ('info', 'informational', '0', 'none'):
            return 'informational'
        elif level_value in ('lo', '1'):
            return 'low'
        elif level_value in ('med', 'moderate', '2'):
            return 'medium'
        elif level_value in ('hi', '3'):
            return 'high'
        elif level_value in ('crit', '4', 'emergency', 'alert'):
            return 'critical'
        return level_value

    filtered = []
    for row in rows:
        # Get value from nested path
        value = get_nested_value(row, field_path)
        level_value = normalize_level(value)

        if level_value in severity_order:
            if severity_order.index(level_value) >= min_level_idx:
                filtered.append(row)
        else:
            # Unknown severity - keep by default
            filtered.append(row)

    return filtered


def stream_collect_and_analyze(run_id, collection_results, artifacts, collection_minutes, llm_config, anonymizer=None, update_phase_func=None, min_severity='informational', time_filter=None, cancel_event=None):
    """Monitor collection, poll artifact sources for data, analyze as data becomes available.
    Returns (all_results dict, summaries dict, timed_out bool).
    If anonymizer is provided, data is masked before LLM analysis.
    min_severity filters rows by severity level before LLM analysis (informational, low, medium, high, critical).
    time_filter filters rows by timestamp fields (StartTime, EventTime, etc.) - applied in Python post-collection.
    timed_out is True if collection ended due to timeout, False if all flows completed naturally.

    STREAMING OPTIMIZATION: LLM analysis starts immediately when an artifact's flow completes,
    rather than waiting for all collections to finish."""
    from services.agentic.analyzers import analyze_single_artifact
    from services.agentic.utils import filter_row_by_time

    total_seconds = collection_minutes * 60
    elapsed = 0
    interval = 30  # Check every 30 seconds

    # Track state
    completed_flows = set()
    retrieved_artifacts = {}  # (client_id, artifact) -> row_count (to detect new data)
    stable_artifacts = {}  # artifact -> polls_stable (how many polls with no change)
    all_results = {}  # artifact -> [rows] (combined from all clients)
    summaries = {}  # artifact -> summary
    analyzed_artifacts = set()  # Artifacts already submitted for LLM analysis
    llm_futures = {}  # future -> artifact
    total_rows_before_filter = 0  # Track raw row count before any filtering

    # Get max concurrent requests from config
    max_concurrent = llm_config.get('agentic', {}).get('max_concurrent_requests', 5)

    # Create time filter function (if enabled)
    time_filter_func = None
    if time_filter and time_filter.get('enabled'):
        from services.agentic.utils import create_time_filter_func
        time_filter_func = create_time_filter_func(time_filter)

    # Get active flows
    active_flows = [c for c in collection_results if c.get('flow_id')]
    if not active_flows:
        add_log_to_run(run_id, "[Velociraptor] No active flows to monitor", "warning")
        return all_results, summaries, False, 0

    # Setup Velociraptor connection
    channel = setup_velociraptor_connection()
    stub = api_pb2_grpc.APIStub(channel) if channel else None

    if not stub:
        add_log_to_run(run_id, "[Velociraptor] Could not establish connection", "warning")
        return all_results, summaries, False, 0

    add_log_to_run(run_id, f"[Velociraptor] Streaming mode: polling {len(artifacts)} artifacts across {len(active_flows)} clients", "info")
    add_log_to_run(run_id, f"[Pipeline] Streaming analysis enabled - LLM starts as artifacts complete", "info")

    # Thread pool for parallel LLM analysis
    executor = ThreadPoolExecutor(max_workers=max_concurrent)

    # Register cleanup callbacks for stop support
    from services.workflow_service import register_cleanup
    register_cleanup(run_id, lambda: executor.shutdown(wait=False, cancel_futures=True))
    register_cleanup(run_id, lambda: cancel_collections(run_id, active_flows))

    def _wf_log(msg, level="info"):
        """Workflow-log callback passed into the per-artifact analyzer so the
        atomic [Skill] / "no match" line shows up in this run's log too —
        the existing-flow path already does this; the streaming path was
        missing it."""
        add_log_to_run(run_id, msg, level)

    def submit_for_analysis(artifact_name, rows):
        """Submit artifact for LLM analysis if not already submitted."""
        if artifact_name in analyzed_artifacts:
            return
        analyzed_artifacts.add(artifact_name)
        add_log_to_run(run_id, f"[LLM] Starting analysis: {artifact_name} ({len(rows)} rows)", "info")

        # Mirror the existing-flow path: lift SIGMA-rule / MITRE metadata off
        # the first row so the analyzer gets `finding_meta` (drives skill
        # selection via mitre_attack and surfaces the rule context in the
        # prompt). Without this, the streaming path's skills fall back to
        # artifact-name fuzzy match alone.
        finding_meta = None
        if rows and isinstance(rows[0], dict):
            first = rows[0]
            finding_meta = {
                'rule_title': first.get('rule_title') or artifact_name,
                'rule_id': first.get('rule_id', ''),
                'rule_description': first.get('rule_description') or first.get('_description', ''),
                'severity': first.get('severity') or first.get('_severity', 'unknown'),
                'falsepositives': first.get('falsepositives', []),
                'mitre_attack': first.get('mitre_attack', []),
            }

        future = executor.submit(
            analyze_single_artifact, artifact_name, rows, llm_config,
            anonymizer, finding_meta, _wf_log,
        )
        llm_futures[future] = artifact_name

    # Circuit-breaker state. Track consecutive LLM failures across the
    # whole streaming loop. If we hit `_circuit_threshold` failures in a
    # row with zero successes ever recorded, the LLM is dead — bail out
    # of the pipeline cleanly instead of sitting in the polling loop for
    # the rest of the collection window producing nothing useful.
    _circuit_state = {
        'consecutive_failures': 0,
        'successful_analyses': 0,
        'failed_analyses': 0,
        'tripped': False,
    }
    _circuit_threshold = 5

    def check_completed_analyses():
        """Check for completed LLM analyses (non-blocking)."""
        completed = []
        for future in list(llm_futures.keys()):
            if future.done():
                artifact = llm_futures.pop(future)
                try:
                    result_artifact, summary, error = future.result(timeout=1)
                    summaries[result_artifact] = summary
                    if error:
                        from services.agentic.analyzers import explain_llm_error
                        _ol = (llm_config.get('agentic') or {}).get('online_llm', {}) if isinstance(llm_config, dict) else {}
                        add_log_to_run(run_id, f"[LLM] Error for {result_artifact}: {explain_llm_error(str(error), _ol.get('model', '?'), _ol.get('provider', '?'))}", "warning")
                        _circuit_state['consecutive_failures'] += 1
                        _circuit_state['failed_analyses'] += 1
                    else:
                        add_log_to_run(run_id, f"[LLM] Analysis complete: {result_artifact}", "success")
                        _circuit_state['consecutive_failures'] = 0
                        _circuit_state['successful_analyses'] += 1
                    completed.append(result_artifact)
                except Exception as e:
                    add_log_to_run(run_id, f"[LLM] Analysis failed for {artifact}: {str(e)}", "warning")
                    summaries[artifact] = f"Analysis failed: {str(e)}"
                    _circuit_state['consecutive_failures'] += 1
                    _circuit_state['failed_analyses'] += 1

        # Trip the breaker only on a sustained-failure-with-zero-success
        # pattern. Tolerates short blips because a single later success
        # resets `consecutive_failures` to 0.
        if (_circuit_state['consecutive_failures'] >= _circuit_threshold
                and _circuit_state['successful_analyses'] == 0
                and not _circuit_state['tripped']):
            _circuit_state['tripped'] = True
            add_log_to_run(
                run_id,
                f"[Pipeline] LLM circuit breaker tripped — "
                f"{_circuit_state['consecutive_failures']} consecutive failures, "
                f"0 successes. Aborting before more time is wasted on a dead LLM.",
                "error",
            )
            # Cancel any pending LLM futures so they stop retrying.
            for f in list(llm_futures.keys()):
                try:
                    f.cancel()
                except Exception:
                    pass
            # The pipeline.py except handler catches RuntimeError and
            # moves the run to `failed`; cancel_event propagation also
            # ensures the outer collection loop exits its sleep().
            raise RuntimeError("LLM circuit breaker tripped — LLM is unreachable")
        return completed

    # Track discovered sources (including sub-artifacts)
    discovered_sources = {}  # flow_id -> set of source names

    try:
        while elapsed < total_seconds:
            # Check for cancellation
            if cancel_event and cancel_event.is_set():
                add_log_to_run(run_id, "[Velociraptor] Collection cancelled by user", "warning")
                break

            # Poll each flow for available data
            for col in active_flows:
                client_id = col.get('client_id')
                flow_id = col.get('flow_id')
                if not flow_id:
                    continue

                # Enumerate all available sources in this flow (includes sub-artifacts)
                if flow_id not in discovered_sources:
                    discovered_sources[flow_id] = set()

                # Get current sources from flow
                current_sources = enumerate_flow_sources(stub, client_id, flow_id)
                new_sources = set(current_sources) - discovered_sources[flow_id]

                if new_sources:
                    for src in new_sources:
                        add_log_to_run(run_id, f"[Velociraptor] Discovered source: {src}", "info")
                    discovered_sources[flow_id].update(new_sources)

                # Query all discovered sources for this flow
                for source_name in discovered_sources[flow_id]:
                    artifact_key = (client_id, source_name)

                    # Query for artifact results
                    rows = query_artifact_results(stub, client_id, flow_id, source_name)

                    if rows:
                        prev_count = retrieved_artifacts.get(artifact_key, 0)
                        if len(rows) > prev_count:
                            # New data available!
                            retrieved_artifacts[artifact_key] = len(rows)
                            total_rows_before_filter += len(rows) - prev_count  # Track raw rows
                            stable_artifacts[source_name] = 0  # Reset stability counter

                            # Apply time filter first (if enabled)
                            filtered_rows = rows
                            rows_after_time = len(rows)
                            if time_filter_func:
                                filtered_rows = [r for r in filtered_rows if filter_row_by_time(r, time_filter_func)]
                                rows_after_time = len(filtered_rows)

                            # Then apply severity filter
                            rows_after_severity = rows_after_time
                            if min_severity != 'informational':
                                filtered_rows = filter_by_severity(filtered_rows, min_severity)
                                rows_after_severity = len(filtered_rows)

                            # Update all_results with filtered data
                            if source_name not in all_results:
                                all_results[source_name] = []
                                # Build informative log message
                                if rows_after_time < len(rows) or rows_after_severity < rows_after_time:
                                    filter_parts = []
                                    if rows_after_time < len(rows):
                                        filter_parts.append(f"{rows_after_time} after time filter")
                                    if rows_after_severity < rows_after_time:
                                        filter_parts.append(f"{rows_after_severity} after {min_severity}+ filter")
                                    add_log_to_run(run_id, f"[Velociraptor] Found: {source_name} ({len(rows)} rows, {', '.join(filter_parts)})", "info")
                                else:
                                    add_log_to_run(run_id, f"[Velociraptor] Found: {source_name} ({len(rows)} rows)", "info")

                            # Replace with latest filtered data
                            all_results[source_name] = filtered_rows
                        else:
                            # Data unchanged - increment stability counter
                            if source_name in all_results and source_name not in analyzed_artifacts:
                                stable_artifacts[source_name] = stable_artifacts.get(source_name, 0) + 1

                                # STREAMING: Process artifact when data is stable (no new data for 1 poll)
                                if stable_artifacts[source_name] >= 1 and all_results[source_name]:
                                    rows_to_analyze = all_results[source_name]
                                    if rows_to_analyze:
                                        # TODO: LLM DISABLED - message updated to reflect this
                                        add_log_to_run(run_id, f"[Pipeline] Artifact {source_name} stable ({len(rows_to_analyze)} rows)", "info")
                                        submit_for_analysis(source_name, rows_to_analyze)
                                    else:
                                        add_log_to_run(run_id, f"[Filter] {source_name}: All rows filtered out - skipping LLM", "info")
                                        analyzed_artifacts.add(source_name)  # Mark as done

            # Check flow status
            for col in active_flows:
                client_id = col.get('client_id')
                flow_id = col.get('flow_id')
                if not flow_id or flow_id in completed_flows:
                    continue

                status, error_info = check_flow_status(stub, client_id, flow_id)
                if status == 'FINISHED':
                    completed_flows.add(flow_id)
                    add_log_to_run(run_id, f"[Velociraptor] Flow completed on {client_id}", "info")
                elif status == 'ERROR':
                    completed_flows.add(flow_id)
                    # Log error details but continue processing - data may still be available
                    if error_info and error_info.get('artifacts_completed', 0) > 0:
                        completed = error_info['artifacts_completed']
                        requested = error_info.get('artifacts_requested', 0)
                        failed = error_info.get('failed_artifacts', [])
                        reason = error_info.get('error_reason', 'unknown reason')

                        # Build informative message - make clear it's warning, not error
                        if failed:
                            failed_str = ', '.join(failed[:3])  # Show up to 3 failed
                            if len(failed) > 3:
                                failed_str += f" (+{len(failed)-3} more)"
                            msg = f"[Velociraptor] (Warning, non-blocking) {len(failed)} artifact(s) did not complete ({failed_str}). {completed}/{requested} succeeded - pipeline continues."
                        else:
                            msg = f"[Velociraptor] (Warning, non-blocking) Flow had partial issues. {completed}/{requested} artifacts succeeded - pipeline continues."
                        add_log_to_run(run_id, msg, "warning")
                    else:
                        add_log_to_run(run_id, f"[Velociraptor] (Error) Flow failed on {client_id} - no data collected", "error")
                    if error_info and error_info.get('backtrace'):
                        # Log first line of backtrace for debugging
                        bt_first_line = error_info['backtrace'].split('\n')[0][:100]
                        print(f"[AGENTIC] Flow {flow_id} error: {bt_first_line}", flush=True)

            # Check for completed LLM analyses
            check_completed_analyses()

            # Check if all flows are done
            all_flows_completed = len(completed_flows) == len(active_flows)
            if all_flows_completed:
                add_log_to_run(run_id, f"[Velociraptor] All {len(active_flows)} flows completed!", "success")
                # Wait for any remaining LLM analyses before breaking
                total_sources = sum(len(srcs) for srcs in discovered_sources.values())
                if len(summaries) == len(analyzed_artifacts) and len(llm_futures) == 0:
                    add_log_to_run(run_id, f"[Pipeline] All {total_sources} sources analyzed - finishing!", "success")
                break

            # Calculate and display remaining time
            remaining = total_seconds - elapsed
            remaining_min = remaining // 60
            remaining_sec = remaining % 60

            collection_progress = 10 + int((elapsed / total_seconds) * 40)
            if update_phase_func:
                update_phase_func(run_id, "collecting", collection_progress)

            artifacts_found = len(all_results)
            total_rows = sum(len(r) for r in all_results.values())
            analyzing_count = len(analyzed_artifacts)

            # Count total discovered sources
            total_sources = sum(len(srcs) for srcs in discovered_sources.values())

            # Show successes vs failures separately so a misleading
            # "Done: 10/10" never hides that every single one errored
            # — the QA bug that prompted the circuit-breaker work.
            ok_n = _circuit_state['successful_analyses']
            fail_n = _circuit_state['failed_analyses']
            done_part = f"Done: {ok_n} ✓ / {fail_n} ✗" if fail_n else f"Done: {ok_n}"

            add_log_to_run(run_id,
                f"[Pipeline] {remaining_min}m {remaining_sec}s | "
                f"Collected: {artifacts_found}/{total_sources} sources | "
                f"Analyzing: {analyzing_count} | {done_part}",
                "info")

            sleep_time = min(interval, remaining)
            if cancel_event:
                cancel_event.wait(timeout=sleep_time)
            else:
                time.sleep(sleep_time)
            elapsed += interval

        # Collection phase done - do one final poll
        add_log_to_run(run_id, "[Velociraptor] Collection ended - final data retrieval...", "info")
        if update_phase_func:
            update_phase_func(run_id, "retrieving_results", 50)

        for col in active_flows:
            client_id = col.get('client_id')
            flow_id = col.get('flow_id')
            if not flow_id:
                continue

            # Get final list of all sources
            final_sources = enumerate_flow_sources(stub, client_id, flow_id)
            for source_name in final_sources:
                rows = query_artifact_results(stub, client_id, flow_id, source_name)
                if rows:
                    # Apply time filter first (same as polling loop)
                    filtered_rows = rows
                    if time_filter_func:
                        filtered_rows = [r for r in filtered_rows if filter_row_by_time(r, time_filter_func)]

                    # Then apply severity filter
                    if min_severity != 'informational':
                        filtered_rows = filter_by_severity(filtered_rows, min_severity)

                    if source_name not in all_results:
                        all_results[source_name] = filtered_rows
                        if min_severity != 'informational' and len(filtered_rows) < len(rows):
                            add_log_to_run(run_id, f"[Velociraptor] Final: {source_name} ({len(rows)} rows, {len(filtered_rows)} after {min_severity}+ filter)", "info")
                        else:
                            add_log_to_run(run_id, f"[Velociraptor] Final: {source_name} ({len(rows)} rows)", "info")
                    elif len(filtered_rows) > len(all_results.get(source_name, [])):
                        all_results[source_name] = filtered_rows

        # Submit any remaining sources that haven't been analyzed yet
        for source_name in all_results.keys():
            if all_results[source_name] and source_name not in analyzed_artifacts:
                submit_for_analysis(source_name, all_results[source_name])

        # All sources collected
        total_rows = sum(len(r) for r in all_results.values())
        add_log_to_run(run_id, f"[Pipeline] Collection complete: {len(all_results)} sources, {total_rows} rows", "success")

        # Wait for remaining LLM analyses to complete
        remaining_analyses = len(llm_futures)
        if remaining_analyses > 0:
            add_log_to_run(run_id, f"[LLM] Waiting for {remaining_analyses} remaining analyses...", "info")
            if update_phase_func:
                update_phase_func(run_id, "analyzing", 60)

            for future in as_completed(llm_futures.keys(), timeout=600):
                artifact = llm_futures.get(future, "unknown")
                try:
                    result_artifact, summary, error = future.result(timeout=60)
                    summaries[result_artifact] = summary

                    progress = 60 + int((len(summaries) / len(analyzed_artifacts)) * 25) if analyzed_artifacts else 85
                    if update_phase_func:
                        update_phase_func(run_id, "analyzing", progress)

                    if error:
                        from services.agentic.analyzers import explain_llm_error
                        _ol = (llm_config.get('agentic') or {}).get('online_llm', {}) if isinstance(llm_config, dict) else {}
                        add_log_to_run(run_id, f"[LLM] Error for {result_artifact}: {explain_llm_error(str(error), _ol.get('model', '?'), _ol.get('provider', '?'))}", "warning")
                    else:
                        add_log_to_run(run_id, f"[LLM] Analysis complete: {result_artifact}", "success")
                except Exception as e:
                    add_log_to_run(run_id, f"[LLM] Analysis failed for {artifact}: {str(e)}", "warning")
                    summaries[artifact] = f"Analysis failed: {str(e)}"

        # All LLM analyses complete
        add_log_to_run(run_id, f"[LLM] All {len(summaries)} artifacts analyzed", "success")

    finally:
        if channel:
            channel.close()
        executor.shutdown(wait=False)

    # Return whether we timed out (vs completed naturally)
    timed_out = elapsed >= total_seconds
    return all_results, summaries, timed_out, total_rows_before_filter


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


def get_existing_collection_results(run_id, flow_id=None, hunt_id=None, time_filter=None, client_ids=None):
    """Fetch results from an existing Velociraptor flow or hunt with optional time filtering.

    Args:
        run_id: Workflow run ID for logging
        flow_id: Flow ID (F.xxx) for single client collection
        hunt_id: Hunt ID (H.xxx OR F.xxx.H) for multi-client hunt
        time_filter: Optional time filter config for VQL-level filtering
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
                for source in flow_sources:
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

                    if not rows:
                        continue

                    # Tag every row with `_client_id` + `_hostname`. The
                    # per-client report filter (services/agentic/reports.py
                    # filter_results_by_client) and the IRIS timeline
                    # extractor (utils.extract_timeline_events) both rely on
                    # these to slice + link events to the right host.
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

            # Now fetch results from each flow
            for flow_info in hunt_flows:
                flow_client_id = flow_info.get('ClientId')
                flow_id = flow_info.get('FlowId')
                if not flow_client_id or not flow_id:
                    continue

                # Get available sources in this flow
                sources = enumerate_flow_sources(stub, flow_client_id, flow_id)
                add_log_to_run(run_id, f"[Velociraptor] Flow {flow_id} has {len(sources)} sources", "info")

                # Track client info
                if flow_client_id not in client_info:
                    client_info[flow_client_id] = {
                        "client_id": flow_client_id,
                        "hostname": "Unknown",
                        "os": "Unknown"
                    }

                # Fetch results from each source with VQL time filtering
                for source_name in sources:
                    rows = query_artifact_results(stub, flow_client_id, flow_id, source_name, start_iso, end_iso)
                    if rows:
                        if source_name not in artifacts:
                            artifacts.append(source_name)
                        if source_name not in all_results:
                            all_results[source_name] = []
                        # Add client_id to each row for traceability
                        for row in rows:
                            row['_client_id'] = flow_client_id
                        all_results[source_name].extend(rows)
                        add_log_to_run(run_id, f"[Velociraptor] Retrieved {len(rows)} rows from {source_name}", "info")

            add_log_to_run(run_id, f"[Velociraptor] Hunt contained {len(artifacts)} artifacts from {len(client_info)} clients", "info")

    except Exception as e:
        add_log_to_run(run_id, f"[Velociraptor] Error fetching existing results: {str(e)}", "error")

    finally:
        channel.close()

    return all_results, artifacts, client_info
