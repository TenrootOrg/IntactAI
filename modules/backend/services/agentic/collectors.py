#!/usr/bin/env python3
"""
Agentic Collectors - Velociraptor artifact collection logic
"""

import json
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection
from services.workflow_service import add_log_to_run


def get_vql_time_filter(start_iso, end_iso):
    """Build a VQL WHERE clause for time filtering.

    Args:
        start_iso: Start time in ISO 8601 format (e.g., '2026-03-03T00:00:00Z')
        end_iso: End time in ISO 8601 format

    Returns:
        VQL WHERE clause string or empty string if no filter needed
    """
    if not start_iso and not end_iso:
        return ""

    # Note: Time filtering in VQL depends on the artifact's timestamp field
    # Most artifacts use _ts or EventTime, but this varies
    # For now, return empty to avoid breaking queries - time filtering is done post-query
    return ""


def check_flow_status(stub, client_id, flow_id):
    """Check the status of a Velociraptor flow. Returns 'RUNNING', 'FINISHED', 'ERROR', or None."""
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
                        # Debug: print what we got
                        print(f"[AGENTIC] Flow status check: flow_id={flow_id}, state={state}, keys={list(row.keys())[:10]}", flush=True)
                        # Velociraptor flow states (case-insensitive check)
                        state_upper = str(state).upper()
                        if state_upper == 'FINISHED':
                            return 'FINISHED'
                        elif state_upper in ('ERROR', 'CANCELLED', 'FAILED'):
                            return 'ERROR'
                        elif state_upper in ('RUNNING', 'IN_PROGRESS'):
                            return 'RUNNING'
                except Exception as e:
                    print(f"[AGENTIC] Flow status parse error: {e}", flush=True)
    except Exception as e:
        print(f"[AGENTIC] Flow status query error: {e}", flush=True)
    return None


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


def build_artifact_spec(artifacts, settings):
    """Build the artifact spec dict with optional time parameters.
    Returns a VQL-compatible spec string."""
    time_filter = settings.get('time_filter', {})
    start_time, end_time = calculate_time_range(time_filter)

    spec_parts = []
    for artifact in artifacts:
        time_params = ARTIFACT_TIME_PARAMS.get(artifact, {})

        if start_time and time_params:
            # Build params dict for this artifact
            params = {}
            if 'start' in time_params:
                params[time_params['start']] = start_time
            if 'end' in time_params and end_time:
                params[time_params['end']] = end_time

            # Format as VQL dict
            param_str = ", ".join([f'{k}="{v}"' for k, v in params.items()])
            spec_parts.append(f'`{artifact}`=dict({param_str})')
        else:
            # No time filtering for this artifact
            spec_parts.append(f'`{artifact}`=dict()')

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
    cpu_limit={cpu_limit}
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
        # Build VQL query with optional time filter
        time_filter_clause = get_vql_time_filter(start_iso, end_iso)
        query = f"""
SELECT * FROM source(client_id='{client_id}', flow_id='{flow_id}', artifact='{artifact}')
{time_filter_clause}
LIMIT 5000
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=5000,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )
        rows = []
        for response in stub.Query(request_obj, timeout=30):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    if isinstance(resp_data, list):
                        rows.extend(resp_data)
                except Exception:
                    pass
        return rows
    except Exception:
        return []


def filter_by_severity(rows, severity_level):
    """Filter rows by minimum severity level.
    Severity order: informational < low < medium < high < critical
    Only filters rows that have a severity/level field."""
    if severity_level == 'informational':
        return rows  # No filtering - show all

    severity_order = ['informational', 'low', 'medium', 'high', 'critical']
    min_level_idx = severity_order.index(severity_level) if severity_level in severity_order else 2  # default medium

    # Common severity field names
    severity_fields = ['Level', 'level', 'Severity', 'severity', 'RuleLevel', 'rule_level',
                       'Priority', 'priority', 'Criticality', 'criticality', 'Risk', 'risk']

    # Check if rows have a severity field
    if not rows:
        return rows
    sample = rows[0]
    severity_field = None
    for field in severity_fields:
        if field in sample:
            severity_field = field
            break

    if not severity_field:
        return rows  # No severity field - keep all rows

    filtered = []
    for row in rows:
        level_value = str(row.get(severity_field, '')).lower().strip()
        # Normalize common level names
        if level_value in ('info', 'informational', '0', 'none'):
            level_value = 'informational'
        elif level_value in ('lo', '1'):
            level_value = 'low'
        elif level_value in ('med', 'moderate', '2'):
            level_value = 'medium'
        elif level_value in ('hi', '3'):
            level_value = 'high'
        elif level_value in ('crit', '4', 'emergency', 'alert'):
            level_value = 'critical'

        if level_value in severity_order:
            level_idx = severity_order.index(level_value)
            if level_idx >= min_level_idx:
                filtered.append(row)
        else:
            # Unknown severity - keep by default
            filtered.append(row)

    return filtered


def stream_collect_and_analyze(run_id, collection_results, artifacts, collection_minutes, llm_config, anonymizer=None, update_phase_func=None, min_severity='informational'):
    """Monitor collection, poll artifact sources for data, analyze as data becomes available.
    Returns (all_results dict, summaries dict, timed_out bool).
    If anonymizer is provided, data is masked before LLM analysis.
    min_severity filters rows by severity level before LLM analysis (informational, low, medium, high, critical).
    timed_out is True if collection ended due to timeout, False if all flows completed naturally.

    STREAMING OPTIMIZATION: LLM analysis starts immediately when an artifact's flow completes,
    rather than waiting for all collections to finish."""
    from services.agentic.analyzers import analyze_single_artifact

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

    # Get max concurrent requests from config
    max_concurrent = llm_config.get('agentic', {}).get('max_concurrent_requests', 5)

    # Get active flows
    active_flows = [c for c in collection_results if c.get('flow_id')]
    if not active_flows:
        add_log_to_run(run_id, "[Velociraptor] No active flows to monitor", "warning")
        return all_results, summaries, False

    # Setup Velociraptor connection
    channel = setup_velociraptor_connection()
    stub = api_pb2_grpc.APIStub(channel) if channel else None

    if not stub:
        add_log_to_run(run_id, "[Velociraptor] Could not establish connection", "warning")
        return all_results, summaries, False

    add_log_to_run(run_id, f"[Velociraptor] Streaming mode: polling {len(artifacts)} artifacts across {len(active_flows)} clients", "info")
    add_log_to_run(run_id, f"[Pipeline] Streaming analysis enabled - LLM starts as artifacts complete", "info")

    # Thread pool for parallel LLM analysis
    executor = ThreadPoolExecutor(max_workers=max_concurrent)

    def submit_for_analysis(artifact_name, rows):
        """Submit artifact for LLM analysis if not already submitted."""
        if artifact_name in analyzed_artifacts:
            return
        analyzed_artifacts.add(artifact_name)
        add_log_to_run(run_id, f"[LLM] Starting analysis: {artifact_name} ({len(rows)} rows)", "info")
        future = executor.submit(analyze_single_artifact, artifact_name, rows, llm_config, anonymizer)
        llm_futures[future] = artifact_name

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
                        add_log_to_run(run_id, f"[LLM] Error for {result_artifact}: {error}", "warning")
                    else:
                        add_log_to_run(run_id, f"[LLM] Analysis complete: {result_artifact}", "success")
                    completed.append(result_artifact)
                except Exception as e:
                    add_log_to_run(run_id, f"[LLM] Analysis failed for {artifact}: {str(e)}", "warning")
                    summaries[artifact] = f"Analysis failed: {str(e)}"
        return completed

    # Track discovered sources (including sub-artifacts)
    discovered_sources = {}  # flow_id -> set of source names

    try:
        while elapsed < total_seconds:
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
                            stable_artifacts[source_name] = 0  # Reset stability counter

                            # Apply severity filter immediately after getting results
                            filtered_rows = rows
                            if min_severity != 'informational':
                                filtered_rows = filter_by_severity(rows, min_severity)

                            # Update all_results with filtered data
                            if source_name not in all_results:
                                all_results[source_name] = []
                                if min_severity != 'informational' and len(filtered_rows) < len(rows):
                                    add_log_to_run(run_id, f"[Velociraptor] Found: {source_name} ({len(rows)} rows, {len(filtered_rows)} after {min_severity}+ filter)", "info")
                                else:
                                    add_log_to_run(run_id, f"[Velociraptor] Found: {source_name} ({len(rows)} rows)", "info")

                            # Replace with latest filtered data
                            all_results[source_name] = filtered_rows
                        else:
                            # Data unchanged - increment stability counter
                            if source_name in all_results and source_name not in analyzed_artifacts:
                                stable_artifacts[source_name] = stable_artifacts.get(source_name, 0) + 1

                                # STREAMING: Start LLM when artifact data is stable (no new data for 1 poll)
                                if stable_artifacts[source_name] >= 1 and all_results[source_name]:
                                    rows_to_analyze = all_results[source_name]
                                    if rows_to_analyze:
                                        add_log_to_run(run_id, f"[Pipeline] Artifact {source_name} stable - starting LLM analysis ({len(rows_to_analyze)} rows)", "info")
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

                status = check_flow_status(stub, client_id, flow_id)
                if status == 'FINISHED':
                    completed_flows.add(flow_id)
                    add_log_to_run(run_id, f"[Velociraptor] Flow completed on {client_id}", "info")
                elif status == 'ERROR':
                    completed_flows.add(flow_id)
                    add_log_to_run(run_id, f"[Velociraptor] Flow cancelled/failed on {client_id}", "warning")

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
            analyzed_count = len(summaries)

            # Count total discovered sources
            total_sources = sum(len(srcs) for srcs in discovered_sources.values())

            add_log_to_run(run_id,
                f"[Pipeline] {remaining_min}m {remaining_sec}s | Collected: {artifacts_found}/{total_sources} sources | Analyzing: {analyzing_count} | Done: {analyzed_count}",
                "info")

            time.sleep(min(interval, remaining))
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
                    if source_name not in all_results:
                        all_results[source_name] = rows
                        add_log_to_run(run_id, f"[Velociraptor] Final: {source_name} ({len(rows)} rows)", "info")
                    elif len(rows) > len(all_results.get(source_name, [])):
                        all_results[source_name] = rows

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
                        add_log_to_run(run_id, f"[LLM] Error for {result_artifact}: {error}", "warning")
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
    return all_results, summaries, timed_out


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


def get_existing_collection_results(run_id, flow_id=None, hunt_id=None, time_filter=None):
    """Fetch results from an existing Velociraptor flow or hunt with optional time filtering.

    Args:
        run_id: Workflow run ID for logging
        flow_id: Flow ID (F.xxx) for single client collection
        hunt_id: Hunt ID (H.xxx) for multi-client hunt
        time_filter: Optional time filter config for VQL-level filtering

    Returns:
        (all_results, artifacts, client_info)
        - all_results: dict of artifact_name -> [rows]
        - artifacts: list of artifact names found
        - client_info: dict of client_id -> {hostname, os, etc.}
    """
    all_results = {}
    artifacts = []
    client_info = {}

    # Calculate time range for VQL filtering
    start_iso, end_iso = calculate_time_range(time_filter)
    if start_iso or end_iso:
        add_log_to_run(run_id, f"[Velociraptor] VQL time filter: {start_iso} to {end_iso}", "info")

    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[Velociraptor] Could not establish connection", "error")
        return all_results, artifacts, client_info

    stub = api_pb2_grpc.APIStub(channel)

    try:
        if flow_id:
            # Get results from a single flow
            add_log_to_run(run_id, f"[Velociraptor] Fetching results from flow: {flow_id}", "info")

            client_id = None
            client_hostname = "Unknown"

            # First, get all clients and search for the flow
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

            # Search each client for this flow
            for client in all_clients:
                cid = client.get('client_id')
                if not cid:
                    continue

                flow_check_query = f"SELECT session_id FROM flows(client_id='{cid}', flow_id='{flow_id}')"
                request_obj = api_pb2.VQLCollectorArgs(
                    max_wait=10,
                    max_row=1,
                    Query=[api_pb2.VQLRequest(VQL=flow_check_query)]
                )

                try:
                    for response in stub.Query(request_obj, timeout=30):
                        if response.log:
                            add_log_to_run(run_id, f"[Velociraptor] Query log for {cid}: {response.log.strip()}", "debug")
                        if response.Response:
                            try:
                                resp_data = json.loads(response.Response)
                                add_log_to_run(run_id, f"[Velociraptor] Query result for {cid}: {len(resp_data)} rows", "debug")
                                if resp_data and len(resp_data) > 0:
                                    client_id = cid
                                    client_hostname = client.get('hostname', 'Unknown')
                                    add_log_to_run(run_id, f"[Velociraptor] Found flow on client: {cid} ({client_hostname})", "info")
                                    break
                            except Exception as e:
                                add_log_to_run(run_id, f"[Velociraptor] Error parsing flow check for {cid}: {e}", "warning")
                except Exception as e:
                    add_log_to_run(run_id, f"[Velociraptor] Error querying client {cid}: {e}", "warning")
                    continue
                if client_id:
                    break

            # Fallback: check server flows
            if not client_id:
                flow_info_query = f"SELECT client_id FROM flows(client_id='server', flow_id='{flow_id}')"
                request_obj = api_pb2.VQLCollectorArgs(
                    max_wait=30,
                    max_row=1,
                    Query=[api_pb2.VQLRequest(VQL=flow_info_query)]
                )

                for response in stub.Query(request_obj, timeout=60):
                    if response.Response:
                        try:
                            resp_data = json.loads(response.Response)
                            if resp_data and len(resp_data) > 0:
                                client_id = 'server'
                                client_hostname = 'Server'
                                add_log_to_run(run_id, f"[Velociraptor] Found server flow: {flow_id}", "info")
                        except:
                            pass

            if not client_id:
                add_log_to_run(run_id, f"[Velociraptor] Could not find flow {flow_id} on any of {len(all_clients)} clients or server", "error")
                return all_results, artifacts, client_info

            # List available sources in the flow using artifacts_with_results
            sources_query = f"SELECT artifacts_with_results FROM flows(client_id='{client_id}', flow_id='{flow_id}')"
            request_obj = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=10,
                Query=[api_pb2.VQLRequest(VQL=sources_query)]
            )

            flow_sources = []
            for response in stub.Query(request_obj, timeout=60):
                if response.Response:
                    try:
                        resp_data = json.loads(response.Response)
                        if resp_data and len(resp_data) > 0:
                            artifacts_list = resp_data[0].get('artifacts_with_results', [])
                            if artifacts_list:
                                flow_sources = artifacts_list
                                add_log_to_run(run_id, f"[Velociraptor] Artifacts in flow: {artifacts_list}", "debug")
                    except Exception as e:
                        add_log_to_run(run_id, f"[Velociraptor] Error getting artifacts list: {e}", "warning")

            add_log_to_run(run_id, f"[Velociraptor] Found {len(flow_sources)} artifact sources in flow", "info")
            artifacts = flow_sources

            # Build VQL time filter clause if enabled
            time_filter_clause = get_vql_time_filter(start_iso, end_iso)
            if time_filter_clause:
                add_log_to_run(run_id, f"[Velociraptor] VQL time filter active", "debug")

            # Fetch results from each source with VQL time filtering
            for source in flow_sources:
                query = f"SELECT * FROM source(client_id='{client_id}', flow_id='{flow_id}', artifact='{source}')"
                if time_filter_clause:
                    query += time_filter_clause
                request_obj = api_pb2.VQLCollectorArgs(
                    max_wait=60,
                    max_row=50000,
                    Query=[api_pb2.VQLRequest(VQL=query)]
                )

                rows = []
                for response in stub.Query(request_obj, timeout=120):
                    if response.Response:
                        try:
                            resp_data = json.loads(response.Response)
                            rows.extend(resp_data)
                        except:
                            pass

                if rows:
                    all_results[source] = rows
                    add_log_to_run(run_id, f"[Velociraptor] Retrieved {len(rows)} rows from {source}", "info")

            # Add client info
            client_info[client_id] = {"client_id": client_id, "hostname": client_hostname, "os": "Unknown"}

        elif hunt_id:
            # Get results from a hunt (multiple clients)
            add_log_to_run(run_id, f"[Velociraptor] Fetching results from hunt: {hunt_id}", "info")

            # First, get all flows in this hunt using hunt_flows()
            flows_query = f"SELECT ClientId, FlowId FROM hunt_flows(hunt_id='{hunt_id}')"
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
