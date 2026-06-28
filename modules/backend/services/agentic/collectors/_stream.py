#!/usr/bin/env python3
"""
Agentic Collectors - Velociraptor artifact collection logic
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from concurrent.futures import as_completed

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection
from services.workflow_service import add_log_to_run
from services.agentic.collectors._base import *  # noqa: F401,F403

def stream_collect_and_analyze(run_id, collection_results, artifacts, collection_minutes, llm_config, anonymizer=None, update_phase_func=None, min_severity='informational', time_filter=None, cancel_event=None, master_prompt=None):
    """Monitor collection, poll artifact sources for data, analyze as data becomes available.
    Returns (all_results dict, summaries dict, timed_out bool).
    If anonymizer is provided, data is masked before LLM analysis.
    min_severity filters rows by severity level before LLM analysis (informational, low, medium, high, critical).
    time_filter filters rows by timestamp fields (StartTime, EventTime, etc.) - applied in Python post-collection.
    timed_out is True if collection ended due to timeout, False if all flows completed naturally.

    STREAMING OPTIMIZATION: LLM analysis starts immediately when an artifact's flow completes,
    rather than waiting for all collections to finish."""
    from services.agentic.utils import filter_row_by_time

    # Agentic per-artifact LLM analysis was REMOVED — the pipeline is always
    # COLLECT-ONLY: collect/poll/merge/filter rows normally, never call the LLM.
    # The run stays fuseable (rows are persisted); analysis happens at the Case
    # level (fusion). The LLM branches below are gated on this and never run.
    _llm_on = False

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

    # Per-flow hostname lookup so the per-client log lines below can show
    # readable names instead of opaque client_ids. Each collection_results
    # entry already carries `hostname` from create_collections().
    flow_hostnames = {
        c.get('client_id'): c.get('hostname') or c.get('client_id')
        for c in collection_results if c.get('client_id')
    }
    multi_client = len(active_flows) > 1
    def _name(cid):
        return flow_hostnames.get(cid, cid)

    # Setup Velociraptor connection
    channel = setup_velociraptor_connection()
    stub = api_pb2_grpc.APIStub(channel) if channel else None

    if not stub:
        add_log_to_run(run_id, "[Velociraptor] Could not establish connection", "warning")
        return all_results, summaries, False, 0

    add_log_to_run(run_id, f"[Velociraptor] Streaming mode: polling {len(artifacts)} artifacts across {len(active_flows)} clients", "info")
    add_log_to_run(run_id, f"[Pipeline] Streaming analysis enabled - LLM starts as artifacts complete", "info")

    # Register cleanup callbacks for stop support
    from services.workflow_service import register_cleanup
    register_cleanup(run_id, lambda: cancel_collections(run_id, active_flows))

    def _wf_log(msg, level="info"):
        """Workflow-log callback passed into the per-artifact analyzer so the
        atomic [Skill] / "no match" line shows up in this run's log too —
        the existing-flow path already does this; the streaming path was
        missing it."""
        add_log_to_run(run_id, msg, level)

    def submit_for_analysis(artifact_name, rows):
        """Mark an artifact as processed. Collect-only — the agentic LLM
        analysis was removed, so rows are simply persisted (they already live
        in all_results) for Case-level fusion; no LLM call is made."""
        if artifact_name in analyzed_artifacts:
            return
        analyzed_artifacts.add(artifact_name)

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
                        add_log_to_run(run_id, f"[LLM] Error for {result_artifact}: {error}", "warning")
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
                    # Tag with hostname so multi-client logs show which host
                    # each discovered source belongs to (single-client mode
                    # adds a redundant tag but it's harmless and keeps the
                    # line format consistent across modes).
                    src_host = _name(client_id)
                    for src in new_sources:
                        add_log_to_run(run_id, f"[Velociraptor] [{src_host}] Discovered source: {src}", "info")
                    discovered_sources[flow_id].update(new_sources)

                # Query all discovered sources for this flow
                # client_hostname is used to tag rows (see below) so the
                # per-client filter in reports.py can attribute each row
                # back to its source host.
                client_hostname = _name(client_id)
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

                            # Tag every row with _client_id + _hostname so
                            # the per-client report filter
                            # (reports.py:filter_results_by_client) can
                            # attribute rows back to their source host.
                            # WITHOUT this tagging, multi-client runs lose
                            # all per-client structure and the per-host
                            # reports come out empty even when 100s of rows
                            # are collected.
                            for r in rows:
                                if isinstance(r, dict):
                                    r.setdefault('_client_id', client_id)
                                    r.setdefault('_hostname', client_hostname)

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
                            # Build informative log message — always include
                            # the hostname tag so multi-client runs are
                            # readable. The "first time this source is seen"
                            # branch used to be the only one that logged;
                            # now we log for every per-client increment so
                            # an operator can see e.g. NofLaptop adding 50
                            # new MFT rows after DESKTOP-566AT85 already
                            # delivered its 100.
                            if rows_after_time < len(rows) or rows_after_severity < rows_after_time:
                                filter_parts = []
                                if rows_after_time < len(rows):
                                    filter_parts.append(f"{rows_after_time} after time filter")
                                if rows_after_severity < rows_after_time:
                                    filter_parts.append(f"{rows_after_severity} after {min_severity}+ filter")
                                add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Found: {source_name} ({len(rows)} rows, {', '.join(filter_parts)})", "info")
                            else:
                                add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Found: {source_name} ({len(rows)} rows)", "info")

                            # Multi-client merge: keep rows from OTHER
                            # clients, replace this client's rows with the
                            # latest filtered set. Without this, a poll on
                            # client B would wipe out client A's rows for
                            # the same source, leaving all_results with only
                            # one client's data per artifact.
                            existing_other_clients = [
                                r for r in all_results[source_name]
                                if isinstance(r, dict) and r.get('_client_id') != client_id
                            ]
                            all_results[source_name] = existing_other_clients + filtered_rows
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
                    add_log_to_run(run_id, f"[Velociraptor] Flow completed on {_name(client_id)}", "info")
                elif status == 'ERROR':
                    completed_flows.add(flow_id)
                    host = _name(client_id)
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
                            msg = f"[Velociraptor] (Warning, non-blocking) {host}: {len(failed)} artifact(s) did not complete ({failed_str}). {completed}/{requested} succeeded - pipeline continues."
                        else:
                            msg = f"[Velociraptor] (Warning, non-blocking) {host}: flow had partial issues. {completed}/{requested} artifacts succeeded - pipeline continues."
                        add_log_to_run(run_id, msg, "warning")
                    else:
                        add_log_to_run(run_id, f"[Velociraptor] (Error) Flow failed on {host} - no data collected", "error")
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

            # Per-client breakdown (multi-client only) so the operator
            # can see each host's progress independently. The aggregate
            # line above merges everything; with N>1 that hides whether
            # one host is stuck while others march on. discovered_sources
            # is keyed by flow_id, so map flow_id -> client_id via
            # active_flows.
            #
            # Format chosen to avoid the trailing-ellipsis trap (`…`)
            # which previous versions used — operators reported the
            # heartbeat looked truncated mid-line.
            if multi_client:
                per_client_parts = []
                for col in active_flows:
                    cid = col.get('client_id')
                    fid = col.get('flow_id')
                    if not cid or not fid:
                        continue
                    n_sources = len(discovered_sources.get(fid, set()))
                    # ✓ marker on done flows; no marker while running
                    # (avoids the previous trailing-ellipsis that looked
                    # like the line was truncated).
                    marker = " ✓" if fid in completed_flows else ""
                    per_client_parts.append(f"{_name(cid)}:{n_sources}{marker}")
                if per_client_parts:
                    add_log_to_run(
                        run_id,
                        "[Pipeline] Per-client: " + " | ".join(per_client_parts),
                        "info",
                    )

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
            client_hostname = _name(client_id)

            # Get final list of all sources
            final_sources = enumerate_flow_sources(stub, client_id, flow_id)
            for source_name in final_sources:
                rows = query_artifact_results(stub, client_id, flow_id, source_name)
                if rows:
                    # Tag rows for per-client attribution (same as main poll loop)
                    for r in rows:
                        if isinstance(r, dict):
                            r.setdefault('_client_id', client_id)
                            r.setdefault('_hostname', client_hostname)

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
                            add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Final: {source_name} ({len(rows)} rows, {len(filtered_rows)} after {min_severity}+ filter)", "info")
                        else:
                            add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Final: {source_name} ({len(rows)} rows)", "info")
                    else:
                        # Multi-client merge: keep other clients' rows,
                        # replace this client's with the latest filtered set.
                        existing_other_clients = [
                            r for r in all_results[source_name]
                            if isinstance(r, dict) and r.get('_client_id') != client_id
                        ]
                        all_results[source_name] = existing_other_clients + filtered_rows
                        add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Final: {source_name} ({len(filtered_rows)} rows added — total now {len(all_results[source_name])})", "info")

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

    # Return whether we timed out (vs completed naturally)
    timed_out = elapsed >= total_seconds
    return all_results, summaries, timed_out, total_rows_before_filter


