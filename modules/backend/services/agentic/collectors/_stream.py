#!/usr/bin/env python3
"""
Agentic Collectors - Velociraptor artifact collection logic
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection
from services.workflow_service import add_log_to_run
from services.agentic.collectors._base import *  # noqa: F401,F403

def stream_collect_and_analyze(run_id, collection_results, artifacts, collection_minutes, update_phase_func=None, cancel_event=None):
    """Monitor a collection: poll artifact sources, retrieve/merge rows as flows
    complete. Returns (all_results, timed_out).

    Pure collection — rows are persisted as-is for Case-level fusion, which owns
    all filtering (time window, severity) and analysis. `timed_out` is True if
    collection ended due to timeout, False if all flows completed naturally."""
    total_seconds = collection_minutes * 60
    elapsed = 0
    interval = 30  # Check every 30 seconds

    # Track state
    completed_flows = set()
    all_results = {}  # artifact -> [rows] (combined from all clients)
    poll_count = 0
    # The log used to trace every per-source transition — "Discovered
    # source: X", then "Found: X (N rows)" again on every poll where X grew,
    # then "X stable (N rows)" once it stopped. A fast-writing artifact
    # (Windows.Hayabusa.Rules on a busy host writes on nearly every 30s poll)
    # re-announced the SAME source five or more times in one run, each line
    # showing a bigger count, none of it telling the operator anything the
    # aggregate line below doesn't already say every cycle. Collapsed to one
    # "still running" line with the running total, at roughly this cadence
    # rather than every poll — polling itself stays at `interval` so flow
    # completion is still noticed promptly; only the LOG volume is throttled.
    HEARTBEAT_EVERY_N_POLLS = max(1, 60 // interval)

    # Get active flows
    active_flows = [c for c in collection_results if c.get('flow_id')]
    if not active_flows:
        add_log_to_run(run_id, "[Velociraptor] No active flows to monitor", "warning")
        return all_results, False

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
        return all_results, False

    add_log_to_run(run_id, f"[Velociraptor] Streaming mode: polling {len(artifacts)} artifacts across {len(active_flows)} clients", "info")
    add_log_to_run(run_id, f"[Velociraptor] Streaming collection — results retrieved as artifacts complete", "info")

    # Register cleanup callbacks for stop support
    from services.workflow_service import register_cleanup
    register_cleanup(run_id, lambda: cancel_collections(run_id, active_flows))

    # Track discovered sources (including sub-artifacts)
    discovered_sources = {}  # flow_id -> set of source names

    try:
        while elapsed < total_seconds:
            # Check for cancellation
            if cancel_event and cancel_event.is_set():
                add_log_to_run(run_id, "[Velociraptor] Collection cancelled by user", "warning")
                break

            poll_count += 1

            # Poll each flow for available data
            for col in active_flows:
                client_id = col.get('client_id')
                flow_id = col.get('flow_id')
                if not flow_id:
                    continue

                # Enumerate all available sources in this flow (includes
                # sub-artifacts) and just track them — no per-source log; see
                # the heartbeat comment above for why.
                discovered_sources.setdefault(flow_id, set())
                discovered_sources[flow_id].update(enumerate_flow_sources(stub, client_id, flow_id))

                # Query every discovered source and merge in whatever is
                # available. No growth/stability bookkeeping: each poll just
                # replaces THIS client's rows with its latest fetch, so a
                # partial early fetch is naturally superseded by a fuller one
                # next poll — nothing to track to get that for free.
                client_hostname = _name(client_id)
                for source_name in discovered_sources[flow_id]:
                    rows = query_artifact_results(stub, client_id, flow_id, source_name)
                    if not rows:
                        continue

                    # Tag every row with _client_id + _hostname — the
                    # multi-client merge below relies on this to keep each
                    # client's rows distinct. Without it, one client's poll
                    # would wipe out another client's rows for the same
                    # source.
                    for r in rows:
                        if isinstance(r, dict):
                            r.setdefault('_client_id', client_id)
                            r.setdefault('_hostname', client_hostname)

                    # Multi-client merge: keep rows from OTHER clients,
                    # replace this client's rows with its latest fetch.
                    existing_other_clients = [
                        r for r in all_results.get(source_name, [])
                        if isinstance(r, dict) and r.get('_client_id') != client_id
                    ]
                    all_results[source_name] = existing_other_clients + rows

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

            # Check if all flows are done
            all_flows_completed = len(completed_flows) == len(active_flows)
            if all_flows_completed:
                add_log_to_run(run_id, f"[Velociraptor] All {len(active_flows)} flows completed!", "success")
                break

            # `remaining` feeds both the sleep below and the heartbeat text,
            # so it's computed every poll regardless of whether the
            # heartbeat itself is due this cycle.
            remaining = total_seconds - elapsed

            # Progress bar updates every poll — unrelated to log volume, no
            # reason to throttle it along with the text heartbeat below.
            collection_progress = 10 + int((elapsed / total_seconds) * 40)
            if update_phase_func:
                update_phase_func(run_id, "collecting", collection_progress)

            # The heartbeat itself: throttled to roughly once a minute (see
            # HEARTBEAT_EVERY_N_POLLS above), not logged every `interval`.
            if poll_count % HEARTBEAT_EVERY_N_POLLS == 0:
                remaining_min = remaining // 60
                remaining_sec = remaining % 60
                total_sources = sum(len(srcs) for srcs in discovered_sources.values())
                total_rows = sum(len(r) for r in all_results.values())

                add_log_to_run(run_id,
                    f"[Velociraptor] Still running — {remaining_min}m {remaining_sec}s left | "
                    f"{len(all_results)}/{total_sources} sources | {total_rows} rows so far",
                    "info")

                # Per-client breakdown (multi-client only) so the operator
                # can see each host's progress independently — the aggregate
                # line above merges everything, which with N>1 hides whether
                # one host is stuck while others march on.
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

                    if source_name not in all_results:
                        all_results[source_name] = rows
                        add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Final: {source_name} ({len(rows)} rows)", "info")
                    else:
                        # Multi-client merge: keep other clients' rows,
                        # replace this client's with the latest set.
                        existing_other_clients = [
                            r for r in all_results[source_name]
                            if isinstance(r, dict) and r.get('_client_id') != client_id
                        ]
                        all_results[source_name] = existing_other_clients + rows
                        add_log_to_run(run_id, f"[Velociraptor] [{client_hostname}] Final: {source_name} ({len(rows)} rows added — total now {len(all_results[source_name])})", "info")

        # Report what was RETRIEVED, and say plainly whether the flows had
        # actually finished. This used to log "Collection complete" in green
        # unconditionally — including when the loop had just fallen out on the
        # deadline — so the run log read:
        #
        #   Collection complete: 9 sources, 389 rows        (success)
        #   Collection timed out - stopping remaining...    (warning)
        #
        # Both true, but "complete" claimed something never checked, and the
        # green line landed immediately before the timeout. `elapsed` is right
        # here, so the outcome is knowable at the point of logging rather than
        # one caller later.
        total_rows = sum(len(r) for r in all_results.values())
        if elapsed >= total_seconds:
            # "so far" is load-bearing: the flows are NOT cancelled when the
            # window closes (see pipeline/_runners.py), so they keep writing in
            # Velociraptor after this line. This is the snapshot that gets fused,
            # not the final size of the collection.
            add_log_to_run(
                run_id,
                f"[Velociraptor] Collection window closed — retrieved "
                f"{len(all_results)} source(s), {total_rows} row(s) so far. "
                f"Flows still running are left to finish in Velociraptor.",
                "warning")
        else:
            add_log_to_run(
                run_id,
                f"[Velociraptor] All flows finished — retrieved "
                f"{len(all_results)} source(s), {total_rows} row(s)",
                "success")

    finally:
        if channel:
            channel.close()

    # Return whether we timed out (vs completed naturally)
    timed_out = elapsed >= total_seconds
    return all_results, timed_out
