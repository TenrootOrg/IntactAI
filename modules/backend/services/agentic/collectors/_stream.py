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
    # WALL CLOCK, not a tally of intervals.
    #
    # `elapsed` used to be incremented by `interval` once per loop, on the
    # assumption that a loop takes about `interval`. It does not: each iteration
    # also fetches results, and that got slower as data accumulated. Measured on
    # a QA appliance 2026-08-26, the gaps between "one minute" heartbeats ran
    # 75s, 130s, 139s, 205s, 287s — so the pipeline believed 7m30s had passed
    # when 22m10s had. A 10-minute collection therefore sailed past the
    # 25-minute watchdog and was killed.
    #
    # The incremental fetch above removes the cause; this removes the fiction.
    # "10 minutes" now means ten minutes however long the polls take, so the
    # collection window is a promise the loop can keep and the watchdog
    # (window + 15 min) stops being reachable by drift.
    _started_at = time.monotonic()
    elapsed = 0
    interval = 30  # Check every 30 seconds

    # Track state
    completed_flows = set()
    # AN ERRORED FLOW IS STILL RUNNING.
    #
    # Velociraptor sets a flow's state to ERROR the moment ANY artifact in it
    # errors — the remaining artifacts keep collecting, and the state never
    # becomes FINISHED afterwards. Treating ERROR as terminal is therefore not a
    # status-mapping detail, it throws away evidence: measured on QA's run
    # 2026-08-25 (flow F.DA6NFH7FCBNS0), one stock artifact's VQL failed
    # ("Symbol CommandLine not found"), we quit 34s in, and Velociraptor's own
    # flow record shows it stayed active for 290.83s — 4m17s of a 30-minute
    # collection discarded, and the run still reported COMPLETED.
    #
    # So for an errored flow the state cannot be the completion signal. PROGRESS
    # is: it is finished when it stops producing. Each poll fingerprints what the
    # flow has yielded (sources + rows); IDLE_POLLS_BEFORE_DONE consecutive polls
    # with no change means it has genuinely stopped, and the operator's time
    # budget remains the outer bound either way.
    errored_flows = {}        # flow_id -> {"fingerprint": tuple, "idle": int}
    IDLE_POLLS_BEFORE_DONE = 3
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

    _flow_owner = {c.get('flow_id'): c.get('client_id')
                   for c in collection_results if c.get('flow_id')}

    def _name_for_flow(fid):
        return _name(_flow_owner.get(fid, fid))

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
    # Rows already retrieved, keyed (client_id, source). The next poll asks
    # Velociraptor to skip exactly this many.
    #
    # PER CLIENT, not per source, and that matters: a hunt-shaped collection has
    # several flows writing the same artifact, and a shared offset would have one
    # host's progress skip past another host's rows.
    #
    # Counted from what we RECEIVED, never from what we asked for. A fetch cut
    # short by the query timeout therefore leaves the offset where the data
    # really ends, and the next poll resumes from there instead of stepping over
    # a gap. That also removes the old "row count went backwards" symptom
    # (479,334 -> 455,315 in a real run): rows are appended now, never replaced,
    # so a short read can no longer delete rows we already had.
    fetched_offsets = {}     # (client_id, source_name) -> int

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
                    _key = (client_id, source_name)
                    _seen = fetched_offsets.get(_key, 0)
                    rows = query_artifact_results(stub, client_id, flow_id,
                                                  source_name, start_row=_seen)
                    if not rows:
                        continue
                    fetched_offsets[_key] = _seen + len(rows)

                    # Tag every row with _client_id + _hostname — the
                    # multi-client merge below relies on this to keep each
                    # client's rows distinct. Without it, one client's poll
                    # would wipe out another client's rows for the same
                    # source.
                    for r in rows:
                        if isinstance(r, dict):
                            r.setdefault('_client_id', client_id)
                            r.setdefault('_hostname', client_hostname)

                    # APPEND the tail. This used to rebuild the source by
                    # keeping other clients' rows and REPLACING this client's
                    # with its latest full fetch — which is why every poll had to
                    # re-download everything. With start_row the fetch returns
                    # only what is new, so it is added to what is already there.
                    all_results.setdefault(source_name, [])
                    all_results[source_name].extend(rows)

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
                    # NOT added to completed_flows — see the note above. The
                    # warning is logged ONCE (this branch is now reached on every
                    # subsequent poll too, and repeating it every 30s for the rest
                    # of a 30-minute collection would bury the log).
                    first_time = flow_id not in errored_flows
                    errored_flows.setdefault(flow_id, {"fingerprint": None, "idle": 0})
                    if not first_time:
                        continue
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

            # An errored flow is done when it stops producing. Fingerprint what
            # each one has yielded so far; unchanged for IDLE_POLLS_BEFORE_DONE
            # consecutive polls means it has finished as far as it ever will.
            for fid, st in errored_flows.items():
                if fid in completed_flows:
                    continue
                srcs = discovered_sources.get(fid, set())
                fp = (len(srcs), sum(len(all_results.get(sn) or []) for sn in srcs))
                if fp == st["fingerprint"]:
                    st["idle"] += 1
                else:
                    st["fingerprint"] = fp
                    st["idle"] = 0
                if st["idle"] >= IDLE_POLLS_BEFORE_DONE:
                    completed_flows.add(fid)
                    add_log_to_run(
                        run_id,
                        f"[Velociraptor] {_name_for_flow(fid)}: flow stopped producing "
                        f"after its error — {fp[0]} source(s), {fp[1]} row(s) collected",
                        "info")

            # Check if all flows are done
            all_flows_completed = len(completed_flows) == len(active_flows)
            if all_flows_completed:
                add_log_to_run(run_id, f"[Velociraptor] All {len(active_flows)} flows completed!", "success")
                break

            # `remaining` feeds both the sleep below and the heartbeat text,
            # so it's computed every poll regardless of whether the
            # heartbeat itself is due this cycle.
            remaining = int(max(0, total_seconds - elapsed))

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

            sleep_time = max(0, min(interval, remaining))
            if cancel_event:
                cancel_event.wait(timeout=sleep_time)
            else:
                time.sleep(sleep_time)
            elapsed = time.monotonic() - _started_at

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
                # The TAIL, not the whole thing. This pass exists to pick up
                # whatever landed after the last poll, and re-downloading every
                # source in full to do that is what made the closing phase of a
                # large collection take minutes per artifact — on a QA run the
                # watchdog fired 32 seconds into it and destroyed the lot.
                _key = (client_id, source_name)
                _seen = fetched_offsets.get(_key, 0)
                rows = query_artifact_results(stub, client_id, flow_id,
                                              source_name, start_row=_seen)
                if rows:
                    fetched_offsets[_key] = _seen + len(rows)
                    # Tag rows for per-client attribution (same as main poll loop)
                    for r in rows:
                        if isinstance(r, dict):
                            r.setdefault('_client_id', client_id)
                            r.setdefault('_hostname', client_hostname)

                    all_results.setdefault(source_name, [])
                    all_results[source_name].extend(rows)
                    add_log_to_run(
                        run_id,
                        f"[Velociraptor] [{client_hostname}] Final: {source_name} "
                        f"({len(rows)} new — total now {len(all_results[source_name])})",
                        "info")

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
            # Just the count. The caller (pipeline/_runners.py) logs the one line
            # explaining the time limit and that flows continue in Velociraptor —
            # restating it here was part of the five-near-identical-messages pile
            # that made a normal outcome look alarming. "so far" is kept because
            # flows are not cancelled, so this total really is provisional.
            add_log_to_run(
                run_id,
                f"[Velociraptor] Collection window closed — retrieved "
                f"{len(all_results)} source(s), {total_rows} row(s) so far",
                "info")
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
