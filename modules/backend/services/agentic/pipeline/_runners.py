#!/usr/bin/env python3
"""
Agentic Pipeline - Main orchestration for forensics analysis pipeline
"""
import threading
import traceback
from datetime import datetime

from services.workflow_service import (
    add_log_to_run,
    update_run_status,
    is_cancelled,
    unregister_cancel,
    request_stop,
)


# Outer watchdog grace period: how long after the collection window the
# pipeline may keep running for synthesis / report generation before we
# force-kill it. The QA hang sat at "running" for nearly an hour with no
# upper bound — this is the absolute backstop even if every other safety
# check misses.
from services.file_storage_service import get_agentic_blueprint, get_workflow, save_workflow

from services.agentic.collectors import (
    create_collections,
    stream_collect_and_analyze,
    persist_pipeline_artifacts,
)
# cancel_collections is deliberately NOT imported here any more. The pipeline no
# longer cancels flows when the collection window closes — see the note at the
# timeout branch below. The only remaining canceller is the cleanup callback
# _stream.py registers for a user-requested Stop.
from services.agentic.pipeline._helpers import *  # noqa: F401,F403
from services.agentic.pipeline._helpers import (_start_watchdog, _update_phase, _PIPELINE_SYNTHESIS_GRACE_SECONDS)  # underscore members

def run_agentic_pipeline(run_id, blueprint_id, client_ids, collection_minutes, cancel_event=None):
    """Background thread: full agentic forensics pipeline (collection-only —
    the run gathers artifacts and is then fused into a Case for analysis)."""
    # Outer watchdog — the absolute backstop. Even if every other
    # safety check misses, the run cannot exceed
    # `collection_minutes + 15min synthesis grace`. See QA hang
    # context: pipeline stayed "running" for ~1 hour after the LLM
    # died because no outer timeout bounded the total wall-clock.
    _watchdog = _start_watchdog(run_id, collection_minutes, label="agentic")

    try:
        update_run_status(run_id, "running", progress=2)
        add_log_to_run(run_id, "[Collection] Starting Velociraptor collection", "info")
        add_log_to_run(run_id,
            "[Collection] Gathering artifacts — fuse this run into a Case for analysis.",
            "info")

        workflow = get_workflow(run_id)

        # Hostnames are stashed in workflow.details by agentic_routes when
        # the run is created (resolve_hostnames is called there so the
        # workflow name in the Workflows tab carries readable names from
        # the moment the row appears). Pull the same map here so the
        # report header + macro citations show those names instead of the
        # bare client_ids.
        hostnames = {}
        if workflow:
            details = workflow.get('details') or {}
            hostnames = details.get('hostnames') or {}
        if not hostnames:
            # Fallback: re-resolve. Cheap (one VQL call) and keeps this
            # pipeline robust against older runs that pre-date the route
            # change.
            try:
                from services.agentic.collectors import resolve_hostnames as _resolve_hn
                hostnames = _resolve_hn(client_ids)
            except Exception:
                hostnames = {cid: cid for cid in client_ids}

        # 1. Get blueprint
        blueprint = get_agentic_blueprint(blueprint_id)
        if not blueprint:
            add_log_to_run(run_id, f"[Pipeline] Blueprint '{blueprint_id}' not found", "error")
            update_run_status(run_id, "failed", progress=0, error="Blueprint not found")
            return

        artifacts = blueprint.get('artifacts', [])
        settings = blueprint.get('settings', {}).copy()  # Copy to avoid mutating blueprint

        add_log_to_run(run_id, f"[Pipeline] Blueprint: {blueprint.get('name')} ({len(artifacts)} artifacts)", "info")
        add_log_to_run(run_id, f"[Pipeline] Clients: {len(client_ids)} selected", "info")
        add_log_to_run(run_id, f"[Pipeline] Collection time: {collection_minutes} minutes", "info")
        # 2. Create collections on selected clients
        add_log_to_run(run_id, "[Velociraptor] Creating collections on selected clients...", "info")
        _update_phase(run_id, "creating_collections", 5)

        if cancel_event and cancel_event.is_set():
            return

        collection_results = create_collections(run_id, artifacts, settings, client_ids)
        success_collections = [c for c in collection_results if c['flow_id']]
        add_log_to_run(run_id, f"[Velociraptor] Created {len(success_collections)}/{len(client_ids)} collections ({len(artifacts)} artifacts each)", "info")

        # Persist the flow IDs back into workflow.details so a future
        # Full re-analysis (from the Interactive chat panel) can fetch
        # the same data without launching a new collection.
        try:
            launched_flow_ids = [c['flow_id'] for c in success_collections if c.get('flow_id')]
            if launched_flow_ids:
                _wf = get_workflow(run_id)
                if _wf is not None:
                    _wd = _wf.get('details') or {}
                    if not isinstance(_wd, dict):
                        _wd = {}
                    _wd['flow_id'] = launched_flow_ids if len(launched_flow_ids) > 1 else launched_flow_ids[0]
                    _wf['details'] = _wd
                    save_workflow(_wf)
        except Exception as _e:
            # Best-effort — re-analysis falls back to "unavailable" if
            # the stash misses; doesn't break the main pipeline.
            print(f"[PIPELINE] Failed to stash flow_ids on {run_id}: {_e}", flush=True)

        if not success_collections:
            add_log_to_run(run_id, "[Velociraptor] No collections were created successfully", "error")
            update_run_status(run_id, "failed", progress=0, error="Failed to create any collections")
            return

        if cancel_event and cancel_event.is_set():
            return

        # 3. Stream-collect: monitor flows, retrieve results as they become available.
        add_log_to_run(run_id, f"[Velociraptor] Collecting data for up to {collection_minutes} minutes...", "info")
        _update_phase(run_id, "collecting", 10)
        all_results, timed_out = stream_collect_and_analyze(
            run_id, success_collections, artifacts, collection_minutes, _update_phase, cancel_event,
        )

        # 4. The window is a deadline for US, not for the endpoints.
        #
        # This used to cancel_collections() on timeout, which killed flows that
        # were still writing. Collection Time is meant to bound how long the
        # pipeline WAITS before snapshotting and handing off to fusion — not to
        # truncate work already running on a host. Cancelling threw away
        # everything a slow client had left to send, and on a big artifact set
        # that is most of it, so the operator paid the collection cost and got a
        # fraction of the data with no way to recover it short of re-running the
        # whole hunt.
        #
        # Now the flows are left alone: they run to completion in Velociraptor
        # and their full output stays queryable there. Note the consequence,
        # because it is not obvious — persist_pipeline_artifacts() below snapshots
        # what was retrieved BY THIS POINT, so rows a flow writes after the window
        # do not reach this run's Case. They are in Velociraptor, not lost.
        #
        # A user-requested Stop still cancels the flows: _stream.py registers
        # cancel_collections as a cleanup callback, and cleanups run only from
        # stop_workflow() — never on normal completion.
        if timed_out:
            add_log_to_run(
                run_id,
                f"[Velociraptor] {collection_minutes}m collection window reached "
                f"— taking a snapshot for analysis. Flows that are still running "
                f"are NOT cancelled; they will finish in Velociraptor.", "warning")
        else:
            add_log_to_run(run_id, "[Velociraptor] All flows completed naturally", "success")

        # Say which of the two things happened. A timed-out run yields a
        # SNAPSHOT: the rows are whatever the clients had written when the window
        # closed, not a finished collection. Calling that "complete" (in green,
        # right after a timeout warning) is what made the log read as
        # self-contradictory, and it hid the one fact the operator needs — that
        # this Case sees less than the collection will ultimately produce.
        #
        # The remedy is no longer only "raise Collection Time": because the flows
        # are no longer cancelled, the missing rows are still being written and
        # are queryable in Velociraptor. Say both, so the operator knows the data
        # exists rather than assuming it was lost.
        total_rows = sum(len(rows) for rows in all_results.values())
        if timed_out:
            add_log_to_run(
                run_id,
                f"[Pipeline] Collection SNAPSHOT: {total_rows} row(s) across "
                f"{len(all_results)} artifact(s) — the {collection_minutes}m window "
                f"closed before every flow finished, so this is what will be fused. "
                f"The flows keep running in Velociraptor and their full output stays "
                f"available there. Raise Collection Time to capture more of it in "
                f"the run itself.", "warning")
        else:
            add_log_to_run(
                run_id,
                f"[Pipeline] Collection complete: {total_rows} total rows across "
                f"{len(all_results)} artifacts", "success")

        if total_rows == 0:
            # No data at all from Velociraptor — this IS a fatal outcome, not
            # a recoverable warning. Promote the logs to 'error' level so the
            # auto-flip in workflow_service picks it up AND the operator sees
            # red, AND set status to 'failed' explicitly so future readers
            # don't have to chase through the auto-flip logic.
            add_log_to_run(run_id, "[Pipeline] No data was returned from the selected clients. Possible causes:", "error")
            add_log_to_run(run_id, "  - Collection time too short - try increasing it", "error")
            add_log_to_run(run_id, "  - Artifacts not applicable to this system - try a different blueprint", "error")
            add_log_to_run(run_id, "  - Clients may be offline - verify client status in Velociraptor", "error")
            update_run_status(
                run_id, "failed", progress=0,
                error="No data returned from selected clients during collection window",
            )
            return

        if cancel_event and cancel_event.is_set():
            return

        if timed_out:
            add_log_to_run(
                run_id,
                f"[Collection] {total_rows} rows across {len(all_results)} artifacts "
                f"captured in the {collection_minutes}m window — fuse this run into a "
                f"Case for analysis. The collection is STILL RUNNING in Velociraptor "
                f"and will finish there on its own.", "info")
        else:
            add_log_to_run(run_id, f"[Collection] {total_rows} rows across "
                           f"{len(all_results)} artifacts collected — fuse this run into a "
                           f"Case for analysis.", "info")
        _update_phase(run_id, "report_ready", 85)

        if cancel_event and cancel_event.is_set():
            return

        # Save raw row data for fusion to read. Cheap to write, best-effort:
        # failures are logged but don't fail the pipeline.
        try:
            persist_pipeline_artifacts(run_id, all_results)
        except Exception as _e:
            print(f"[AGENTIC] persist_pipeline_artifacts failed (non-fatal): {_e}", flush=True)

        _update_phase(run_id, "completed", 100)
        # Do not claim the COLLECTION finished when only the RUN did.
        #
        # This line used to be an unconditional green "Collection complete", which
        # on a timed-out run directly contradicted the warning a few lines above:
        # the window closed early, the flows were left running (see the timeout
        # branch), and Velociraptor is demonstrably still collecting. An operator
        # who set 1 minute saw "Collection complete" and reasonably concluded that
        # was all the data there would ever be.
        #
        # The run status stays 'completed' on purpose — the PIPELINE did finish its
        # work, and anything else would leave a row spinning in the UI forever.
        # Only the wording is corrected, because that is what was untrue.
        if timed_out:
            add_log_to_run(
                run_id,
                f"[Collection] Run finished — {total_rows} row(s) snapshotted for "
                f"fusion. NOT the full collection: the {collection_minutes}m window "
                f"ended first and the flows are still running in Velociraptor. "
                f"Check them there, or re-run with a longer Collection Time to "
                f"capture more in the Case.", "warning")
        else:
            add_log_to_run(run_id, "[Collection] Collection complete — fuse into a Case for analysis.", "success")
        if not is_cancelled(run_id):
            update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        if is_cancelled(run_id):
            return  # Stop was requested, don't overwrite cancelled status
        error_msg = f"[Pipeline] Error: {str(e)}"
        print(f"[AGENTIC] {error_msg}", flush=True)
        traceback.print_exc()
        add_log_to_run(run_id, error_msg, "error")
        add_log_to_run(run_id, traceback.format_exc(), "error")
        update_run_status(run_id, "failed", error=str(e))
    finally:
        try:
            _watchdog.cancel()
        except Exception:
            pass
        unregister_cancel(run_id)
