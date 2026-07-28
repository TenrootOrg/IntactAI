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
    cancel_collections,
    persist_pipeline_artifacts,
)
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

        # 4. Cancel any remaining collections ONLY if we timed out
        if timed_out:
            add_log_to_run(
                run_id,
                f"[Velociraptor] {collection_minutes}m collection window reached "
                f"— stopping flows that are still running...", "warning")
            cancel_collections(run_id, success_collections)
        else:
            add_log_to_run(run_id, "[Velociraptor] All flows completed naturally", "success")

        # Say which of the two things happened. A timed-out collection is
        # PARTIAL: the rows are whatever the clients had written when the
        # window closed, not a finished collection. Calling that "complete"
        # (in green, right after a timeout warning) is what made the log read
        # as self-contradictory, and it hid the one fact the operator needs —
        # that the result is truncated and the window was too short.
        total_rows = sum(len(rows) for rows in all_results.values())
        if timed_out:
            add_log_to_run(
                run_id,
                f"[Pipeline] Collection PARTIAL: {total_rows} row(s) across "
                f"{len(all_results)} artifact(s) — the {collection_minutes}m window "
                f"closed before every flow finished. Raise Collection Time for "
                f"this blueprint to collect it fully.", "warning")
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
