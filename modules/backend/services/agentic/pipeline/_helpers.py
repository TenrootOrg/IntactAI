#!/usr/bin/env python3
"""
Agentic Pipeline - Main orchestration for forensics analysis pipeline
"""
import threading

from services.workflow_service import add_log_to_run, request_stop
from services.file_storage_service import get_workflow, save_workflow

_PIPELINE_SYNTHESIS_GRACE_SECONDS = 15 * 60  # 15 minutes

def _start_watchdog(run_id: str, collection_minutes: int, label: str = "agentic"):
    """Start a threading.Timer that calls request_stop(run_id) if the
    pipeline outlives `collection_minutes * 60 + grace`. The cancel
    event then propagates through every loop in collectors.py and
    pipeline.py exits via its existing `except`. Returns the Timer
    so the caller can .cancel() it in the finally block."""
    deadline = max(int(collection_minutes), 1) * 60 + _PIPELINE_SYNTHESIS_GRACE_SECONDS

    def _fire():
        # Log loudly so the operator sees this in the run log instead
        # of just a status flip.
        try:
            _why = (f"Watchdog: the {label} pipeline exceeded its budget of "
                    f"{deadline}s ({collection_minutes} min collection window + "
                    f"{_PIPELINE_SYNTHESIS_GRACE_SECONDS // 60} min grace) and was "
                    f"stopped. Whatever had been collected by then is saved — use "
                    f"Fetch results to pick up the rest.")
            add_log_to_run(run_id, f"[Pipeline] {_why}", "error")
            request_stop(run_id, reason=_why)
        except Exception:
            pass

    t = threading.Timer(deadline, _fire)
    t.daemon = True
    t.start()
    return t

def _collect_only_report(total_rows, all_results, client_count) -> str:
    """Completion report for a collection run — states what was collected and
    points the operator at fusion (Case Analysis) for the actual analysis."""
    arts = ", ".join(sorted(all_results.keys())) if all_results else "(none)"
    return (
        "# Collection complete\n\n"
        f"Collected **{total_rows} rows** across **{len(all_results)} artifact(s)** from "
        f"**{client_count} client(s)**.\n\n"
        "Fuse this run into a **Case** to get correlation, findings, and a timeline.\n\n"
        f"**Artifacts collected:** {arts}\n"
    )


def _update_phase(run_id, phase, progress):
    """Update workflow with current phase and progress"""
    workflow = get_workflow(run_id)
    if workflow:
        workflow['phase'] = phase
        workflow['progress'] = progress
        save_workflow(workflow)


