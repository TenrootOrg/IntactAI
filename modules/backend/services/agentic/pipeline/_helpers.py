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
# pipeline may keep running for synthesis / report generation / IRIS
# import before we force-kill it. The QA hang sat at "running" for
# nearly an hour with no upper bound — this is the absolute backstop
# even if every other safety check misses.
from services.file_storage_service import get_agentic_blueprint, get_workflow, save_workflow
from services.data_anonymizer import DataAnonymizer

from services.agentic.collectors import (
    create_collections,
    stream_collect_and_analyze,
    cancel_collections
)
from services.agentic.reports import (
    generate_empty_report,
    save_report_content,
    persist_pipeline_artifacts,
)
from services.agentic.utils import extract_timeline_events, filter_malicious_events

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
            add_log_to_run(
                run_id,
                f"[Pipeline] Watchdog: {label} pipeline exceeded "
                f"{deadline}s — forcing cancellation",
                "error",
            )
            request_stop(run_id)
        except Exception:
            pass

    t = threading.Timer(deadline, _fire)
    t.daemon = True
    t.start()
    return t

def _collect_only_report(total_rows, all_results, client_count) -> str:
    """Deterministic report when no LLM is configured — states what was collected and
    points the operator at the Case fusion path for LLM-free findings."""
    arts = ", ".join(sorted(all_results.keys())) if all_results else "(none)"
    return (
        "# Collection complete — no LLM analysis\n\n"
        f"Collected **{total_rows} rows** across **{len(all_results)} artifact(s)** from "
        f"**{client_count} client(s)**.\n\n"
        "No LLM is configured, so per-artifact AI analysis and the narrative report were "
        "skipped. **This run is fully usable**: fuse it into a **Case** (Cases UI / "
        "`/api/cases`) to get deterministic, LLM-free correlation, findings, timeline, and "
        "interactive chat.\n\n"
        f"**Artifacts collected:** {arts}\n"
    )


def _update_phase(run_id, phase, progress):
    """Update workflow with current phase and progress"""
    workflow = get_workflow(run_id)
    if workflow:
        workflow['phase'] = phase
        workflow['progress'] = progress
        save_workflow(workflow)


