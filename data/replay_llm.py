#!/usr/bin/env python3
"""
Replay LLM stages of an Azure scan against already-collected data.

Reuses the cached collected_data + findings from a prior workflow JSON
and runs ONLY analyze_artifacts + generate_azure_report. Persists output
under a fresh run_id so the original is untouched.

Run inside the backend container:
    docker exec intact_backend python3 /app/data/replay_llm.py
"""

import json
import os
import sys
import time
from datetime import datetime

# Source run to replay. Override via argv: python3 replay_llm.py <run_id>
SOURCE_RUN = sys.argv[1] if len(sys.argv) > 1 else "azure_scan_1778068979121"
SOURCE_JSON = f"/app/data/azure_runs/{SOURCE_RUN}.json"

sys.path.insert(0, "/app")

from services.workflow_service import (
    create_automation_run,
    update_run_status,
    add_log_to_run,
    record_phase_timing,
)
from services.agentic.analyzers import analyze_artifacts
from services.agentic.utils import normalize_all_results
from services.azure.reports import generate_azure_report, save_azure_report
from services.file_storage_service import load_frontend_config


def main():
    if not os.path.exists(SOURCE_JSON):
        print(f"FATAL: source not found: {SOURCE_JSON}")
        sys.exit(1)

    src = json.load(open(SOURCE_JSON))
    collected_data = src.get("collected_data") or {}
    findings = src.get("findings") or {}
    if not findings:
        print("FATAL: source has no findings — nothing to analyze")
        sys.exit(1)

    total_rows = sum(len(v) for v in findings.values())
    print(f"Replaying analysis for {SOURCE_RUN}")
    print(f"  sources: {[(k, len(v)) for k, v in collected_data.items()]}")
    print(f"  finding buckets: {len(findings)} ({total_rows} total finding rows)")

    # New run_id with distinct prefix so it's easy to spot in the dashboard
    # Use automation_type=azure_scan so the dashboard's Report/Data buttons
    # render correctly; the trigger field marks this as a replay for audit.
    rid = create_automation_run(
        automation_type="azure_scan",
        name=f"Azure LLM Replay of {SOURCE_RUN}",
        details={
            "trigger": "replay-script",
            "source_run": SOURCE_RUN,
        },
    )
    print(f"new run_id: {rid}")
    update_run_status(rid, "running", progress=10)
    add_log_to_run(rid, f"[REPLAY] Replaying LLM stages of {SOURCE_RUN}", "info")
    add_log_to_run(rid, f"[REPLAY] Source data: {sum(len(v) for v in collected_data.values())} records across {len(collected_data)} sources, {len(findings)} finding buckets", "info")

    # Normalize timestamps in both the source records and the findings
    # (matched_record references). Mirrors the live pipeline's behaviour
    # so the LLM sees consistent "YYYY-MM-DD HH:MM:SS" strings everywhere.
    try:
        normalize_all_results(collected_data)
        normalize_all_results(findings)
        add_log_to_run(rid, "[REPLAY] Normalized timestamps in collected_data + findings", "info")
    except Exception as ex:
        add_log_to_run(rid, f"[REPLAY] Timestamp normalization failed (non-fatal): {ex}", "warning")

    # ---- Analysis ----
    add_log_to_run(rid, "[AZURE] Phase 5: Running LLM analysis...", "info")
    update_run_status(rid, "running", progress=40)
    t0 = time.monotonic()
    llm_config = load_frontend_config() or {}
    try:
        analysis_results = analyze_artifacts(
            run_id=rid,
            all_results=findings,
            llm_config=llm_config,
            anonymizer=None,
            pipeline_kind="azure",
        )
        record_phase_timing(rid, "analysis", time.monotonic() - t0)
        add_log_to_run(rid, f"[AZURE] LLM analysis complete: {len(analysis_results)} summaries", "info")
    except Exception as ex:
        add_log_to_run(rid, f"[AZURE] LLM analysis failed: {ex}", "error")
        update_run_status(rid, "failed", error=str(ex))
        print(f"FAILED at analyze_artifacts: {ex}")
        raise

    # ---- Reporting ----
    add_log_to_run(rid, "[AZURE] Phase 6: Generating reports...", "info")
    update_run_status(rid, "running", progress=85)
    t1 = time.monotonic()
    try:
        # Find the original blueprint/tenant if we can guess; otherwise use stubs
        scan_metadata = {
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "time_filter": {"type": "relative", "value": "24h"},
            "sources": list(collected_data.keys()),
        }
        blueprint = {"name": "Azure Full Investigation (replayed)", "id": "azure_full_investigation"}
        reports = generate_azure_report(
            run_id=rid,
            blueprint=blueprint,
            collected_data=collected_data,
            findings=findings,
            analysis_results=analysis_results,
            llm_config=llm_config,
            scan_metadata=scan_metadata,
        )
        record_phase_timing(rid, "reporting", time.monotonic() - t1)
        save_azure_report(rid, reports)
        add_log_to_run(rid, "[AZURE] Reports generated successfully", "success")
    except Exception as ex:
        add_log_to_run(rid, f"[AZURE] Report generation failed: {ex}", "error")
        update_run_status(rid, "failed", error=str(ex))
        print(f"FAILED at generate_azure_report: {ex}")
        raise

    update_run_status(rid, "completed", progress=100, details={"has_report": True})
    print(f"DONE — replay run_id: {rid}")
    print(f"  inspect: curl http://localhost:5001/api/dashboard/automation/{rid}")


if __name__ == "__main__":
    main()
