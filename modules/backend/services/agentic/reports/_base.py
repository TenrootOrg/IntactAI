#!/usr/bin/env python3
"""
Agentic Reports — collect-only surface.

The agentic Velociraptor pipeline is collect-only: analysis + narrative
reporting happen at the Case Analysis (fusion) layer, not per-run. What
remains here is the small set of helpers the live collection path still
needs — client-row filtering, the empty-data placeholder, run-result
storage, and raw-artifact persistence that fusion reads to build the case
graph. The former LLM report engine (_generate.py) has been removed.
"""

import json
import os
from datetime import datetime

from services.file_storage_service import save_report


def filter_results_by_client(all_results, client_id):
    """Filter artifact results to only include rows from a specific client.

    Args:
        all_results: Dict of artifact_name -> list of rows (each row has _client_id)
        client_id: The client ID to filter for

    Returns:
        Dict of artifact_name -> filtered list of rows for this client only
    """
    filtered = {}
    for artifact_name, rows in all_results.items():
        client_rows = [row for row in rows if row.get('_client_id') == client_id]
        if client_rows:
            filtered[artifact_name] = client_rows
    return filtered


def generate_empty_report(blueprint, client_ids, collection_minutes):
    """Generate report when no data was collected"""
    return f"""# Agentic Forensics Report

> **All timestamps in this report are in UTC.**

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
**Blueprint:** {blueprint.get('name')}
**Clients:** {len(client_ids)} selected
**Collection Duration:** {collection_minutes} minutes

---

## Summary

No data was collected from the selected clients during the {collection_minutes}-minute collection window.

**Possible reasons:**
- Selected clients may be offline or unreachable
- Artifacts may not be applicable to the target operating systems
- Collection time may have been too short for clients to respond

**Recommended actions:**
- Verify that selected clients are online in the Dashboard
- Increase the collection time window
- Check Velociraptor hunt status for errors
"""


def save_report_content(run_id, report_content):
    """Save report(s) to database. Handles both single report (legacy) and dict of reports."""
    if isinstance(report_content, dict):
        # Multiple reports - save as JSON containing both
        save_report(run_id, json.dumps(report_content))
        print(f"[AGENTIC] Reports saved for run_id: {run_id} ({list(report_content.keys())})", flush=True)
    else:
        # Legacy single report
        save_report(run_id, report_content)
        print(f"[AGENTIC] Report saved for run_id: {run_id}", flush=True)


def persist_pipeline_artifacts(run_id, artifact_summaries, all_results):
    """Save the artifact summaries + raw row data for the fusion layer.

    Case Analysis (fusion) reads `raw_results.json` to build the cross-module
    / cross-host case graph — this is the bridge from a collect-only agentic
    run into the case. `artifact_summaries` is kept alongside for parity but is
    empty in the collect-only path.

    Files written to /data/downloads/<run_id>/:
      - artifact_summaries.json   : dict[artifact_name -> summary text]
      - raw_results.json          : dict[artifact_name -> [row, ...]]

    Both are best-effort — a failure to persist these doesn't break the main
    pipeline.
    """
    downloads_dir = f"/data/downloads/{run_id}"
    try:
        os.makedirs(downloads_dir, exist_ok=True)
        with open(f"{downloads_dir}/artifact_summaries.json", "w") as f:
            json.dump(artifact_summaries or {}, f)
        with open(f"{downloads_dir}/raw_results.json", "w") as f:
            # Use default=str so any non-serialisable values (datetimes,
            # bytes, etc.) degrade to a string rather than crashing the
            # whole save.
            json.dump(all_results or {}, f, default=str)
    except Exception as e:
        # Telemetry only — fusion will detect missing files and degrade.
        print(f"[PIPELINE] Failed to persist artifacts for {run_id}: {e}", flush=True)
