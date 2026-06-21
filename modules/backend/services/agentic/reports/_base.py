#!/usr/bin/env python3
"""
Agentic Reports - Report generation functions for forensic analysis
"""

import json
import re
import textwrap
import zipfile
import os
from datetime import datetime

from services.workflow_service import add_log_to_run
from services.file_storage_service import save_report, get_report
from services.agentic.analyzers import call_llm
from services.agentic.utils import extract_timeline_events


_LIST_MARKER_RE = re.compile(r'^(\s*)([-*+]|\d+\.)\s+')


def wrap_markdown_paragraphs(text: str, width: int = 100) -> str:
    """Hard-wrap paragraph text in a markdown string so raw .md files read
    sanely in editors without soft-wrap, without breaking structural
    markdown (headings, code fences, tables, list items, front-matter).

    The LLM-written report body arrives as one very long logical line per
    paragraph. Renderers handle this fine, but editors without word-wrap
    show each paragraph as a single off-screen line. Wrapping here keeps
    the rendered output identical while making the raw file readable.
    """
    if not text:
        return text

    lines = text.split('\n')
    out = []
    in_fence = False
    fence_marker = None
    in_frontmatter = False
    saw_frontmatter_open = False

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # YAML front-matter (first-line --- only)
        if not saw_frontmatter_open and idx == 0 and stripped == '---':
            in_frontmatter = True
            saw_frontmatter_open = True
            out.append(line)
            continue
        if in_frontmatter:
            out.append(line)
            if stripped == '---':
                in_frontmatter = False
            continue

        # fenced code block
        if not in_fence and (stripped.startswith('```') or stripped.startswith('~~~')):
            in_fence = True
            fence_marker = stripped[:3]
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            if stripped.startswith(fence_marker):
                in_fence = False
                fence_marker = None
            continue

        # Structural lines that must never be wrapped: headings, tables,
        # blockquotes, list items, blank lines, horizontal rules.
        if (not stripped
                or stripped.startswith('#')
                or stripped.startswith('|')
                or stripped.startswith('>')
                or _LIST_MARKER_RE.match(line)
                or set(stripped) <= {'-', '='}):
            out.append(line)
            continue

        # Regular paragraph line -> wrap. break_long_words=False and
        # break_on_hyphens=False keep URLs, filepaths, and hashes intact.
        out.append(textwrap.fill(
            line,
            width=width,
            break_long_words=False,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=False,
        ))

    return '\n'.join(out)


def _format_clients_label(client_ids, hostnames=None):
    """Render the "Clients:" header value with the ≤3 names rule.

    ≤3 clients with known hostnames → "2 (NofLaptop, DESKTOP-566AT85)".
    >3 clients OR hostnames missing  → "7 analyzed".

    Same pattern used in the workflow name (agentic_routes.py) so the
    operator sees consistent labelling everywhere.
    """
    n = len(client_ids)
    if n <= 3 and hostnames:
        names = [hostnames.get(cid) or cid for cid in client_ids]
        return f"{n} ({', '.join(names)})"
    return f"{n} analyzed"


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


def get_client_hostname(client_id, all_results):
    """Extract hostname from results for a client (from any row that has it)."""
    for rows in all_results.values():
        for row in rows:
            if row.get('_client_id') == client_id:
                hostname = row.get('_hostname') or row.get('Hostname') or row.get('hostname')
                if hostname:
                    return hostname
    # Fallback to client_id
    return client_id.replace('C.', 'Client-')



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


def _generate_timeline_section(events, llm_config, run_id):
    """Generate a human-readable timeline summary from events."""
    if not events:
        return "No timestamped events found in collected artifacts."

    # Limit to most relevant events (first 200 and last 50 for context)
    if len(events) > 250:
        selected_events = events[:200] + events[-50:]
    else:
        selected_events = events

    # Format events for LLM (handle None timestamps for events without time info)
    events_text = "\n".join([
        f"[{ev['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if ev.get('timestamp') else 'UNKNOWN TIME'}] ({ev['source']}) [{ev.get('hostname', 'Unknown')}] {ev.get('description', '')[:200]}"
        for ev in selected_events
    ])

    system_prompt = """You are a forensic analyst creating a timeline narrative.
Given a chronological list of events from various forensic artifacts, create a coherent narrative
that explains what happened on the system(s). Focus on:
- Initial compromise indicators (first suspicious activity)
- Lateral movement and persistence
- Data exfiltration attempts
- Key actions by threat actors or users
- Notable patterns and correlations between events

Format as a timeline with clear timestamps and explanations. Group related events logically."""

    user_prompt = f"""Create a narrative timeline from these {len(selected_events)} forensic events:

{events_text}

Generate a clear, chronological narrative of what occurred:"""

    try:
        add_log_to_run(run_id, f"[Report] Generating timeline narrative from {len(events)} events...", "info")
        timeline = call_llm(user_prompt, system_prompt, llm_config)
        return timeline
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Timeline generation failed: {str(e)}", "warning")
        # Fallback: just list events
        return "**Timeline Events:**\n\n" + events_text[:10000]


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


def get_report_content(run_id, report_type=None):
    """Get report content from database.

    Args:
        run_id: The run ID
        report_type: 'executive', 'technical', or None for combined/legacy
    Returns: markdown string or None

    Handles `{"technical": null}` (a state the report blob can land in
    after a partially-failed re-run) by returning None instead of the
    raw JSON literal. The previous version's `combined += None`
    raised TypeError → was caught → fell through to legacy raw return,
    leaking the JSON string into anything that called us — visible
    most recently as the literal `{"technical": null}` appearing in
    engagement reports.
    """
    content = get_report(run_id)
    if not content:
        return None

    # Try to parse as JSON (new multi-report format)
    try:
        reports = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        reports = None

    if isinstance(reports, dict):
        # Coerce empty/None values to '' so a `{"technical": null}` is
        # treated as missing rather than silently leaking the JSON
        # source string downstream.
        tech = reports.get('technical') or ''
        execu = reports.get('executive') or ''
        if report_type:
            return reports.get(report_type) or None
        parts = []
        if execu.strip():
            parts.append(execu.strip())
            parts.append("\n\n---\n\n")
        if tech.strip():
            parts.append(tech.strip())
        combined = ''.join(parts).strip()
        return combined or None

    # Legacy single report (raw string written directly to the DB,
    # not JSON-wrapped). Only treat as valid if it looks like
    # markdown rather than a stringified JSON null/empty marker.
    s = (content or '').strip()
    if not s or s in ('{}', '[]', 'null', '""'):
        return None
    return content


def get_available_report_types(run_id):
    """Get list of available report types for a run."""
    content = get_report(run_id)
    if not content:
        return []

    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            return list(reports.keys())
    except (json.JSONDecodeError, TypeError):
        pass

    return ['combined']  # Legacy format



def persist_pipeline_artifacts(run_id, artifact_summaries, all_results):
    """Save the artifact summaries + raw row data alongside the report ZIP.

    Used by the interactive-mode "reports-only" re-run path: when the
    operator chats with the LLM and asks for the report to be regenerated
    with their corrections applied, we can rebuild the per-client + macro
    reports without re-running the (expensive) per-artifact LLM analysis.

    Files written to /data/downloads/<run_id>/:
      - artifact_summaries.json   : dict[artifact_name -> LLM summary text]
      - raw_results.json          : dict[artifact_name -> [row, ...]]
                                    (used by filter_results_by_client for
                                    per-client report regeneration)

    Both are best-effort — a failure to persist these doesn't break the
    main pipeline; the re-run path just falls back to a full re-analysis.
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
        # Telemetry only — re-run path will detect missing files and
        # fall back to scope="full" anyway.
        print(f"[PIPELINE] Failed to persist artifacts for {run_id}: {e}", flush=True)


def _safe_hostname(name):
    """Same alnum/-/_ transform used for ZIP entry names. One source of
    truth so persist + read map round-trips cleanly."""
    return "".join(c if c.isalnum() or c in '-_' else '_' for c in (name or 'unknown'))


def persist_per_client_reports(run_id, per_client_dict, hostnames):
    """Write each client's report markdown to disk so the chat assistant
    can read it directly without unzipping anything. Files land at
    `/data/downloads/<run_id>/per_client/<safe_hostname>.md`.

    Called from the pipeline + reports-only re-run alongside
    `create_report_package`. The ZIP is still the operator-facing
    download artifact; this directory is the chat's source-of-truth.
    Markdown is small, so the duplication is cheap."""
    if not per_client_dict:
        return
    pc_dir = f"/data/downloads/{run_id}/per_client"
    try:
        os.makedirs(pc_dir, exist_ok=True)
        hn = hostnames or {}
        for client_id, report in per_client_dict.items():
            hostname = hn.get(client_id) or client_id
            fname = f"{_safe_hostname(hostname)}.md"
            with open(f"{pc_dir}/{fname}", "w") as f:
                f.write(report or '')
    except Exception as e:
        # Best-effort — chat will fall back to ZIP extraction if needed.
        print(f"[REPORTS] Failed to persist per-client reports for {run_id}: {e}", flush=True)


def get_per_client_reports(run_id, hostnames=None):
    """Return `{client_id: markdown}` for every per-client report stored
    on disk for this run. Falls back to extracting from `reports.zip`
    when the disk directory is missing or empty (legacy runs that
    pre-date the per-client persistence), and seeds the disk copy on
    the way so subsequent reads avoid the unzip.

    `hostnames` is the workflow.details.hostnames map; we need it to
    reverse-map `<safe_hostname>.md` filenames back to client_ids.
    When omitted, returns the map keyed by `safe_hostname` instead
    (caller has to deal with the inconsistency — but every call site
    in this codebase has the hostnames dict on hand)."""
    pc_dir = f"/data/downloads/{run_id}/per_client"
    hn = hostnames or {}
    # Build reverse map: safe_hostname -> client_id. When two clients
    # collapse to the same safe_hostname (rare but possible with weird
    # chars), the later one wins — same behaviour as the ZIP.
    rev = {_safe_hostname(h): cid for cid, h in hn.items()}

    out = {}
    if os.path.isdir(pc_dir):
        try:
            for fname in os.listdir(pc_dir):
                if not fname.endswith('.md'):
                    continue
                stem = fname[:-3]  # strip .md
                client_id = rev.get(stem, stem)
                try:
                    with open(f"{pc_dir}/{fname}") as f:
                        out[client_id] = f.read()
                except Exception as e:
                    print(f"[REPORTS] Failed to read {pc_dir}/{fname}: {e}", flush=True)
        except Exception as e:
            print(f"[REPORTS] Failed to list {pc_dir}: {e}", flush=True)

    if out:
        return out

    # Backfill from ZIP for legacy runs (or runs where the persist
    # helper failed). The ZIP uses `<safe_hostname>_report.md` — strip
    # the trailing _report.md to recover the safe_hostname.
    zip_path = f"/data/downloads/{run_id}/reports.zip"
    if not os.path.exists(zip_path):
        return out
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                if name == '00_ORGANIZATION_SUMMARY.md' or not name.endswith('_report.md'):
                    continue
                stem = name[:-len('_report.md')]
                client_id = rev.get(stem, stem)
                out[client_id] = zf.read(name).decode('utf-8', errors='replace')
        # Seed disk so the next call reads from there. Pass hostnames
        # back through so the filenames match.
        if out and hn:
            # Build a dict keyed by the actual client_ids we resolved.
            persist_per_client_reports(run_id, out, hn)
    except Exception as e:
        print(f"[REPORTS] ZIP backfill failed for {run_id}: {e}", flush=True)
    return out


def create_report_package(run_id, multi_reports):
    """Create a ZIP package containing all reports.

    Args:
        run_id: Workflow run ID
        multi_reports: Dict from generate_multi_client_reports()

    Returns:
        Path to the created ZIP file
    """
    # Ensure downloads directory exists
    downloads_dir = f"/data/downloads/{run_id}"
    os.makedirs(downloads_dir, exist_ok=True)

    zip_path = f"{downloads_dir}/reports.zip"
    hostnames = multi_reports.get('hostnames', {})

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add macro summary first (00_ prefix for sorting). Only present
        # when the operator opted in via the cross-client-synthesis
        # checkbox; otherwise the ZIP contains only per-client reports.
        macro = multi_reports.get('macro')
        if macro:
            zf.writestr("00_ORGANIZATION_SUMMARY.md", macro)

        # Add per-client reports
        for client_id, report in multi_reports['per_client'].items():
            hostname = hostnames.get(client_id, client_id)
            # Clean hostname for filename
            safe_hostname = "".join(c if c.isalnum() or c in '-_' else '_' for c in hostname)
            zf.writestr(f"{safe_hostname}_report.md", report)

    return zip_path
