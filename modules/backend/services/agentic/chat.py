"""Interactive chat for agentic-run report validation.

DFIR validation is iterative: the first-pass report inevitably contains
false positives ("that PowerShell on NofLaptop was IT admin Bob") and
gaps the operator wants re-investigated. This module exposes the
chat machinery a UI panel uses to:

  1. Talk through findings with the LLM (multi-turn).
  2. Synthesise the chat into a structured "master prompt" — false
     positives + investigation priorities + domain context.
  3. (Re-run plumbing lives in agentic_routes.py — this module just
     produces the master prompt that the re-run consumes.)

Storage: conversation lives in `workflow.details.chat_messages` as
`[{role, content, ts}, ...]`. Capped at 100 messages — when exceeded
the OLDEST entries are dropped (we keep latest because they're the
most relevant when the LLM rebuilds context).
"""
from __future__ import annotations

import time as _time
import json
from typing import Dict, List, Optional

from services.workflow_service import add_log_to_run
from services.file_storage_service import get_workflow, save_workflow
from services.agentic.analyzers import call_llm
from services.agentic.reports import get_report_content, get_per_client_reports


# ---------------------------------------------------------------------------
# Constants + helpers
# ---------------------------------------------------------------------------

# How many turns to keep in workflow.details. Beyond this we drop the
# oldest. 100 is generous for normal DFIR validation flow; tens of turns
# at most.
_MAX_TURNS = 100

# Hard cap on a single message body to prevent operator pasting 10 MB
# of logs into the chat textarea.
_MAX_MESSAGE_CHARS = 50_000

# How much of the run's reports we feed into the chat's system context.
# A multi-client run might have 5+ per-client reports of 10–30 k each
# plus a macro — easily 100 k+. Haiku has a 200 k-token window so 180 k
# chars (~45 k tokens) is comfortable; leaves plenty of room for the
# system-prompt scaffolding, multi-turn chat history, and the assistant
# reply. We truncate proportionally per-section if a run blows past this.
_REPORT_CONTEXT_CHAR_BUDGET = 180_000

# When the total context exceeds the budget, every per-section block is
# scaled down by the same ratio rather than hard-cutting the tail. This
# keeps the LLM aware of every host even on huge runs.
_TRUNCATION_MARKER = "\n\n*[…section truncated to fit chat context budget…]*"


def _get_messages(run_id: str) -> List[Dict]:
    """Return the persisted chat transcript for a run (or empty list)."""
    workflow = get_workflow(run_id)
    if not workflow:
        return []
    details = workflow.get("details") or {}
    msgs = details.get("chat_messages") or []
    return msgs if isinstance(msgs, list) else []


def _merge_details(run_id: str, patch: Dict) -> None:
    """Merge a dict into workflow.details without touching status/progress.

    update_run_status() unconditionally writes `status`, so calling it
    with status=None would clobber the run's completed/failed state.
    Read-modify-write through save_workflow keeps the rest of the row
    intact while merging the patch into details.
    """
    workflow = get_workflow(run_id)
    if not workflow:
        return
    existing = workflow.get("details") or {}
    if not isinstance(existing, dict):
        existing = {}
    existing.update(patch)
    workflow["details"] = existing
    save_workflow(workflow)


def _save_messages(run_id: str, messages: List[Dict]) -> None:
    """Persist the chat transcript back to workflow.details. Drops the
    oldest entries when the cap is exceeded."""
    if len(messages) > _MAX_TURNS:
        messages = messages[-_MAX_TURNS:]
    _merge_details(run_id, {"chat_messages": messages})


def _assemble_agentic_sections(run_id, details):
    """Agentic-specific report assembler: single-client or multi-client
    with per-host breakdown + optional org-wide macro."""
    client_ids = details.get("client_ids") or []
    hostnames = details.get("hostnames") or {}
    sections = []
    if len(client_ids) <= 1:
        body = (get_report_content(run_id) or "").strip()
        if body:
            hn = (hostnames.get(client_ids[0]) if client_ids else None) or "this host"
            sections.append({"label": f"### Per-host report: {hn}", "body": body})
    else:
        macro = (get_report_content(run_id) or "").strip()
        if macro and not macro.lstrip().startswith("# Multi-client run — per-client reports only"):
            sections.append({"label": "### Organisation-wide synthesis (macro)", "body": macro})
        per_client = get_per_client_reports(run_id, hostnames=hostnames) or {}
        for cid in client_ids:
            body = (per_client.get(cid) or "").strip()
            if not body:
                continue
            hn = hostnames.get(cid) or cid
            sections.append({"label": f"### Per-host report: {hn}  (client_id {cid})", "body": body})
    return sections


def _assemble_cloud_sections(run_id, details, kind):
    """AWS / Azure: single-target scan with one markdown blob. `kind` is
    'aws' or 'azure' — picks the right report accessor."""
    if kind == 'aws':
        from services.aws.reports import get_aws_report_content as _getter
        label = "### AWS scan report"
    else:
        from services.azure.reports import get_azure_report_content as _getter
        label = "### Azure scan report"
    body = (_getter(run_id) or "").strip()
    if not body:
        return []
    return [{"label": label, "body": body}]


def _assemble_engagement_sections(run_id, details):
    """Engagement Report: the assembled deliverable is saved via
    `save_report` (same accessor AWS/Azure use). Pull it via the
    storage layer directly — keeps this isolated from the engagement
    package to avoid a circular import."""
    from services.storage.report_store import get_report
    raw = get_report(run_id)
    if not raw:
        return []
    try:
        import json as _json
        parsed = _json.loads(raw)
        md = parsed.get('technical') if isinstance(parsed, dict) else None
        md = (md or raw).strip()
    except (ValueError, TypeError):
        md = (raw or '').strip()
    if not md:
        return []
    return [{"label": "### Engagement Report (current draft)", "body": md}]


def _assemble_report_context(run_id: str) -> str:
    """Build the report-context block for the chat system prompt.

    Dispatches by workflow.automation_type:
      - 'agentic'    → per-host reports + optional macro (see
                       `_assemble_agentic_sections`).
      - 'aws_scan'   → single AWS report blob.
      - 'azure_scan' → single Azure report blob.
      - anything else → empty (best-effort).

    When the total exceeds the budget, every per-section block gets
    scaled down by the same ratio so the assistant still has at least
    some content from every section."""
    workflow = get_workflow(run_id) or {}
    details = workflow.get("details") or {}
    automation_type = workflow.get("automation_type")

    if automation_type == 'aws_scan':
        sections = _assemble_cloud_sections(run_id, details, kind='aws')
    elif automation_type == 'azure_scan':
        sections = _assemble_cloud_sections(run_id, details, kind='azure')
    elif automation_type == 'engagement_report':
        sections = _assemble_engagement_sections(run_id, details)
    elif automation_type == 'memory':
        # Memory module stores its single LLM report directly on the
        # workflow row's details.report_md (no per-host fan-out, no
        # reports table). Hand it to the chat verbatim — the assistant
        # can answer follow-up questions about the findings, suggest
        # plugins to re-run, or push corrections back through the
        # synthesize-master-prompt path.
        report_md = (details or {}).get("report_md") or ""
        if report_md.strip():
            label = "Memory forensics report"
            host = (details or {}).get("client_name") or (details or {}).get("client_id") or ""
            mode = (details or {}).get("mode") or "?"
            if host:
                label = f"Memory forensics report — {host} (mode={mode})"
            sections = [{"label": label, "body": report_md}]
        else:
            sections = []
    else:
        # Default to agentic behaviour — preserves prior path for the
        # original agentic chat code.
        sections = _assemble_agentic_sections(run_id, details)

    if not sections:
        return "(no report content available yet)"

    # Total assembled size + budget enforcement. Budget is for the body
    # text only; the labels are short and unbudgeted.
    bodies_total = sum(len(s["body"]) for s in sections)
    if bodies_total <= _REPORT_CONTEXT_CHAR_BUDGET:
        return "\n\n".join(f"{s['label']}\n{s['body']}" for s in sections)

    # Over budget — scale every section proportionally so each host
    # still gets representation. Keep at least 2 k chars per section
    # (a useful flavour) even if the math says less.
    ratio = _REPORT_CONTEXT_CHAR_BUDGET / bodies_total
    parts = []
    for s in sections:
        keep = max(2000, int(len(s["body"]) * ratio))
        body = s["body"]
        if len(body) > keep:
            body = body[:keep] + _TRUNCATION_MARKER
        parts.append(f"{s['label']}\n{body}")
    return "\n\n".join(parts)


def _build_chat_system_prompt(run_id: str) -> str:
    """The chat assistant's role + every relevant report as initial context."""
    report_block = _assemble_report_context(run_id)

    return (
        "You are a DFIR analyst's assistant. The operator has just walked "
        "through the report below with the customer's IT team and is now "
        "passing on what they learned in the conversation — which findings "
        "turned out to be legitimate IT activity, which need a deeper look, "
        "and whatever environment context came up that should shape the "
        "next pass of the analysis.\n"
        "\n"
        "Treat the operator's messages as free-form notes from a real "
        "conversation, not a structured form. They will write in prose; "
        "you reply in prose — full sentences, no bullet points, no "
        "numbered lists, no markdown headings, no bold labels like "
        "**Finding X:**. Just a short paragraph. Keep replies to a "
        "couple of sentences. Ask a clarifying question only when "
        "something the operator said is genuinely ambiguous in a way "
        "that would hurt the re-run (which host, which user, which "
        "time window). Do not push them to use finding IDs or any "
        "template. Do not invent details that aren't in the report or "
        "in what the operator told you.\n"
        "\n"
        "## Report context for this run\n"
        "Every report relevant to this run is included below — for "
        "multi-client runs that means the organisation-wide synthesis "
        "(when generated) plus a per-host report for each client. "
        "Quote concrete findings from the right host when the operator "
        "asks; do not say you can't see a report when one is included.\n"
        "\n"
        f"{report_block}\n"
    )


def _format_history_for_llm(messages: List[Dict]) -> str:
    """Flatten the multi-turn history into a single user-prompt string.

    call_llm() is single-turn (no `messages: list[]` parameter). To
    preserve conversational continuity we serialise the prior turns
    into the user prompt as a readable transcript, then ask the LLM
    to reply to the LATEST user message.
    """
    if not messages:
        return ""
    lines = []
    for m in messages[:-1]:  # all but the last (which is the new user turn)
        role = m.get("role", "user").upper()
        content = (m.get("content") or "").strip()
        if not content:
            continue
        lines.append(f"### {role}\n{content}")
    # The final message IS the operator's current turn — include it under
    # its own heading so the LLM replies to it specifically.
    if messages:
        last = messages[-1]
        lines.append(f"### {last.get('role', 'user').upper()} (current turn — reply to this)\n"
                     f"{(last.get('content') or '').strip()}")
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Public API used by the route handlers
# ---------------------------------------------------------------------------


_FLOW_LOG_RE = None  # lazy-compiled in _maybe_recover_flow_ids


def _maybe_recover_flow_ids(run_id: str, workflow: Dict) -> bool:
    """Best-effort: if the workflow's `details.flow_id` / `hunt_id` are
    empty but the log history still carries the
    "[Velociraptor] [N/N] Collection started on ... (<cid>): F.xxxx"
    lines that the collector emitted at run time, extract those flow IDs
    and stash them in workflow.details so Full re-analysis becomes
    available on legacy runs.

    Returns True if anything was recovered (caller should re-read the
    workflow). False = nothing to recover, or already had flow IDs.
    """
    import re as _re
    global _FLOW_LOG_RE
    if _FLOW_LOG_RE is None:
        # Match: ... on <hostname> (<client_id>): <flow_id>
        _FLOW_LOG_RE = _re.compile(r'on\s+\S+\s+\((C\.[A-Za-z0-9]+)\)\s*:\s*(F\.[A-Za-z0-9]+)')

    details = workflow.get('details') or {}
    if not isinstance(details, dict):
        details = {}
    if details.get('flow_id') or details.get('hunt_id'):
        return False  # nothing to do

    logs = workflow.get('logs') or []
    recovered = {}  # client_id -> flow_id
    for line in logs:
        msg = (line.get('message') or '')
        if 'Collection started' not in msg:
            continue
        m = _FLOW_LOG_RE.search(msg)
        if m:
            cid, fid = m.group(1), m.group(2)
            recovered[cid] = fid

    if not recovered:
        return False

    flow_ids = list(recovered.values())
    details['flow_id'] = flow_ids if len(flow_ids) > 1 else flow_ids[0]
    workflow['details'] = details
    save_workflow(workflow)
    add_log_to_run(
        run_id,
        f"[Interactive] Recovered {len(flow_ids)} flow ID(s) from log history "
        f"({', '.join(flow_ids)}). Full re-analysis is now available.",
        "info",
    )
    return True


def _scope_availability(automation_type, run_id, details):
    """Per-pipeline predicates for whether reports-only and full
    re-analysis are viable on a given run.

    Returns (reports_only_available, full_analysis_available).

    Each branch checks the source-of-truth for that pipeline:
      - agentic    → sidecar JSON on disk; flow_id/hunt_id in details
      - aws_scan   → sidecar JSON on disk; raw AWS run data on disk
      - azure_scan → azure_runs JSON dump on disk (covers both)
    """
    import os as _os

    sidecar_dir = f"/data/downloads/{run_id}"
    has_agentic_sidecars = (
        _os.path.exists(f"{sidecar_dir}/artifact_summaries.json") and
        _os.path.exists(f"{sidecar_dir}/raw_results.json")
    )

    def _cloud_scope(persisted_path):
        """For AWS/Azure: both rerun scopes work as long as the
        persisted run JSON exists. The reanalyse helper falls back to
        the in-JSON `analysis` dict when the agentic-style sidecar
        isn't present, so reports-only is viable either way."""
        if not _os.path.exists(persisted_path):
            return (False, False)
        # Reports-only is viable if EITHER the sidecar exists OR the
        # persisted JSON has any per-rule analyses to replay. Avoids
        # the UI greying out reports-only on legacy runs that still
        # have usable in-JSON analyses.
        try:
            import json as _json
            with open(persisted_path) as f:
                _data = _json.load(f)
            has_analysis = bool(_data.get('analysis'))
            has_findings = bool(_data.get('findings'))
        except Exception:
            has_analysis = False
            has_findings = False
        return (
            has_agentic_sidecars or has_analysis,
            has_findings,  # full needs findings to re-analyse
        )

    if automation_type == 'aws_scan':
        return _cloud_scope(f"/app/data/aws_runs/{run_id}.json")

    if automation_type == 'azure_scan':
        return _cloud_scope(f"/app/data/azure_runs/{run_id}.json")

    if automation_type == 'engagement_report':
        # Engagement re-runs only need the original source list on
        # the workflow's details + the source workflows still being
        # readable. Both scopes (reports_only / full) collapse to one
        # LLM call for engagement, but we accept either symmetrically.
        sources = details.get('sources') or []
        has_sources = bool(sources)
        return (has_sources, has_sources)

    # Agentic (default)
    full_analysis_available = bool(details.get("flow_id") or details.get("hunt_id"))
    return (has_agentic_sidecars, full_analysis_available)


def get_chat_state(run_id: str) -> Dict:
    """Snapshot of the chat for a given run — used by the GET endpoint.

    For agentic runs: includes resolved client list (`[{client_id,
    hostname}, ...]`) so the UI can show the per-client target
    selector. For AWS/Azure: `clients` is empty (single-target
    scans), and the modal hides the dropdown automatically.

    The two `*_available` booleans tell the UI which re-run scopes
    can actually run on this workflow — see `_scope_availability`."""
    workflow = get_workflow(run_id)
    if not workflow:
        return {
            "messages": [], "master_prompt": None, "report_version": 1,
            "clients": [],
            "reports_only_available": False,
            "full_analysis_available": False,
        }
    automation_type = workflow.get("automation_type")
    # Legacy agentic runs may still have flow IDs recoverable from
    # log history. AWS/Azure don't need this dance — they persist
    # their own collected data files directly.
    if automation_type not in ('aws_scan', 'azure_scan'):
        if _maybe_recover_flow_ids(run_id, workflow):
            workflow = get_workflow(run_id)
    details = workflow.get("details") or {}
    client_ids = details.get("client_ids") or []
    hostnames = details.get("hostnames") or {}
    clients = [
        {"client_id": cid, "hostname": hostnames.get(cid) or cid}
        for cid in client_ids
    ]
    reports_only_available, full_analysis_available = _scope_availability(
        automation_type, run_id, details
    )
    return {
        "messages": details.get("chat_messages") or [],
        "master_prompt": details.get("master_prompt") or None,
        "report_version": int(details.get("report_version") or 1),
        "clients": clients,
        "reports_only_available": reports_only_available,
        "full_analysis_available": full_analysis_available,
    }


def send_chat_message(run_id: str, user_text: str, llm_config: Dict) -> str:
    """Append the operator's message, get an assistant reply, persist both,
    return the assistant text.

    Raises ValueError on empty / too-long input. Raises RuntimeError on
    LLM failure (caller surfaces to operator).
    """
    if not user_text or not user_text.strip():
        raise ValueError("message is empty")
    if len(user_text) > _MAX_MESSAGE_CHARS:
        raise ValueError(f"message too long ({len(user_text)} > {_MAX_MESSAGE_CHARS} chars)")

    messages = _get_messages(run_id)
    now = int(_time.time())
    messages.append({"role": "user", "content": user_text.strip(), "ts": now})

    system_prompt = _build_chat_system_prompt(run_id)
    user_prompt = _format_history_for_llm(messages)

    try:
        reply = call_llm(user_prompt, system_prompt, llm_config, run_id=run_id)
    except Exception as e:
        # Don't lose the operator's message on LLM failure — persist what
        # we have so the chat history reflects the attempt, then re-raise
        # for the route to surface.
        _save_messages(run_id, messages)
        raise RuntimeError(f"chat LLM call failed: {e}") from e

    if not reply or not isinstance(reply, str):
        _save_messages(run_id, messages)
        raise RuntimeError(f"chat LLM returned unexpected type: {type(reply).__name__}")

    messages.append({"role": "assistant", "content": reply, "ts": int(_time.time())})
    _save_messages(run_id, messages)
    add_log_to_run(run_id, f"[Interactive] Chat turn: operator sent {len(user_text)} chars, assistant replied {len(reply)} chars", "info")
    return reply


_SYNTH_SYSTEM = """You are condensing a DFIR analyst's chat with their assistant
into a short briefing that the next pass of the automated analysis will
read verbatim as domain context. The chat captures what the operator
learned from sitting with the customer's IT team and walking through the
report together.

Write the briefing as flowing prose — a few short paragraphs of free
text. Do not use bullet lists, headings, finding IDs, or any structured
template. Read like a colleague handing the case to the next shift:
which activity turned out to be legitimate IT work and why, which areas
the operator wants looked at more closely, and the environment context
that should colour the next pass (who owns which host, what is normal
on this network, anything the model would otherwise mis-call).

Stay strictly grounded in what the operator actually said in the chat.
Do not invent corrections, priorities, or facts they did not mention.
If the chat is sparse, the briefing should be sparse — keep it honest.
"""


def synthesize_master_prompt(run_id: str, llm_config: Dict) -> str:
    """Compress the chat transcript into a structured master prompt.
    Persists to workflow.details.master_prompt and returns it.

    Raises RuntimeError on LLM failure.
    """
    messages = _get_messages(run_id)
    if not messages:
        raise ValueError("no chat history to synthesise — send at least one message first")

    # Build the LLM prompt: the full transcript + the explicit ask.
    transcript = json.dumps(messages, indent=2, default=str)
    user_prompt = (
        f"Chat transcript:\n```json\n{transcript[:80_000]}\n```\n\n"
        "Write the briefing as described in the system prompt — flowing "
        "prose, no bullets, no headings, no template."
    )

    try:
        master = call_llm(user_prompt, _SYNTH_SYSTEM, llm_config, run_id=run_id)
    except Exception as e:
        raise RuntimeError(f"master-prompt synthesis LLM call failed: {e}") from e

    if not master or not isinstance(master, str):
        raise RuntimeError(f"synthesis LLM returned unexpected type: {type(master).__name__}")

    master = master.strip()
    _merge_details(run_id, {"master_prompt": master})
    add_log_to_run(run_id, f"[Interactive] Synthesised master prompt ({len(master)} chars).", "success")
    return master


def set_master_prompt(run_id: str, master_prompt: Optional[str]) -> None:
    """Operator-editable override: lets the UI persist a hand-edited
    master prompt before triggering the re-run. Pass None to clear."""
    _merge_details(run_id, {"master_prompt": (master_prompt or "").strip() or None})


def clear_chat(run_id: str) -> None:
    """Wipe the chat transcript + any synthesised master prompt for this
    run. Used by the "Clear chat" link in the modal so the operator can
    start a fresh conversation when the prior transcript is stale or
    cluttered."""
    _merge_details(run_id, {"chat_messages": [], "master_prompt": None})
    add_log_to_run(run_id, "[Interactive] Chat cleared by operator.", "info")
