#!/usr/bin/env python3
"""
Agentic Analyzers - LLM analysis functions for forensic data
"""

import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.agentic.constants import (
    TRUNCATE_TOKEN_LIMIT, MAX_LLM_TOKENS,
    OLLAMA_CONTEXT_SIZE, OLLAMA_TIMEOUT_SECONDS,
    ONLINE_LLM_TIMEOUT_SECONDS,
)
from services.agentic.analyzers._llm import *  # noqa: F401,F403
from services.agentic.analyzers._llm import _log_llm_totals  # underscore helper not covered by import *

def _compute_data_scope(rows):
    """Pre-compute factual scope of the data for the LLM prompt.

    Returns a dict with the actual min/max timestamps, unique users, unique IPs,
    record count, etc. The LLM is instructed to ONLY reference these values.
    """
    if not rows:
        return {
            'total_count': 0,
            'time_range': 'no data',
            'unique_users': [],
            'unique_ips': [],
            'unique_operations': [],
        }

    # Extract timestamps from various possible fields
    timestamps = []
    users = set()
    ips = set()
    operations = set()

    def _get_first(rec, *keys):
        if not isinstance(rec, dict):
            return None
        for k in keys:
            v = rec.get(k)
            if v:
                return v
        return None

    for r in rows:
        # Records may be findings (with matched_record nested) or raw events
        rec = r.get('matched_record', r) if isinstance(r, dict) else {}
        if not isinstance(rec, dict):
            continue

        ts = _get_first(rec, '_timestamp', 'CreationTime', 'createdDateTime',
                        'activityDateTime', 'TimeGenerated', 'eventDateTime')
        if ts:
            timestamps.append(str(ts))

        user = _get_first(rec, 'UserId', 'userPrincipalName', 'Actor')
        if isinstance(user, str):
            users.add(user)
        elif isinstance(user, list):
            for u in user:
                if isinstance(u, str):
                    users.add(u)
                elif isinstance(u, dict) and u.get('ID'):
                    users.add(u['ID'])

        # initiatedBy.user.userPrincipalName
        ib = rec.get('initiatedBy')
        if isinstance(ib, dict):
            u = ib.get('user', {}) if isinstance(ib.get('user'), dict) else {}
            if u.get('userPrincipalName'):
                users.add(u['userPrincipalName'])

        ip = _get_first(rec, 'ipAddress', 'IPAddress', 'ClientIP', 'ClientIPAddress')
        if isinstance(ip, str):
            ips.add(ip)

        op = _get_first(rec, 'Operation', 'activityDisplayName', 'eventName')
        if isinstance(op, str):
            operations.add(op)

    timestamps.sort()
    distinct_dates = sorted({t[:10] for t in timestamps if len(t) >= 10})

    # Detect state snapshot: no records have timestamps, or every record is marked as one
    is_state_snapshot = (not timestamps) or all(
        (r.get('_state_snapshot') if isinstance(r, dict) else False)
        for r in rows
    )

    if is_state_snapshot:
        time_range = '(state snapshot — no event time range)'
    else:
        time_range = (
            f"{timestamps[0]} → {timestamps[-1]} ({len(distinct_dates)} distinct day(s))"
            if timestamps else 'unknown'
        )

    return {
        'total_count': len(rows),
        'time_range': time_range,
        'distinct_dates': distinct_dates,
        'unique_users': sorted(users)[:50],
        'unique_ips': sorted(ips)[:50],
        'unique_operations': sorted(operations)[:50],
        'is_state_snapshot': is_state_snapshot,
    }


def _sample_records_for_llm(rows, max_count=90):
    """Sample records to send to LLM: first N + last N + random middle.

    Avoids sending thousands of identical records that encourage narrative
    inflation, while still giving the LLM a representative slice.
    """
    import random
    if len(rows) <= max_count:
        return rows, False
    third = max_count // 3
    first = rows[:third]
    last = rows[-third:]
    middle_pool = rows[third:-third] if len(rows) > 2 * third else []
    middle = random.sample(middle_pool, min(third, len(middle_pool))) if middle_pool else []
    return first + middle + last, True


# Opaque Velociraptor identifiers that bloat every row's token cost without
# giving the LLM any analytical leverage. Both the canonical Velociraptor
# casings (ClientId, FlowId) and the underscore variants we add in the hunt
# branch (_client_id) are stripped. Per-host attribution for multi-client
# hunts is preserved at the pipeline / synthesis layer, not in the per-row
# data the analyzer LLM sees.
_LLM_DROP_KEYS = frozenset({
    "ClientId", "client_id", "_client_id",
    "FlowId", "flow_id", "_flow_id",
})


def _strip_metadata_fields(rows):
    """Remove ClientId / FlowId metadata from rows before LLM serialization.
    No-op when the keys aren't present (single-flow path) or rows aren't dicts."""
    if not rows:
        return rows
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append({k: v for k, v in r.items() if k not in _LLM_DROP_KEYS})
        else:
            out.append(r)
    return out


def analyze_single_artifact(artifact, rows, llm_config, anonymizer=None, finding_meta=None,
                            log_func=None, run_id=None, master_prompt=None):
    """Analyze a single artifact with LLM. Returns (artifact, summary, error) tuple.

    `log_func` is the workflow-log callback `(msg, level)` from the
    orchestrator; if provided, the atomic skill pick (if any) is logged so
    the operator can see which DFIR skill drove each artifact analysis.

    Anti-hallucination guards:
    - Pre-computes data scope (timestamps, users, IPs) and pins it in the prompt
    - Includes the SIGMA rule's own description if `finding_meta` is provided
    - Hard rule: only reference values that appear in the records
    - Forces structured output (machine-parseable findings + prose summary)
    - Caps record count to a representative sample to avoid context bloat
    """
    if anonymizer:
        # Snapshot mapping size before/after so we can show what THIS
        # artifact contributed to the shared dictionary. The summary log
        # at the end of the pipeline still emits the cumulative table;
        # this adds a per-artifact timestamp the operator can use to
        # verify masking ran BEFORE the LLM call for each artifact.
        before_n = len(anonymizer.mapping)
        rows = anonymizer.mask_data(rows)
        added = len(anonymizer.mapping) - before_n
        if log_func:
            try:
                log_func(
                    f"[Masking] {artifact}: masked {len(rows)} rows "
                    f"(+{added} new values, {len(anonymizer.mapping)} total) "
                    f"before LLM call",
                    "info",
                )
            except Exception:
                pass

    # Pre-compute factual scope from the FULL set, before sampling
    scope = _compute_data_scope(rows)
    sampled_rows, was_sampled = _sample_records_for_llm(rows, max_count=90)
    # Drop opaque ClientId / FlowId metadata — pure token waste in the
    # per-record JSON the analyzer sends to the LLM.
    sampled_rows = _strip_metadata_fields(sampled_rows)

    data_str = json.dumps(sampled_rows, indent=2, default=str)
    if len(data_str) > TRUNCATE_TOKEN_LIMIT:
        data_str = data_str[:TRUNCATE_TOKEN_LIMIT] + "\n... (truncated)"

    # Pull rule context from the first finding (all share the same rule)
    rule_context = ""
    if finding_meta:
        rule_context = "\n".join(filter(None, [
            f"**Rule:** {finding_meta.get('rule_title', artifact)}",
            f"**Rule ID:** {finding_meta.get('rule_id', '')}" if finding_meta.get('rule_id') else None,
            f"**Severity (rule level):** {finding_meta.get('severity', 'unknown')}",
            f"**Description:** {finding_meta.get('rule_description', '')}" if finding_meta.get('rule_description') else None,
            f"**Known false positives:** {', '.join(finding_meta.get('falsepositives', []))}" if finding_meta.get('falsepositives') else None,
            f"**MITRE:** {', '.join(t.get('id') or t.get('name', '') for t in finding_meta.get('mitre_attack', []))}" if finding_meta.get('mitre_attack') else None,
        ]))

    is_state = scope.get('is_state_snapshot', False)

    if is_state:
        scope_block = (
            f"**Data type:** STATE SNAPSHOT (current configuration, NOT a timeline of events)\n"
            f"**Total items:** {scope['total_count']}\n"
            f"**Time range:** {scope['time_range']}\n"
            f"**Note:** Do NOT describe a timeline. Identify outliers, misconfigurations, "
            f"and items that look anomalous compared to a healthy baseline."
        )
    else:
        scope_block = (
            f"**Data type:** EVENT LOG (timeline of things that happened)\n"
            f"**Total records:** {scope['total_count']}\n"
            f"**Time range:** {scope['time_range']}\n"
            f"**Distinct dates:** {', '.join(scope['distinct_dates']) or '(none)'}\n"
            f"**Unique users (up to 50):** {', '.join(scope['unique_users']) or '(none)'}\n"
            f"**Unique IPs (up to 50):** {', '.join(scope['unique_ips']) or '(none)'}\n"
            f"**Unique operations (up to 50):** {', '.join(scope['unique_operations']) or '(none)'}"
        )

    sample_note = (
        f"\n\nNote: Showing {len(sampled_rows)} of {scope['total_count']} records (first/middle/last sample)."
        if was_sampled else ""
    )

    system_prompt = """You are a senior forensic security analyst. Your job is to triage detection findings and write a concise analysis a SOC analyst can act on.

## HARD RULES — DO NOT VIOLATE
1. **Only reference dates, users, IPs, hostnames, and counts that appear in the SCOPE FACTS or the RECORDS shown below.** If the records cover one day, do NOT describe a multi-day campaign. If you compute a number, show how (e.g., "5 events from 213.x.x.x out of 242 total").
2. **Do not invent attacker tools, threat actor names, or campaign narratives.** "Likely Hydra/Medusa", "APT29", "credential stuffing botnet" are forbidden unless the records contain explicit indicators.
3. **Distinguish FACT vs INFERENCE.** Tag every claim. Facts are directly observable in the records. Inferences are interpretations and must be marked as such with confidence level.
4. **Default values are not evidence.** `riskDetail: "hidden"` is the Microsoft default when no risk was detected — it is NOT "suppressed" or "hidden by attacker". Empty `deviceId` is normal for non-AAD-joined devices. `conditionalAccessStatus: "notApplied"` means no policy targeted the sign-in, NOT a bypass.
5. **Calibrate severity honestly.** Reserve CRITICAL for confirmed compromise. Use HIGH for strong inference. Use MEDIUM for suspicious patterns needing investigation. Use LOW for context. Prefer downgrading when in doubt — false alarms destroy SOC trust.
6. **Always include a `false_positive_check` for every finding** explaining what would make this benign (e.g., "user is on personal BYOD device", "service principal token refresh", "scheduled background sync").
7. **Findings emission gate.** A `findings[]` entry exists only when the records show *specific behaviour-level evidence* of attacker intent (detection rule hit, anomalous timing, suspicious chaining of actions, baseline deviation, known TTPs) AND your confidence is high enough that a SOC analyst would act on it (pivot, block, escalate, contain). Default-shaped activity is NOT a finding — even if you could write one for it. Examples that should NOT become findings: normal interactive logons, default Windows scheduled tasks, expected user browsing, vendor RMM tools the org legitimately uses, software-installer mtime changes during normal use. An empty `findings[]` is the correct output when nothing suspicious is in the data. **Do NOT pad with low-confidence findings to make the JSON look fuller.**
8. **IOC discipline.** A value belongs in `iocs.*` only if an analyst would pivot on it or block it in a SIEM. Brand-name mentions in user activity (browser history, installed-software lists, normal RDP-to-vendor-portal traffic) are NOT IOCs even when "interesting". Authentication providers (AzureAD, NT AUTHORITY, NT VIRTUAL MACHINE) and internal hostnames (DESKTOP-*, local-*) are NEVER IOCs. When in doubt, omit.
9. **Timestamp format.** The records use a single canonical timestamp format: `YYYY-MM-DD HH:MM:SS` (24-hour, no timezone, no `T`, no `Z`). When you cite timestamps in `sample_timestamps`, evidence quotes, or prose, **use exactly that format** — copy the value from the records as-is. Do not convert to ISO-8601 (`2026-05-06T07:49:12Z`), do not add fractional seconds, do not add a timezone. Example: `"2026-05-06 07:49:12"`, never `"2026-05-06T07:49:12Z"`.

## OUTPUT FORMAT
Return your response in two parts:

### Part 1: Structured findings (JSON in a code block)
```json
{
  "summary": "1-2 sentences describing what the data shows.",
  "scan_scope_acknowledged": "Echo back the time range and record count from SCOPE FACTS.",
  "findings": [
    {
      "id": "F1",
      "title": "Short title",
      "severity": "critical|high|medium|low|informational",
      "confidence": "low|medium|high",
      "evidence": "Direct quote or specific values from the records (FACT)",
      "evidence_count": 12,
      "interpretation": "Your inference about what this means (INFERENCE)",
      "false_positive_check": "What would make this benign",
      "sample_users": ["user1@x.com"],
      "sample_ips": ["1.2.3.4"],
      "sample_timestamps": ["2026-04-01 07:20:17"],
      "mitre": ["T1110"],
      "recommended_action": "What the analyst should do next"
    }
  ],
  "iocs": {
    // STRICT: only put values an analyst would pivot on or block. Empty arrays are fine — preferable to false positives.
    "ips":     [],   // External attacker IPs only. Skip RFC1918 unless specific evidence of attacker pivot.
    "domains": [],   // ONLY attacker-controlled or attacker-abused domains (C2 / exfil / staging / malicious download).
                     //  Do NOT list vendor/SaaS brands (anydesk.com, github.com, openai.com, facebook.com, gmail.com,
                     //  crowdstrike.com, splashtop.com, microsoft.com, etc.) unless there's specific evidence of attacker abuse.
                     //  Do NOT list authentication providers (AzureAD, NT AUTHORITY, NT VIRTUAL MACHINE).
                     //  Do NOT list internal hostnames (DESKTOP-*, local-*, *.local, *.lan).
    "hashes":  [],   // Lower-case hex only — bare value, no "SHA256:" prefix here.
    "users":   []    // ONLY accounts implicated in attacker activity (created, elevated, target of lateral movement).
                     //  Don't list every user observed.
  }
}
```

### Part 2: Brief prose summary (max 200 words)
A short narrative the analyst can paste into a ticket. NO recap of every finding — just the top 1-3 issues and what to check first.
"""

    # Inject one DFIR domain-knowledge skill if any matches the artifact +
    # MITRE techniques on this finding. No-op if no skill clears the score
    # threshold or the skills index is empty. Logs the chosen skill (and
    # whether it came from the pinned artifact_map or runtime fuzzy match)
    # to the workflow log so the operator can see which guidance drove
    # each per-artifact analysis.
    try:
        from services.agentic.skills import (
            select_skills, compose_system_prompt, _lookup_artifact_map,
        )
        mitre_ids = [
            t.get('id') for t in (finding_meta or {}).get('mitre_attack', [])
            if isinstance(t, dict) and t.get('id')
        ]
        selected = select_skills(artifact, mitre_ids)
        if selected:
            system_prompt = compose_system_prompt(system_prompt, selected)
            if log_func:
                source = "pinned" if _lookup_artifact_map(artifact) else "fuzzy"
                log_func(f"[Skill] {artifact} → {selected[0]} ({source})", "info")
        elif log_func:
            log_func(f"[Skill] {artifact} → no match (using base prompt only)", "info")
    except Exception:  # noqa: BLE001 — skills must never block analysis
        pass

    # Interactive-mode master prompt — domain context supplied by the
    # operator after reviewing a prior run's report (false positives,
    # legitimate IT activity, investigation priorities). Prepended to
    # the system prompt so the analyst's corrections take precedence
    # over the base instructions. Only present on re-runs triggered
    # from the interactive chat panel.
    if master_prompt:
        system_prompt = (
            "## OPERATOR CONTEXT (from interactive validation)\n"
            "The following corrections + investigation priorities have been "
            "supplied by the analyst after reviewing a prior version of this "
            "report. Treat them as ground truth and adjust your analysis "
            "accordingly — downweight or remove findings the analyst marked "
            "as false-positive / known-legitimate, surface and deepen any "
            "areas they asked you to investigate further.\n\n"
            f"{master_prompt.strip()}\n\n---\n\n"
        ) + system_prompt
        if log_func:
            log_func(f"[Pipeline] master prompt applied to {artifact}", "info")

    user_prompt = f"""## ARTIFACT
{artifact}

## RULE CONTEXT
{rule_context or '(no SIGMA rule metadata available)'}

## SCOPE FACTS (these are your ONLY source of truth for dates/users/IPs/counts)
{scope_block}

## RECORDS{sample_note}
{data_str}

Now produce the JSON findings + brief prose summary, following all HARD RULES above."""

    try:
        summary = call_llm(user_prompt, system_prompt, llm_config, run_id=run_id)
        return (artifact, summary, None)
    except Exception as e:
        return (artifact, f"Analysis failed: {str(e)}", str(e))
