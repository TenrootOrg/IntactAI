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

# =============================================================================
# Model Aliases - Friendly names that resolve to latest model IDs
# =============================================================================
# Anthropic supports aliases without dates (e.g., claude-opus-4-6 auto-updates)
# OpenRouter requires specific model IDs that may need periodic updates

MODEL_ALIASES = {
    # Claude models - simple aliases auto-update to latest
    "claude-opus": {
        "claude": "opus",  # Auto-resolves to latest Opus
        "openrouter": "anthropic/claude-opus-4-6"  # OpenRouter needs specific version
    },
    "claude-sonnet": {
        "claude": "sonnet",  # Auto-resolves to latest Sonnet
        "openrouter": "anthropic/claude-sonnet-4-6"
    },
    "claude-haiku": {
        "claude": "haiku",  # Auto-resolves to latest Haiku
        "openrouter": "anthropic/claude-haiku-4-5"
    },
    # OpenAI models
    "gpt-4o": {
        "openai": "gpt-4o",
        "openrouter": "openai/gpt-4o"
    },
    "gpt-4.1": {
        "openai": "gpt-4.1",
        "openrouter": "openai/gpt-4.1"
    },
    # Google models - use -latest suffix for auto-updates
    "gemini-flash": {
        "gemini": "gemini-2.5-flash-latest",  # Auto-resolves to latest Flash
        "openrouter": "google/gemini-2.5-flash-preview"
    },
    "gemini-pro": {
        "gemini": "gemini-2.5-pro-latest",  # Auto-resolves to latest Pro
        "openrouter": "google/gemini-2.5-pro-preview"
    },
    # DeepSeek models (OpenRouter only)
    "deepseek-v3": {
        "openrouter": "deepseek/deepseek-chat-v3-0324"
    },
    "deepseek-r1": {
        "openrouter": "deepseek/deepseek-r1"
    },
}

def resolve_model_alias(model_name: str, provider: str) -> str:
    """Resolve a friendly model name to the actual model ID for a provider.

    Args:
        model_name: Friendly name (e.g., 'claude-sonnet') or actual model ID
        provider: Provider name ('claude', 'openai', 'openrouter')

    Returns:
        Actual model ID to use with the API
    """
    # Check if it's an alias
    if model_name in MODEL_ALIASES:
        alias_map = MODEL_ALIASES[model_name]
        if provider in alias_map:
            return alias_map[provider]
        # Fallback: try openrouter if direct provider not found
        if 'openrouter' in alias_map:
            return alias_map['openrouter']

    # Not an alias, return as-is (user provided actual model ID)
    return model_name


def get_available_models() -> list:
    """Return list of available model aliases for frontend dropdown."""
    return list(MODEL_ALIASES.keys())


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


def analyze_single_artifact(artifact, rows, llm_config, anonymizer=None, finding_meta=None, log_func=None):
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
        rows = anonymizer.mask_data(rows)

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
      "sample_timestamps": ["2026-04-01T07:20:17Z"],
      "mitre": ["T1110"],
      "recommended_action": "What the analyst should do next"
    }
  ],
  "iocs": {
    "ips": [],
    "users": [],
    "hashes": [],
    "domains": []
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
        summary = call_llm(user_prompt, system_prompt, llm_config)
        return (artifact, summary, None)
    except Exception as e:
        return (artifact, f"Analysis failed: {str(e)}", str(e))


def _extract_findings_from_summary(summary_text: str) -> dict:
    """Pull the JSON block out of a per-artifact summary string (the format
    that analyze_single_artifact returns: a fenced ```json``` block followed
    by a prose paragraph). Returns the parsed dict, or {} if extraction fails.
    """
    if not isinstance(summary_text, str) or not summary_text:
        return {}
    # Match ```json ... ``` (with optional language tag).
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", summary_text, flags=re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return {}


def synthesize_findings(run_id, summaries, llm_config, log_func=None):
    """Cross-artifact synthesis pass: take the per-artifact summaries from the
    atomic phase, pick one macro DFIR playbook via skills.select_macro_skill(),
    and produce a unified narrative + prioritized next-actions.

    Returns the synthesis text (string), or None if synthesis was skipped
    (e.g., no findings, no macros loaded, or LLM call failed). Never raises —
    synthesis is best-effort and must not break the pipeline.
    """
    if not summaries:
        return None

    def log(msg, level="info"):
        try:
            from services.workflow_service import add_log_to_run
            add_log_to_run(run_id, msg, level)
        except Exception:  # noqa: BLE001
            pass
        if log_func:
            log_func(msg, level)

    # Aggregate MITRE techniques + severity counts + per-artifact title lines.
    aggregated_mitre = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    artifact_names = list(summaries.keys())
    finding_lines = []

    for artifact, summary in summaries.items():
        parsed = _extract_findings_from_summary(summary)
        if not parsed:
            continue
        for f in parsed.get("findings", []) or []:
            sev = (f.get("severity") or "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            for t in f.get("mitre", []) or []:
                if t:
                    aggregated_mitre.append(str(t))
            # One compact line per finding for the synthesis input.
            finding_lines.append(
                f"- [{artifact}] [{sev or '?'}] {f.get('title', '?')}: "
                f"{(f.get('interpretation') or f.get('evidence') or '')[:240]}"
            )

    if not finding_lines:
        log("[LLM] Synthesis: no parseable findings across artifacts; skipping.")
        return None

    # Pick the macro playbook for this run.
    try:
        from services.agentic.skills import select_macro_skill, get_macro_body
    except Exception:  # noqa: BLE001
        log("[LLM] Synthesis: skills module unavailable; skipping.")
        return None

    macro_name = select_macro_skill(
        aggregated_mitre=aggregated_mitre,
        severity_counts=severity_counts,
        artifact_names=artifact_names,
    )
    if not macro_name:
        log("[LLM] Synthesis: no macro playbook matched; skipping.")
        return None

    macro_body = get_macro_body(macro_name) or ""

    log(f"[LLM] Synthesis: using macro '{macro_name}' across {len(artifact_names)} artifacts")

    synthesis_system_prompt = f"""You are a senior DFIR lead writing a cross-artifact investigation summary for a SOC.

You have a list of per-artifact findings already triaged by junior analysts. Your job is to:
1. Connect the dots — identify whether multiple findings point to one campaign / one root cause / one threat actor pattern, or to independent issues.
2. Calibrate confidence honestly. A single "high" finding alone is suggestive; three "high" findings spanning persistence + execution + lateral movement is a strong story.
3. Stay grounded in the FACTS each junior analyst already established. Do NOT invent attacker names, tools, or activity not present in the per-artifact findings.
4. Prioritize next actions for the SOC: what to escalate, what to contain, what to ignore.

## DOMAIN PLAYBOOK
{macro_body}
"""

    synthesis_user_prompt = f"""## RUN CONTEXT
- Artifacts analyzed: {len(artifact_names)}
- Severity rollup: {json.dumps(severity_counts)}
- Distinct MITRE techniques observed: {sorted(set(aggregated_mitre))[:40]}

## PER-ARTIFACT FINDINGS (one line each — distilled from junior-analyst JSON)
{chr(10).join(finding_lines[:200])}

## YOUR DELIVERABLE
1. **Executive narrative** (≤200 words): the story across artifacts. What appears to have happened, in plain language. Cite evidence by `[artifact]` reference.
2. **Confidence**: low / medium / high — one line of justification.
3. **Top 3 actions for the SOC**: ranked. Each with a single sentence of "why".
4. **Calibration check**: 1-2 sentences on what would invalidate this narrative.
"""

    try:
        return call_llm(synthesis_user_prompt, synthesis_system_prompt, llm_config)
    except Exception as e:  # noqa: BLE001
        log(f"[LLM] Synthesis call failed: {e}", "warning")
        return None


def analyze_artifacts(run_id, all_results, llm_config, anonymizer=None, log_func=None):
    """Run LLM analysis on each artifact's results using parallel execution"""
    from services.workflow_service import add_log_to_run

    def log(msg, level="info"):
        if log_func:
            log_func(msg, level)
        add_log_to_run(run_id, msg, level)

    summaries = {}
    artifacts_list = list(all_results.keys())

    if not artifacts_list:
        return summaries

    # Get max concurrent requests from config (default: 5)
    max_concurrent = llm_config.get('agentic', {}).get('max_concurrent_requests', 5)
    log(f"[LLM] Starting parallel analysis with {max_concurrent} concurrent requests")

    # Submit all analysis tasks to thread pool
    futures = {}
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        for artifact in artifacts_list:
            rows = all_results[artifact]
            # Extract rule/finding metadata from the first item (all share it)
            finding_meta = None
            if rows and isinstance(rows[0], dict):
                first = rows[0]
                finding_meta = {
                    'rule_title': first.get('rule_title') or artifact,
                    'rule_id': first.get('rule_id', ''),
                    'rule_description': first.get('rule_description') or first.get('_description', ''),
                    'severity': first.get('severity') or first.get('_severity', 'unknown'),
                    'falsepositives': first.get('falsepositives', []),
                    'mitre_attack': first.get('mitre_attack', []),
                }
            log(f"[LLM] Queued {artifact} ({len(rows)} rows) for analysis")
            future = executor.submit(
                analyze_single_artifact, artifact, rows, llm_config,
                anonymizer, finding_meta, log,
            )
            futures[future] = artifact

        # Collect results as they complete
        completed = 0
        error_count = 0
        for future in as_completed(futures):
            artifact, summary, error = future.result()
            summaries[artifact] = summary
            completed += 1

            if error:
                error_count += 1
                log(f"[LLM] Error for {artifact}: {error}", "warning")
            else:
                log(f"[LLM] Analysis complete for {artifact} ({completed}/{len(artifacts_list)})")

    # If ALL analyses failed, raise an exception so the pipeline knows
    if error_count == len(artifacts_list) and len(artifacts_list) > 0:
        raise RuntimeError(f"All {error_count} LLM analyses failed. Check your LLM configuration (API key or Ollama server).")

    # Synthesis pass: cross-artifact narrative anchored on a macro DFIR
    # playbook. Best-effort — never breaks the pipeline if it fails.
    # Stored under a reserved key the report layer can render distinctly.
    if error_count < len(artifacts_list):
        synthesis = synthesize_findings(run_id, summaries, llm_config, log_func=log_func)
        if synthesis:
            summaries["__synthesis__"] = synthesis
            log(f"[LLM] Cross-artifact synthesis added ({len(synthesis)} chars)")

    return summaries


def validate_llm_config(config):
    """Validate LLM configuration before starting analysis.

    Raises ValueError if configuration is invalid.
    """
    agentic_config = config.get('agentic', {})
    mode = agentic_config.get('llm_mode', 'online')

    if mode == 'online':
        online_config = agentic_config.get('online_llm', {})
        api_key = online_config.get('api_key', '')
        if not api_key:
            raise ValueError(
                "LLM mode is set to 'online' but no API key is configured. "
                "Please go to Settings > Agentic and either:\n"
                "1. Enter your Claude/OpenAI API key, or\n"
                "2. Switch to 'offline' mode and configure Ollama"
            )
    else:
        offline_config = agentic_config.get('offline_llm', {})
        url = offline_config.get('url', '')
        if not url:
            raise ValueError(
                "LLM mode is set to 'offline' but no Ollama URL is configured. "
                "Please go to Settings > Agentic and configure the Ollama server URL."
            )


def call_llm(prompt, system_prompt, config):
    """Call the configured LLM provider"""
    agentic_config = config.get('agentic', {})
    mode = agentic_config.get('llm_mode', 'online')

    # Get configurable limits with fallbacks to constants
    max_tokens = agentic_config.get('max_response_tokens', MAX_LLM_TOKENS)
    context_size = agentic_config.get('ollama_context_size', OLLAMA_CONTEXT_SIZE)
    timeout = agentic_config.get('ollama_timeout', OLLAMA_TIMEOUT_SECONDS)

    if mode == 'online':
        return _call_llm_online(prompt, system_prompt, agentic_config.get('online_llm', {}), max_tokens)
    else:
        return _call_llm_offline(prompt, system_prompt, agentic_config.get('offline_llm', {}), context_size, timeout)


def _call_llm_online(prompt, system_prompt, provider_config, max_tokens):
    """Call Claude or other online LLM"""
    provider = provider_config.get('provider', 'claude')
    api_key = provider_config.get('api_key', '')
    model_input = provider_config.get('model', 'claude-sonnet')

    # Handle custom model for OpenRouter
    if model_input == 'custom':
        model = provider_config.get('custom_model', '')
        if not model:
            raise ValueError("Custom model selected but no model ID provided")
    else:
        # Resolve model alias to actual model ID
        model = resolve_model_alias(model_input, provider)

    if not api_key:
        raise ValueError("Online LLM API key not configured. Set it in Settings.")

    # Big report-generation prompts (~30-50K input tokens) routinely exceed
    # the SDK default 60s HTTP timeout. When that happens upstream of
    # OpenRouter, Cloudflare returns an HTML timeout page and the OpenAI
    # SDK fails with a confusing json.JSONDecodeError. Catch that
    # specifically and surface a clearer message; bump every client's
    # timeout to ONLINE_LLM_TIMEOUT_SECONDS (default 600s).
    def _wrap_decode_errors(provider_name, fn):
        try:
            return fn()
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"{provider_name} returned non-JSON response (likely upstream "
                f"timeout on a large prompt; the proxy returned an HTML error "
                f"page). Try a shorter prompt or raise ONLINE_LLM_TIMEOUT_SECONDS. "
                f"Original parse error: {e}"
            ) from e

    if provider == 'claude':
        import anthropic
        client = anthropic.Anthropic(api_key=api_key, timeout=ONLINE_LLM_TIMEOUT_SECONDS)
        response = _wrap_decode_errors('Claude', lambda: client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}]
        ))
        return response.content[0].text
    elif provider == 'openai':
        import openai
        client = openai.OpenAI(api_key=api_key, timeout=ONLINE_LLM_TIMEOUT_SECONDS)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = _wrap_decode_errors('OpenAI', lambda: client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.1
        ))
        return response.choices[0].message.content
    elif provider == 'openrouter':
        import openai
        client = openai.OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            timeout=ONLINE_LLM_TIMEOUT_SECONDS,
        )
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = _wrap_decode_errors('OpenRouter', lambda: client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.1
        ))
        return response.choices[0].message.content
    elif provider == 'gemini':
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(model)
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = _wrap_decode_errors('Gemini', lambda: gemini_model.generate_content(
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0.1
            ),
            request_options={'timeout': ONLINE_LLM_TIMEOUT_SECONDS},
        ))
        return response.text
    else:
        raise ValueError(f"Unsupported online provider: {provider}")


def _call_llm_offline(prompt, system_prompt, provider_config, context_size, timeout):
    """Call Ollama or other local LLM"""
    provider = provider_config.get('provider', 'ollama')
    model = provider_config.get('model', 'llama3.3:70b')
    url = provider_config.get('url', 'http://localhost:11434')

    if provider == 'ollama':
        full_prompt = f"{system_prompt}\n\n{prompt}"
        response = requests.post(
            f"{url}/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "num_ctx": context_size
                }
            },
            timeout=timeout
        )
        response.raise_for_status()
        return response.json().get('response', '')
    else:
        raise ValueError(f"Unsupported offline provider: {provider}")
