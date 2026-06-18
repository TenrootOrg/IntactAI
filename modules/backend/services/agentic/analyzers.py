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
# LLM cost table (USD per 1M tokens). Approximate; refresh periodically.
# Lookup is best-effort — unknown models log $0 cost but still record token
# counts so the operator gets the volume picture at minimum.
# =============================================================================
_LLM_COST_PER_MTOK = {
    # Anthropic (Sonnet 4 / Opus 4 family)
    "claude-opus": (15.00, 75.00),
    "claude-sonnet": (3.00, 15.00),
    "claude-haiku": (0.80, 4.00),
    "opus": (15.00, 75.00),
    "sonnet": (3.00, 15.00),
    "haiku": (0.80, 4.00),
    # OpenAI
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    # Common OpenRouter-style ids (longest-match wins via the helper below)
    "anthropic/claude-opus": (15.00, 75.00),
    "anthropic/claude-sonnet": (3.00, 15.00),
    "anthropic/claude-haiku": (0.80, 4.00),
    "openai/gpt-4o-mini": (0.15, 0.60),
    "openai/gpt-4o": (2.50, 10.00),
    "google/gemini-2.5-pro": (1.25, 10.00),
    "google/gemini-2.5-flash": (0.075, 0.30),
}


def _estimate_llm_cost(model: str, in_tokens: int, out_tokens: int) -> float:
    """Approximate USD cost for the given model + token volume.

    Pricing is per-million-tokens. Unknown models return 0.0 (the operator
    still sees the token volume in the metrics). Picks the longest matching
    prefix so e.g. `anthropic/claude-sonnet-4-6` resolves to the
    `anthropic/claude-sonnet` row.

    Normalises the model string before matching:
      - strip leading `~` (added by the route for OpenRouter "latest"
        auto-resolve — `~anthropic/claude-haiku-latest`)
      - strip trailing `-latest` (resolves to whatever the alias points
        at, but pricing follows the family)
    Without this, OpenRouter aliases reported $0 cost despite real spend
    because the `~` prefix prevented any pricing-table key from matching.
    """
    if not model:
        return 0.0
    key = model.lower().lstrip("~")
    # Match against both the raw key AND the -latest-stripped form so
    # `anthropic/claude-haiku-latest` resolves to `anthropic/claude-haiku`.
    candidates = {key}
    if key.endswith("-latest"):
        candidates.add(key[: -len("-latest")])
    best = None
    for cand in candidates:
        for k in _LLM_COST_PER_MTOK:
            if cand.startswith(k.lower()) and (best is None or len(k) > len(best)):
                best = k
    if best is None:
        return 0.0
    cin, cout = _LLM_COST_PER_MTOK[best]
    return (in_tokens / 1_000_000.0) * cin + (out_tokens / 1_000_000.0) * cout


def _record_llm_usage(run_id, provider, model, response):
    """Extract usage tokens from a provider response and persist to workflow row.

    Each provider exposes usage on a different attribute path; we normalise
    here. Failures swallowed — telemetry never breaks the pipeline.
    """
    if not run_id:
        return
    in_tokens = 0
    out_tokens = 0
    try:
        if provider == 'claude':
            usage = getattr(response, 'usage', None)
            if usage is not None:
                in_tokens = int(getattr(usage, 'input_tokens', 0) or 0)
                out_tokens = int(getattr(usage, 'output_tokens', 0) or 0)
        elif provider in ('openai', 'openrouter'):
            usage = getattr(response, 'usage', None)
            if usage is not None:
                in_tokens = int(getattr(usage, 'prompt_tokens', 0) or 0)
                out_tokens = int(getattr(usage, 'completion_tokens', 0) or 0)
        elif provider == 'gemini':
            usage = getattr(response, 'usage_metadata', None)
            if usage is not None:
                in_tokens = int(getattr(usage, 'prompt_token_count', 0) or 0)
                out_tokens = int(getattr(usage, 'candidates_token_count', 0) or 0)
        elif provider == 'ollama':
            # Ollama returns dicts with prompt_eval_count / eval_count
            if isinstance(response, dict):
                in_tokens = int(response.get('prompt_eval_count', 0) or 0)
                out_tokens = int(response.get('eval_count', 0) or 0)
    except Exception as ex:
        print(f"[ANALYZER] usage extraction failed ({provider}): {ex}", flush=True)
        return

    cost = _estimate_llm_cost(model or '', in_tokens, out_tokens)
    try:
        from services.workflow_service import record_llm_metrics
        record_llm_metrics(
            run_id,
            calls=1,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            cost_usd=cost,
            model=model,
        )
    except Exception as ex:
        print(f"[ANALYZER] record_llm_metrics failed: {ex}", flush=True)

# =============================================================================
# Model Aliases - Friendly names that resolve to latest model IDs
# =============================================================================
# Anthropic supports aliases without dates (e.g., claude-opus-4-6 auto-updates)
# OpenRouter requires specific model IDs that may need periodic updates

MODEL_ALIASES = {
    # Claude models - simple aliases auto-update to latest
    "claude-opus": {
        "claude": "opus",  # Auto-resolves to latest Opus
        "openrouter": "anthropic/claude-opus-4-6",  # OpenRouter needs specific version
        "max_output_tokens": 128000,
    },
    "claude-sonnet": {
        "claude": "sonnet",  # Auto-resolves to latest Sonnet
        "openrouter": "anthropic/claude-sonnet-4-6",
        "max_output_tokens": 64000,
    },
    "claude-haiku": {
        "claude": "haiku",  # Auto-resolves to latest Haiku
        "openrouter": "anthropic/claude-haiku-4-5",
        "max_output_tokens": 8192,
    },
    # OpenAI models
    "gpt-4o": {
        "openai": "gpt-4o",
        "openrouter": "openai/gpt-4o",
        "max_output_tokens": 16384,
    },
    "gpt-4.1": {
        "openai": "gpt-4.1",
        "openrouter": "openai/gpt-4.1",
        "max_output_tokens": 32768,
    },
    # Google models - use -latest suffix for auto-updates
    "gemini-flash": {
        "gemini": "gemini-2.5-flash-latest",  # Auto-resolves to latest Flash
        "openrouter": "google/gemini-2.5-flash-preview",
        "max_output_tokens": 65536,
    },
    "gemini-pro": {
        "gemini": "gemini-2.5-pro-latest",  # Auto-resolves to latest Pro
        "openrouter": "google/gemini-2.5-pro-preview",
        "max_output_tokens": 65536,
    },
    # DeepSeek models (OpenRouter only)
    "deepseek-v3": {
        "openrouter": "deepseek/deepseek-chat-v3-0324",
        "max_output_tokens": 8192,
    },
    "deepseek-r1": {
        "openrouter": "deepseek/deepseek-r1",
        "max_output_tokens": 8192,
    },
}


def get_model_max_output_tokens(model_input: str, provider: str):
    """Resolve the max output tokens for a given model id + provider.

    Walk order:
        1. Friendly alias table (`MODEL_ALIASES[model_input].max_output_tokens`)
        2. The provider's catalog file (looks up the resolved native id
           or canonical id and reads `max_output_tokens` off the entry)
        3. None — caller falls back to the constant default

    Used by the resolver to honor the user's "just always use the max"
    directive when the operator hasn't explicitly overridden it.
    """
    if not model_input:
        return None
    # Step 1: alias table
    alias_entry = MODEL_ALIASES.get(model_input)
    if alias_entry and alias_entry.get("max_output_tokens"):
        return alias_entry["max_output_tokens"]

    # Step 2: per-provider catalog. Local imports to avoid module-load
    # ordering issues — the catalog package imports analyzers' siblings
    # transitively in some paths.
    catalog_module = None
    try:
        if provider == "openrouter":
            from services.llm_catalogs import openrouter as catalog_module
        elif provider == "claude":
            from services.llm_catalogs import anthropic as catalog_module
        elif provider == "openai":
            from services.llm_catalogs import openai as catalog_module
        elif provider == "gemini":
            from services.llm_catalogs import gemini as catalog_module
    except Exception:
        catalog_module = None

    if catalog_module:
        try:
            models = catalog_module.load_catalog()
            # `model_input` for direct providers is usually the friendly
            # alias; only OpenRouter and "custom" pass raw ids. Try both
            # native id and canonical id matches.
            resolved = resolve_model_alias(model_input, provider)
            for m in models:
                if m.get("id") == resolved or m.get("id") == model_input \
                        or m.get("canonical_id") == resolved:
                    if m.get("max_output_tokens"):
                        return m["max_output_tokens"]
        except Exception:
            pass

    # Step 3: OpenRouter-mirror fallback. When the operator picks a model
    # from the dropdown's OpenRouter-fallback section, the saved value
    # is in direct-SDK form (e.g. `claude-opus-4-6`). Convert back to
    # canonical (`anthropic/claude-opus-4.6`) and look in the OpenRouter
    # catalog so max_output_tokens / context_length stay accurate.
    if provider in ("claude", "openai", "gemini"):
        try:
            from routes.config_routes import _canonical_from_direct_sdk_id
            from services.llm_catalogs import openrouter as or_catalog
            canonical = _canonical_from_direct_sdk_id(model_input, provider)
            if canonical:
                for m in or_catalog.load_catalog():
                    cid = m.get("id") or ""
                    bare = cid[1:] if cid.startswith("~") else cid
                    if bare == canonical and m.get("max_output_tokens"):
                        return m["max_output_tokens"]
        except Exception:
            pass

    return None

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

    # OpenRouter aliases — model IDs ending in `-latest` need a leading
    # `~` to be parsed by the API as "auto-resolve to latest in this
    # family". Without the tilde, OpenRouter returns 400 "not a valid
    # model ID". Operators routinely copy the URL slug from
    # `openrouter.ai/~anthropic/claude-sonnet-latest` and miss the
    # leading `~` (it looks like part of the URL path); auto-prepend
    # so the alias works either way. The tilde is OpenRouter-specific —
    # other providers don't use it, so only apply when we'd hit OR.
    if (
        provider == "openrouter"
        and "/" in model_name
        and model_name.endswith("-latest")
        and not model_name.startswith("~")
    ):
        return "~" + model_name

    # Not an alias, return as-is (user provided actual model ID)
    return model_name


def explain_llm_error(error_str: str, model: str, provider: str) -> str:
    """Wrap a raw LLM API error with operator-friendly guidance when the
    underlying cause is a model-ID problem.

    The bare error from OpenRouter / Anthropic / OpenAI looks like
    `Error code: 400 - {'error': {'message': 'X is not a valid model ID', ...}}`
    which is uninformative when the dashboard logs it on a fresh install.
    Detect the common 'invalid model' pattern and prepend a hint with
    the configured model + provider + how to fix it. Pass-through for
    every other error shape (rate limits, auth, server errors, etc.) so
    we don't accidentally hide useful detail.
    """
    err_lower = (error_str or "").lower()
    invalid_model = (
        "is not a valid model id" in err_lower
        or "model_not_found" in err_lower
        or "no such model" in err_lower
    )
    if not invalid_model:
        return error_str

    hint_lines = [
        f"Model '{model}' was rejected by {provider}.",
    ]
    if provider == "openrouter":
        hint_lines.append(
            f"  Verify the ID at https://openrouter.ai/{model.lstrip('~')} — "
            "if that page 404s, the model doesn't exist or the alias hasn't been published."
        )
        hint_lines.append(
            "  Common cause: a per-version `-latest` (e.g. `openai/gpt-5.5-latest`) — "
            "OpenRouter only mints `-latest` aliases at the family level "
            "(e.g. `~openai/gpt-latest`). Use a pinned version (`openai/gpt-5.5`) "
            "or a family alias (`~openai/gpt-latest`, `~anthropic/claude-sonnet-latest`)."
        )
    else:
        hint_lines.append(
            f"  Set a valid model ID in Settings → Agentic → Online LLM. "
            f"Provider '{provider}' published model lists are at the vendor's API docs."
        )
    hint_lines.append(f"  Raw error: {error_str}")
    return "\n".join(hint_lines)


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

DISCIPLINE: Synthesise only suspicious/malicious activity threading across artifacts.
If the per-artifact summaries describe normal baseline activity (default Windows tasks,
expected user browsing, legitimate vendor RMM, routine logons), the right synthesis is
"no cross-artifact attacker activity identified" — NOT a story about benign behaviour.
A short, honest synthesis beats a padded one. Mark anything you ARE inferring with
explicit confidence and what would invalidate it.

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
        return call_llm(synthesis_user_prompt, synthesis_system_prompt, llm_config, run_id=run_id)
    except Exception as e:  # noqa: BLE001
        log(f"[LLM] Synthesis call failed: {e}", "warning")
        return None


def _extract_event_timestamp(row):
    """Best-effort timestamp extraction from a finding row.

    Findings come from heterogeneous sources (SIGMA, UAL pre-detected, state
    snapshots) and use different keys. Returns ISO string or empty string.
    State-snapshot rows have no event time and sort first.
    """
    if not isinstance(row, dict):
        return ""
    for k in ("_timestamp", "_finding_time", "createdDateTime", "activityDateTime",
              "CreationTime", "TimeGenerated", "@timestamp"):
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
    inner = row.get("matched_record")
    if isinstance(inner, dict):
        for k in ("CreationTime", "createdDateTime", "activityDateTime", "@timestamp"):
            v = inner.get(k)
            if isinstance(v, str) and v:
                return v
    return ""


def _correlation_id(row):
    """Extract Microsoft's canonical correlation identifier from a row.

    Used for dedup at prompt-rendering time. The Graph and UAL collectors
    both pass the same logical event through with the same correlationId
    (Microsoft's own join key) — that's how we drop duplicates without a
    fragile RecordType / Operation allowlist.

    Returns None if the row carries no correlation field. Such rows are
    NEVER dropped (we'd rather show duplicates than hide events).
    """
    if not isinstance(row, dict):
        return None
    inner = row.get("matched_record") if isinstance(row.get("matched_record"), dict) else {}
    for key in ("correlationId", "CorrelationId", "correlation_id"):
        v = row.get(key) or inner.get(key)
        if v:
            return v
    return None


# When the same correlationId appears in multiple sources, prefer the richer
# Graph schema (Azure.Audit) over UAL's flatter Office 365 management API
# shape. Higher number wins.
_TIMELINE_SOURCE_PRIORITY = {
    "Azure.Audit": 5,
    "Azure.SignIn": 4,
    "Azure.UnifiedAudit": 3,
    "Azure.SignIn.Pivot": 2,
}


def _row_source(row):
    """Best-effort source-name extraction (used for dedup priority)."""
    if not isinstance(row, dict):
        return ""
    return (
        row.get("_source")
        or (row.get("matched_record") or {}).get("_source")
        or ""
    )


def _is_state_snapshot(row):
    """A row is a state snapshot when the pipeline tagged it as such.

    Only the Azure pipeline sets `_state_snapshot=True` (currently for
    `Azure.CAPolicy` and `Azure.Federation` — their config dumps, not
    timeline events). Forensic on-prem rows never carry this flag, so the
    state-vs-event split degrades cleanly to "everything is an event" for
    other callers.
    """
    if not isinstance(row, dict):
        return False
    return bool(row.get("_state_snapshot"))


def _analyze_timeline(run_id, all_results, llm_config, anonymizer, log):
    """Single-pass analysis for small Azure runs.

    Three rendering disciplines that the previous version got wrong:

    1. **State snapshots are not events.** Rows tagged `_state_snapshot=True`
       (e.g. CA policy / federation config dumps) get rendered in a separate
       "STATE AT SCAN TIME" section, with their `lastModifiedDateTime` (when
       the config last changed) explicitly distinguished from the scan time
       (when we observed it). This stops the LLM confabulating "policy
       disabled at <scan time>" as if it were an attacker action.

    2. **Dedup by correlationId, not by source.** When the same logical
       event appears in both `Azure.Audit` and `Azure.UnifiedAudit` (each
       carries Microsoft's canonical `correlationId`), keep the highest-
       fidelity copy. Generic and attack-pattern-agnostic — no allowlist
       of "interesting" Operations.

    3. **System prompt explicitly forbids treating state as events.**
       Backed up by structural separation in the prompt.

    Returns the narrative string or None on failure.
    """
    # ---- Step 1: flatten + bucket into state-snapshots vs. timed events
    state_rows = []
    event_rows = []
    aggregated_mitre = []
    severity_counts = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

    for artifact, rows in all_results.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            sev = (row.get("_severity") or row.get("severity") or "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            for t in row.get("mitre_attack", []) or []:
                if isinstance(t, dict) and t.get("id"):
                    aggregated_mitre.append(t["id"])
            if _is_state_snapshot(row):
                state_rows.append((artifact, row))
            else:
                event_rows.append((_extract_event_timestamp(row), artifact, row))

    if not state_rows and not event_rows:
        return None

    # ---- Step 2: mask everything in one pass for consistent anonymization
    if anonymizer:
        try:
            all_dicts = [r for _, r in state_rows] + [r for _, _, r in event_rows]
            masked = anonymizer.mask_data(all_dicts)
            ns = len(state_rows)
            state_rows = [(art, m) for (art, _), m in zip(state_rows, masked[:ns])]
            event_rows = [(ts, art, m) for (ts, art, _), m in zip(event_rows, masked[ns:])]
        except Exception as ex:
            log(f"[LLM] Timeline masking failed (continuing unmasked): {ex}", "warning")

    # ---- Step 3: dedup events by correlationId (keep highest-priority source)
    deduped = []
    seen = {}  # corr_id -> index into the deduped list
    for ts, artifact, row in event_rows:
        cid = _correlation_id(row)
        if not cid:
            deduped.append((ts, artifact, row))
            continue
        pri = _TIMELINE_SOURCE_PRIORITY.get(_row_source(row), 1)
        if cid in seen:
            existing_idx = seen[cid]
            existing_pri = _TIMELINE_SOURCE_PRIORITY.get(
                _row_source(deduped[existing_idx][2]), 1)
            if pri > existing_pri:
                deduped[existing_idx] = (ts, artifact, row)
        else:
            seen[cid] = len(deduped)
            deduped.append((ts, artifact, row))

    dropped = len(event_rows) - len(deduped)
    if dropped > 0:
        log(f"[LLM] Timeline: deduped {dropped} events by correlationId")

    # Sort timed events chronologically (empty timestamps float to top)
    deduped.sort(key=lambda x: x[0])

    # ---- Step 4: render the STATE section
    state_lines = []
    for artifact, row in state_rows:
        rec = row.get("matched_record") if isinstance(row.get("matched_record"), dict) else row
        # Pull state-friendly identifiers
        name = (
            rec.get("displayName")
            or rec.get("name")
            or row.get("rule_title")
            or row.get("_description")
            or "(unnamed)"
        )
        # State entries have a real "when last changed" field in
        # `lastModifiedDateTime` (Graph) or `_last_modified` (custom). NOT
        # the scan time — that's `_finding_time`, which we deliberately
        # strip from this rendering.
        last_mod = (
            rec.get("lastModifiedDateTime")
            or rec.get("_last_modified")
            or rec.get("modifiedDateTime")
            or "(unknown)"
        )
        sev = (row.get("_severity") or row.get("severity") or "?").lower()
        descr = row.get("_description") or row.get("rule_description") or ""
        # Render a concise summary; keep the raw record for fact-checking
        rec_str = json.dumps(
            {k: v for k, v in rec.items() if k not in ("_finding_time", "_state_snapshot")},
            default=str,
        )
        if len(rec_str) > 800:
            rec_str = rec_str[:800] + "...(truncated)"
        state_lines.append(
            f"- [{artifact}] [{sev}] {name} (last modified: {last_mod}) — {descr} :: {rec_str}"
        )

    # ---- Step 5: render the EVENT timeline
    event_lines = []
    for ts, artifact, row in deduped:
        ts_label = ts or "(no-timestamp)"
        sev = (row.get("_severity") or row.get("severity") or "?").lower()
        desc = row.get("_description") or row.get("rule_title") or row.get("rule_description") or ""
        rec = row.get("matched_record")
        if rec is not None:
            rec_str = json.dumps(rec, default=str)
        else:
            rec_str = json.dumps({k: v for k, v in row.items() if not k.startswith("_")},
                                 default=str)
        if len(rec_str) > 1000:
            rec_str = rec_str[:1000] + "...(truncated)"
        event_lines.append(f"{ts_label} [{sev}] [{artifact}] {desc} :: {rec_str}")

    # Defensive cap so a degenerate run can't blow the LLM context window
    truncated_note = []
    if len(event_lines) > 600:
        truncated_note.append(f"... ({len(deduped) - 600} more events truncated)")
        event_lines = event_lines[:600]

    # ---- Step 6: pick the macro DFIR playbook
    macro_body = ""
    macro_name = ""
    try:
        from services.agentic.skills import select_macro_skill, get_macro_body
        artifact_names = list(all_results.keys())
        macro_name = select_macro_skill(
            aggregated_mitre=aggregated_mitre,
            severity_counts=severity_counts,
            artifact_names=artifact_names,
        ) or ""
        macro_body = get_macro_body(macro_name) if macro_name else ""
    except Exception as ex:
        log(f"[LLM] Timeline: skill select failed (continuing without macro): {ex}", "warning")

    if macro_name:
        log(f"[LLM] Timeline: using macro '{macro_name}'")

    # Optional model upgrade for the timeline pass. Operators that want
    # Sonnet-class quality on the single analytic call (vs cheaper Haiku for
    # fan-out) can set agentic.timeline_model in their LLM config. Logged so
    # the operator sees which model actually ran.
    timeline_model = (llm_config.get('agentic', {}) or {}).get('timeline_model')
    if timeline_model:
        log(f"[LLM] Timeline: using model override '{timeline_model}'")

    # ---- Step 7: build the prompt with explicit state-vs-event discipline
    state_section = (
        "\n## STATE AT SCAN TIME (point-in-time observations, NOT events)\n"
        "These are configuration snapshots, not things that happened during the timeline.\n"
        "Each entry shows when the config was *last modified* — that is the only real\n"
        "timestamp on these rows. The scan time is when we OBSERVED the state, not when\n"
        "it changed.\n\n"
        + "\n".join(state_lines)
        if state_lines else
        "\n## STATE AT SCAN TIME\n(no state snapshots in this run)\n"
    )

    event_section = (
        "\n## CHRONOLOGICAL EVENT TIMELINE\n"
        "Each line: `<timestamp> [<severity>] [<artifact>] <description> :: <record>`.\n"
        "These ARE things that happened in time order. Use them to build the chain.\n\n"
        + "\n".join(event_lines + truncated_note)
        if event_lines else
        "\n## CHRONOLOGICAL EVENT TIMELINE\n(no time-anchored events in this run)\n"
    )

    system_prompt = f"""You are a senior DFIR lead writing a single coherent investigation report.

DISCIPLINE:
- The input has TWO sections: state snapshots (current config) and a chronological event timeline.
- State entries describe how things are CURRENTLY configured. They are NOT events. Do NOT narrate them as if they happened during the timeline. The "last modified" field is when the config last changed; the scan time is when we observed it.
- Events have real timestamps. Tell the story in time order. Connect events that share actors / IPs / app IDs / target resources.
- If a state observation is *relevant* to the events (e.g. "MFA policy is currently disabled, which would explain how the bypass succeeded"), call that out as context — but never as a chained event with a fabricated event time.
- Stay strictly grounded. Don't invent threat actor names, tools, or activity. If a connection looks plausible but not certain, mark it as an inference with confidence.
- If the timeline shows nothing actually suspicious, say so plainly. A short honest narrative beats a padded one.

## DOMAIN PLAYBOOK
{macro_body}
"""

    user_prompt = f"""## RUN CONTEXT
- Time-anchored events: {len(deduped)}
- State snapshots: {len(state_rows)}
- Severity rollup: {json.dumps(severity_counts)}
- Distinct MITRE techniques observed: {sorted(set(aggregated_mitre))[:40]}
- Artifacts merged: {sorted(all_results.keys())}
{state_section}
{event_section}

## YOUR DELIVERABLE
1. **Executive narrative** (≤300 words): what happened in time order, anchored on real event timestamps. Reference state observations where they explain the events, but never as chained events with their own event times.
2. **Identified chain(s)**: bullet list. Each chain: a 1-line label + the events that compose it (cite by timestamp + artifact).
3. **Confidence**: low / medium / high with one-line justification.
4. **Top 3 actions for the SOC**: ranked, each with a single sentence of "why".
5. **Calibration check**: 1-2 sentences on what would invalidate this narrative.
"""

    try:
        return call_llm(user_prompt, system_prompt, llm_config,
                        run_id=run_id, model_override=timeline_model)
    except Exception as e:  # noqa: BLE001
        log(f"[LLM] Timeline call failed: {e}", "warning")
        return None


def analyze_artifacts(run_id, all_results, llm_config, anonymizer=None, log_func=None,
                      pipeline_kind="agentic", master_prompt=None):
    """Run LLM analysis on each artifact's results using parallel execution.

    `pipeline_kind` tells the analyzer what shape the data has:
      - "azure":   chronological log events (signins, audit, UAL). Eligible
                   for the single timeline pass when small.
      - "aws":     chronological CloudTrail / GuardDuty / AccessAnalyzer
                   events. Same chronological treatment as "azure" —
                   eligible for the cross-artifact timeline pass.
      - "agentic": forensic artifacts from Velociraptor (registry parses,
                   browser histories, autoruns, etc). NOT chronological;
                   always fan out per-artifact. This is the default so
                   existing on-prem callers keep their behavior unchanged.
    """
    from services.workflow_service import add_log_to_run

    def log(msg, level="info"):
        if log_func:
            log_func(msg, level)
        add_log_to_run(run_id, msg, level)

    summaries = {}
    artifacts_list = list(all_results.keys())

    if not artifacts_list:
        return summaries

    # ---- Adaptive strategy (Azure pipeline only) ----
    # When the merged event volume is small enough to fit in one LLM context,
    # add a cross-artifact timeline pass on top of the normal per-artifact
    # fan-out. The timeline pass sees every event with its real timestamp
    # and narrates the chain — cross-event correlations like "MFA disabled
    # 11 minutes before the credential was planted" are visible to it but
    # NOT to the per-artifact synthesis (which only sees titles+severities).
    # The fan-out then produces the per-rule structured findings the report
    # appendix renders, matching the on-prem (endpoint) report shape.
    #
    # Gated to pipeline_kind="azure" because forensic artifacts (the on-prem
    # agentic flow) aren't a chronological event stream — registry/browser
    # data render badly as a timeline. Velociraptor scans always fan out
    # without the extra timeline call.
    #
    # Threshold tunable via llm_config.agentic.timeline_threshold;
    # 0 disables the timeline-pass add-on entirely.
    total_rows = sum(len(rows) for rows in all_results.values())
    timeline_threshold = int(llm_config.get('agentic', {}).get('timeline_threshold', 500) or 0)
    timeline_added = False
    if pipeline_kind in ("azure", "aws") and 0 < total_rows <= timeline_threshold:
        log(
            f"[LLM] Small {pipeline_kind.upper()} run ({total_rows} rows <= {timeline_threshold}); "
            f"adding cross-artifact timeline pass on top of {len(artifacts_list)}-artifact fan-out"
        )
        timeline_text = _analyze_timeline(run_id, all_results, llm_config, anonymizer, log)
        if timeline_text:
            summaries["__timeline__"] = timeline_text
            timeline_added = True
        else:
            log("[LLM] Timeline pass returned empty; continuing with fan-out only", "warning")

    # ---- Fan-out (one LLM call per artifact) ----
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
                anonymizer, finding_meta, log, run_id, master_prompt,
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
                # Wrap with operator-friendly hint if the underlying cause is
                # an invalid model ID (the most common operator-config bug).
                _provider = (llm_config.get('agentic') or {}).get('online_llm', {}).get('provider', '?')
                _model = (llm_config.get('agentic') or {}).get('online_llm', {}).get('model', '?')
                log(f"[LLM] Error for {artifact}: {explain_llm_error(str(error), _model, _provider)}", "warning")
            else:
                log(f"[LLM] Analysis complete for {artifact} ({completed}/{len(artifacts_list)})")

    # If ALL analyses failed, raise an exception so the pipeline knows
    if error_count == len(artifacts_list) and len(artifacts_list) > 0:
        raise RuntimeError(
            f"All {error_count} LLM analyses failed. Most common cause: invalid "
            f"model ID in Settings → Agentic → Online LLM. Check the per-artifact "
            f"warnings above for the exact upstream error."
        )

    # Synthesis pass: cross-artifact narrative anchored on a macro DFIR
    # playbook. Best-effort — never breaks the pipeline if it fails.
    # Stored under a reserved key the report layer can render distinctly.
    #
    # Skip when the Azure timeline pass already populated __timeline__ —
    # that's the same cross-artifact narrative role and a second LLM call
    # for the same job would be pure redundancy. The on-prem (agentic)
    # path always runs synthesis here because it has no timeline pass.
    if error_count < len(artifacts_list) and not timeline_added:
        synthesis = synthesize_findings(run_id, summaries, llm_config, log_func=log_func)
        if synthesis:
            summaries["__synthesis__"] = synthesis
            log(f"[LLM] Cross-artifact synthesis added ({len(synthesis)} chars)")
    elif timeline_added:
        log("[LLM] Skipping synthesis pass — timeline already provides the cross-artifact narrative")

    # Surface running totals for the operator scanning the workflow log.
    # The dashboard reads the same llm_metrics dict from the workflow row.
    _log_llm_totals(run_id, log)

    return summaries


def file_get_workflow_for_metrics(run_id):
    """Lazy import to avoid a circular import at module load time."""
    from services.file_storage_service import get_workflow as _get
    return _get(run_id)


def _log_llm_totals(run_id, log):
    """Emit one `[LLM] Totals: ...` line summarising the run's LLM spend.

    Centralised so timeline-pass and fan-out paths can both call it without
    risk of double-printing. Quiet if no LLM calls happened.
    """
    try:
        wf = file_get_workflow_for_metrics(run_id)
        m = (wf or {}).get("llm_metrics") or {}
        if m.get("calls"):
            log(
                f"[LLM] Totals: {m['calls']} calls, "
                f"{m.get('input_tokens', 0):,} in / {m.get('output_tokens', 0):,} out, "
                f"~${m.get('cost_usd', 0.0):.4f} ({m.get('model', '?')})"
            )
    except Exception as ex:
        print(f"[ANALYZER] llm totals log failed: {ex}", flush=True)


def is_llm_configured(config) -> bool:
    """True iff an LLM transport is usable (online has an api_key, or offline has a URL).
    The single gate the pipeline consults to decide LLM vs COLLECT-ONLY. Mirrors the
    fusion layer's llm_sim._use_real precedent so the whole product is LLM-optional."""
    agentic_config = (config or {}).get('agentic', {}) or {}
    mode = agentic_config.get('llm_mode', 'online')
    if mode == 'online':
        return bool((agentic_config.get('online_llm') or {}).get('api_key'))
    return bool((agentic_config.get('offline_llm') or {}).get('url'))


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


def ping_llm(config, timeout_seconds=30):
    """Reachability check for the configured LLM. Sends a trivial 1-token
    completion ('ping') and raises on connection error, auth failure, or
    timeout. Used as a pre-flight at the top of the pipeline so the run
    fails immediately when the LLM endpoint is unreachable, instead of
    spending 30 minutes' worth of Velociraptor collection before
    discovering the problem.

    A thread-with-join wrapper enforces the timeout — call_llm itself
    bakes in ONLINE_LLM_TIMEOUT_SECONDS (600s) which is way too long
    for a pre-flight. The inner call uses an intentionally short prompt
    so we get a real connection attempt with minimal token spend.
    """
    import threading

    err_holder: list = [None]

    def _do_ping():
        try:
            # 'ping' is two tokens of prompt and we ask for a single
            # token back — total LLM cost is negligible per pipeline
            # run, and a real round-trip is what proves the endpoint
            # is alive.
            call_llm("ping", "Reply with a single word.", config)
        except Exception as e:  # noqa: BLE001 — we want everything
            err_holder[0] = e

    t = threading.Thread(target=_do_ping, daemon=True)
    t.start()
    t.join(timeout=timeout_seconds)
    if t.is_alive():
        # The thread is still running; the LLM SDK isn't honouring our
        # timeout (or 30s wasn't enough). Surface as a timeout so the
        # caller can fail-fast even though the daemon thread keeps
        # spinning in the background until the SDK gives up.
        raise TimeoutError(
            f"LLM ping did not return within {timeout_seconds}s — endpoint is unreachable"
        )
    if err_holder[0] is not None:
        raise err_holder[0]


def call_llm(prompt, system_prompt, config, run_id=None, model_override=None):
    """Call the configured LLM provider.

    `run_id` is optional; when provided, per-call token usage is accumulated
    onto the workflow row's llm_metrics dict via record_llm_metrics.

    `model_override` is optional; when set, replaces the configured model
    for THIS call only. Used by the single-pass timeline mode to spend a
    bit more on a stronger model since it only fires once per run.
    """
    agentic_config = config.get('agentic', {})
    mode = agentic_config.get('llm_mode', 'online')

    # Resolution order honors the user's "just always use the max" directive
    # while preserving the override path: an explicit operator value wins;
    # otherwise we ask the alias/catalog layer for the model's published
    # max output tokens; otherwise we fall back to the constant default.
    # Clearing the input field in Settings sends `None`/0 here, which
    # re-engages the auto-resolved max — useful escape hatch.
    configured = agentic_config.get('max_response_tokens')
    if configured:
        max_tokens = configured
    else:
        if mode == 'online':
            online_cfg = agentic_config.get('online_llm', {})
            model_input = (model_override or online_cfg.get('model') or '')
            provider_name = online_cfg.get('provider', 'claude')
            model_max = get_model_max_output_tokens(model_input, provider_name)
        else:
            model_max = None
        max_tokens = model_max or MAX_LLM_TOKENS

    context_size = agentic_config.get('ollama_context_size', OLLAMA_CONTEXT_SIZE)
    timeout = agentic_config.get('ollama_timeout', OLLAMA_TIMEOUT_SECONDS)

    if mode == 'online':
        provider_config = dict(agentic_config.get('online_llm', {}))
        if model_override:
            provider_config['model'] = model_override
        return _call_llm_online(prompt, system_prompt, provider_config, max_tokens, run_id)
    else:
        provider_config = dict(agentic_config.get('offline_llm', {}))
        if model_override:
            provider_config['model'] = model_override
        return _call_llm_offline(prompt, system_prompt, provider_config, context_size, timeout, run_id)


def _call_llm_online(prompt, system_prompt, provider_config, max_tokens, run_id=None):
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
        _record_llm_usage(run_id, 'claude', model, response)
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
        _record_llm_usage(run_id, 'openai', model, response)
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
        _record_llm_usage(run_id, 'openrouter', model, response)
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
        _record_llm_usage(run_id, 'gemini', model, response)
        return response.text
    else:
        raise ValueError(f"Unsupported online provider: {provider}")


def _call_llm_offline(prompt, system_prompt, provider_config, context_size, timeout, run_id=None):
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
        body = response.json()
        _record_llm_usage(run_id, 'ollama', model, body)
        return body.get('response', '')
    else:
        raise ValueError(f"Unsupported offline provider: {provider}")
