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
    # Same Gemini rates under the bare ids the DIRECT google provider emits.
    # The `google/...` rows above only match OpenRouter-style ids, so once
    # Gemini became directly selectable its model ids (`gemini-2.5-flash`)
    # matched nothing and every Gemini run reported $0 — the tokens were
    # recorded, the spend was not.
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.075, 0.30),
    # Ollama Cloud is deliberately absent: it bills by subscription tier, not
    # per token, so any per-MTok figure here would be invented. Unknown models
    # record token volume with $0 cost, which is the honest answer.
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
    if best is not None:
        cin, cout = _LLM_COST_PER_MTOK[best]
        return (in_tokens / 1_000_000.0) * cin + (out_tokens / 1_000_000.0) * cout
    # Fallback: the OpenRouter catalog carries per-token pricing for 300+ models
    # (incl. DeepSeek, Qwen, Mistral, …) so any model the operator picks under
    # Settings > Agentic > OpenRouter is priced without hardcoding. Pricing values
    # are USD PER TOKEN (not per-million).
    try:
        from services.llm_catalogs.openrouter import load_catalog
        for m in (load_catalog() or []):
            if key in (str(m.get("id", "")).lower(), str(m.get("canonical_id", "")).lower()):
                pr = m.get("pricing") or {}
                pin = float(pr.get("prompt") or 0.0)
                pout = float(pr.get("completion") or 0.0)
                if pin or pout:
                    return in_tokens * pin + out_tokens * pout
                break
    except Exception:
        pass
    return 0.0


def _case_log(run_id, action, status="info", detail=""):
    """Best-effort line into the Case Analysis activity log.

    `run_id` is the case_id on every fusion chain (report / chat / synthesize);
    log_case_event itself no-ops when the id is not a real case, so this is safe
    to call from the transport layer unconditionally. Telemetry only — it must
    never raise into an LLM call.
    """
    if not run_id:
        return
    try:
        from services.fusion.store import log_case_event
        log_case_event(run_id, action, status, detail)
    except Exception:  # noqa: BLE001
        pass


# Providers that speak the OpenAI chat-completions API. They differ ONLY by
# base_url, so one adapter serves all of them — the openrouter branch was
# already doing exactly this, just written out a second time.
#
# `openai` maps to None: the SDK's own default endpoint. Everything else is a
# gateway that happens to implement the same wire format, which is why LiteLLM,
# vLLM and LM Studio need no adapter of their own — they are URLs, not
# integrations.
OPENAI_COMPATIBLE_BASE_URLS = {
    'openai': None,
    'openrouter': 'https://openrouter.ai/api/v1',
    'ollama-cloud': 'https://ollama.com/v1',
}

# Token accounting is identical for all of them (prompt_tokens /
# completion_tokens), including the offline OpenAI-compatible endpoint.
_OPENAI_SHAPED = set(OPENAI_COMPATIBLE_BASE_URLS) | {'openai-compatible'}


def _wrap_decode_errors(provider_name, fn):
    """Turn a proxy's HTML error page into a readable message.

    Module-level rather than nested inside _call_llm_online: the shared
    OpenAI-compatible adapter needs it too, and a nested definition is
    invisible from there — which surfaced as
    "NameError: name '_wrap_decode_errors' is not defined" on the first real
    call through a self-hosted endpoint.
    """
    try:
        return fn()
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{provider_name} returned non-JSON response (likely upstream "
            f"timeout on a large prompt; the proxy returned an HTML error "
            f"page). Try a shorter prompt or raise ONLINE_LLM_TIMEOUT_SECONDS. "
            f"Original parse error: {e}"
        ) from e


def _call_openai_compatible(provider, prompt, system_prompt, api_key, model,
                            max_tokens, base_url=None, timeout=None, run_id=None):
    """One request path for every OpenAI chat-completions endpoint.

    `api_key` may be a placeholder for self-hosted servers that ignore auth —
    the SDK refuses to construct a client without one, so callers pass a dummy
    rather than leaving it empty.
    """
    import openai
    kwargs = {'api_key': api_key or 'not-needed',
              'timeout': timeout or ONLINE_LLM_TIMEOUT_SECONDS}
    if base_url:
        kwargs['base_url'] = base_url
    client = openai.OpenAI(**kwargs)
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    label = provider.replace('-', ' ').title()
    response = _wrap_decode_errors(label, lambda: client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
        temperature=0.1,
    ))
    _record_llm_usage(run_id, provider, model, response)
    return response.choices[0].message.content


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
        elif provider in _OPENAI_SHAPED:
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
        elif isinstance(response, dict) and 'in_tokens' in response:
            # subscription CLI providers: already normalised by subscription_cli
            in_tokens = int(response.get('in_tokens', 0) or 0)
            out_tokens = int(response.get('out_tokens', 0) or 0)
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
        elif provider == "codex-subscription":
            # Present in get_model_context_length but was missing here, so a
            # subscription model got the constant default output cap instead of
            # its real one — silently truncating long reports.
            from services.llm_catalogs import codex as catalog_module
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

def get_model_context_length(model_input: str, provider: str):
    """Resolve the model's CONTEXT WINDOW (input+output ceiling), or None.

    Same walk as get_model_max_output_tokens — alias table, then the provider's
    catalog, then the OpenRouter mirror — but reading `context_length`. Exists so
    the payload budget can be derived from the model actually selected instead of
    a constant written for a hypothetical one (services/fusion/budget.py).
    """
    if not model_input:
        return None
    alias_entry = MODEL_ALIASES.get(model_input)
    if alias_entry and alias_entry.get("context_length"):
        return alias_entry["context_length"]

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
        elif provider == "codex-subscription":
            from services.llm_catalogs import codex as catalog_module
    except Exception:
        catalog_module = None

    if catalog_module:
        try:
            models = catalog_module.load_catalog()
            resolved = resolve_model_alias(model_input, provider)
            for m in models:
                if m.get("id") == resolved or m.get("id") == model_input \
                        or m.get("canonical_id") == resolved:
                    if m.get("context_length"):
                        return m["context_length"]
        except Exception:
            pass

    if provider in ("claude", "openai", "gemini"):
        try:
            from routes.config_routes import _canonical_from_direct_sdk_id
            from services.llm_catalogs import openrouter as or_catalog
            canonical = _canonical_from_direct_sdk_id(model_input, provider)
            if canonical:
                for m in or_catalog.load_catalog():
                    cid = m.get("id") or ""
                    bare = cid[1:] if cid.startswith("~") else cid
                    if bare == canonical and m.get("context_length"):
                        return m["context_length"]
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


def is_llm_configured(config) -> bool:
    """True iff an LLM transport is usable (online has an api_key, or offline has a URL).
    The single gate the pipeline consults to decide LLM vs COLLECT-ONLY. Mirrors the
    fusion layer's llm_sim._use_real precedent so the whole product is LLM-optional."""
    agentic_config = (config or {}).get('agentic', {}) or {}
    mode = agentic_config.get('llm_mode', 'online')
    if mode == 'online':
        online = agentic_config.get('online_llm') or {}
        # Subscription providers authenticate through a vendor CLI, so there is
        # no api_key to test — "configured" means the CLI is installed and a
        # credential is stored.
        if subscription_provider_ready(online.get('provider')):
            return True
        return bool(online.get('api_key'))
    return bool((agentic_config.get('offline_llm') or {}).get('url'))


def subscription_provider_ready(provider) -> bool:
    """True iff `provider` is a CLI-subscription provider that is ready to use.

    Import is local and failure-tolerant: the subscription path is optional and
    must never be able to break the api-key providers.
    """
    try:
        from services.agentic import subscription_cli as sub
        if not sub.is_subscription_provider(provider):
            return False
        return sub.is_installed(provider) and sub.has_credentials(provider)
    except Exception:  # noqa: BLE001
        return False


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

    # Subscription providers carry no api_key — they authenticate through the
    # vendor CLI, so they must bypass this gate entirely and are handled below.
    from services.agentic import subscription_cli as _sub
    _is_subscription = _sub.is_subscription_provider(provider)

    if not api_key and not _is_subscription:
        raise ValueError("Online LLM API key not configured. Set it in Settings.")

    # Big report-generation prompts (~30-50K input tokens) routinely exceed
    # the SDK default 60s HTTP timeout. When that happens upstream of
    # OpenRouter, Cloudflare returns an HTML timeout page and the OpenAI
    # SDK fails with a confusing json.JSONDecodeError. Catch that
    # specifically and surface a clearer message; bump every client's
    # timeout to ONLINE_LLM_TIMEOUT_SECONDS (default 600s).
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
    elif provider in OPENAI_COMPATIBLE_BASE_URLS:
        return _call_openai_compatible(
            provider, prompt, system_prompt, api_key, model, max_tokens,
            base_url=OPENAI_COMPATIBLE_BASE_URLS[provider], run_id=run_id)
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
    elif _is_subscription:
        # Spend the operator's subscription via the vendor CLI instead of a
        # metered API key. The connection outcome is logged to the case's
        # activity log so an analyst can see, in the Case Analysis Log, whether
        # the subscription answered — run_id IS the case_id on every fusion
        # chain, and log_case_event no-ops for non-case run ids.
        spec_label = _sub.PROVIDERS[provider]['label']
        _case_log(run_id, f"LLM · calling {spec_label}", "info",
                  f"model {model or 'CLI default'} via the {provider} CLI "
                  f"(subscription auth, needs internet)")
        try:
            result = _sub.run_prompt(
                provider, prompt,
                system_prompt=system_prompt,
                model=(model or None),
                timeout=ONLINE_LLM_TIMEOUT_SECONDS,
            )
        except _sub.SubscriptionCLIError as e:
            _case_log(run_id, f"LLM · {spec_label} connection failed", "error",
                      f"{e.reason}: {e}")
            raise
        except Exception as e:
            _case_log(run_id, f"LLM · {spec_label} call failed", "error", str(e))
            raise
        _case_log(run_id, f"LLM · {spec_label} responded", "success",
                  f"{len(result.get('text') or ''):,} chars, "
                  f"{result.get('in_tokens', 0):,} in / "
                  f"{result.get('out_tokens', 0):,} out tokens")
        _record_llm_usage(run_id, provider, model, result)
        return result['text']
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
    elif provider == 'openai-compatible':
        # LiteLLM proxy / vLLM / LM Studio / Ollama's own /v1 — all speak the
        # OpenAI wire format, so they are one provider distinguished by URL
        # rather than one integration each. "Offline" here means self-hosted,
        # not local: the server is usually a different host on the network.
        #
        # `url` is the OpenAI-style base (…/v1). Unlike the native ollama branch
        # this cannot carry num_ctx — the OpenAI schema has no equivalent — so a
        # server needing a larger context window must be configured for it
        # server-side. That is the reason the native branch above is kept.
        api_key = provider_config.get('api_key') or ''
        return _call_openai_compatible(
            'openai-compatible', prompt, system_prompt, api_key, model,
            max_tokens=provider_config.get('max_tokens') or MAX_LLM_TOKENS,
            base_url=url, timeout=timeout, run_id=run_id)
    else:
        raise ValueError(f"Unsupported offline provider: {provider}")
