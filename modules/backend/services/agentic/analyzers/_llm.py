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
