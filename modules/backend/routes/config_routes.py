#!/usr/bin/env python3
"""
Config Routes - Configuration endpoints (frontend config, cloud config)
"""

import json
import time
from flask import Blueprint, jsonify, request
from services.file_storage_service import load_frontend_config, save_frontend_config

config_bp = Blueprint('config', __name__)

# What GET /api/config substitutes for a saved secret. Anything arriving back
# with this prefix means "the operator did not retype the key, keep the stored
# one" — it is never a credential. Named because it is easy to guess wrong: it
# is bullets, not asterisks, and a mismatched guess sends the mask itself to
# the provider as a key.
_API_KEY_MASK_PREFIX = '••••'

# Default configuration (agentic settings only - velociraptor uses container's api.config.yaml)
DEFAULT_CONFIG = {
    "agentic": {
        "llm_mode": "online",
        "offline_llm": {
            "provider": "ollama",
            "model": "llama3.3:70b",
            "url": "http://localhost:11434"
        },
        "online_llm": {
            "provider": "openrouter",
            "api_key": "",
            "model": "~anthropic/claude-haiku-latest"
        }
    }
}

# Default cloud configuration
DEFAULT_CLOUD_CONFIG = {
    "provider": "aws",
    "aws": {
        "access_key_id": "",
        "secret_access_key": "",
        "region": "us-east-1",
        "session_token": ""
    },
    "azure": {
        "tenant_id": "",
        "client_id": "",
        "client_secret": "",
        "subscription_id": ""
    }
}


def _deep_merge(base, update):
    """Deep merge update into base dict."""
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _load_config():
    """Load configuration from database or return defaults."""
    try:
        saved_config = load_frontend_config()
        if saved_config:
            config = DEFAULT_CONFIG.copy()
            _deep_merge(config, saved_config)
            return config
    except Exception as e:
        print(f"Error loading config: {e}")
    return DEFAULT_CONFIG.copy()


def _save_config(config):
    """Save configuration to database."""
    save_frontend_config(config)


def _load_cloud_config():
    """Load cloud configuration from database."""
    from services.file_storage_service import load_cloud_config
    try:
        saved = load_cloud_config()
        if saved:
            config = DEFAULT_CLOUD_CONFIG.copy()
            _deep_merge(config, saved)
            return config
    except Exception as e:
        print(f"Error loading cloud config: {e}")
    return DEFAULT_CLOUD_CONFIG.copy()


def _save_cloud_config(config):
    """Save cloud configuration to database."""
    from services.file_storage_service import save_cloud_config
    save_cloud_config(config)


# =============================================================================
# LLM Model Aliases Endpoint
# =============================================================================

@config_bp.route('/api/config/models', methods=['GET'])
def get_available_models():
    """Get available LLM model aliases for dropdown selection."""
    try:
        from services.agentic.analyzers import MODEL_ALIASES
        return jsonify({
            "models": list(MODEL_ALIASES.keys()),
            "aliases": MODEL_ALIASES
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _parse_catalog_query():
    """Parse and clamp the q/limit/offset query params shared by every
    per-provider model search endpoint."""
    q = request.args.get('q', '')
    try:
        limit = max(1, min(int(request.args.get('limit', 10)), 100))
    except (TypeError, ValueError):
        limit = 10
    try:
        offset = max(0, int(request.args.get('offset', 0)))
    except (TypeError, ValueError):
        offset = 0
    return q, limit, offset


# --- OpenRouter mirror fallback -----------------------------------------
# Maps direct-provider name → OpenRouter id prefix (incl. the `~` family-
# alias prefix OpenRouter emits for "-latest" entries).
_OR_VENDOR_PREFIX = {
    "claude": "anthropic/",
    "openai": "openai/",
    "gemini": "google/",
}


def _direct_sdk_id_from_canonical(canonical: str, provider: str):
    """Convert an OpenRouter canonical id (`anthropic/claude-opus-4.6`)
    into the id the direct-provider SDK expects (`claude-opus-4-6`).

    Returns None if the canonical id doesn't belong to this provider.
    """
    if not canonical:
        return None
    vendor = _OR_VENDOR_PREFIX.get(provider)
    if not vendor:
        return None
    # OpenRouter uses `~vendor/family` for "-latest" auto-resolve entries;
    # peel the tilde first so the prefix match still works.
    bare = canonical[1:] if canonical.startswith("~") else canonical
    if not bare.startswith(vendor):
        return None
    bare = bare[len(vendor):]
    if provider == "claude":
        # Anthropic native ids use dashes between version components, while
        # OpenRouter mirrors use dots: claude-opus-4.6 → claude-opus-4-6.
        return bare.replace(".", "-")
    # OpenAI + Google keep dots in their native model ids (gpt-4.1,
    # gemini-2.5-pro), so identity-strip-prefix is enough.
    return bare


def _canonical_from_direct_sdk_id(direct_id: str, provider: str):
    """Inverse of _direct_sdk_id_from_canonical. Used to look up an
    OpenRouter mirror entry's metadata when the operator's saved model
    is in direct-SDK form (e.g. `claude-opus-4-6` ↔
    `anthropic/claude-opus-4.6`)."""
    if not direct_id:
        return None
    vendor = _OR_VENDOR_PREFIX.get(provider)
    if not vendor:
        return None
    if provider == "claude":
        # Convert version-separator dashes back to dots. Best-effort: a
        # generic dash→dot would mangle ids like `claude-opus`. Use a
        # regex that only swaps `-<digit>-<digit>` patterns.
        import re
        cooked = re.sub(r"-(\d+)-(\d+)", r"-\1.\2", direct_id)
        return vendor + cooked
    return vendor + direct_id


def _openrouter_mirror_for_provider(provider: str, q: str = ""):
    """Pull OpenRouter catalog entries for the matching vendor and
    re-shape them as direct-provider entries. Used as a fallback when
    the operator hasn't configured a direct API key (so the direct
    catalog is empty) — gives them a rich dropdown anyway.

    Each entry's `id` is the direct-SDK id (so picking it and running
    `call_llm` actually works against the direct provider), while
    `canonical_id` keeps the OpenRouter id so metadata stays joinable.
    """
    vendor = _OR_VENDOR_PREFIX.get(provider)
    if not vendor:
        return []

    from services.llm_catalogs import openrouter as or_catalog
    or_models = or_catalog.load_catalog()

    q_lower = (q or "").strip().lower()
    out = []
    for m in or_models:
        cid = m.get("id") or ""
        # Accept both `vendor/…` and the `~vendor/…` family-alias form.
        bare_cid = cid[1:] if cid.startswith("~") else cid
        if not bare_cid.startswith(vendor):
            continue
        direct_id = _direct_sdk_id_from_canonical(cid, provider)
        if not direct_id:
            continue
        # Substring filter — match on either the direct id or the
        # OpenRouter name/canonical so operators searching by either
        # find what they want.
        if q_lower:
            if (q_lower not in direct_id.lower()
                    and q_lower not in cid.lower()
                    and q_lower not in (m.get("name") or "").lower()):
                continue
        out.append({
            "id": direct_id,
            "canonical_id": cid,
            "name": m.get("name") or direct_id,
            "max_output_tokens": m.get("max_output_tokens"),
            "context_length": m.get("context_length"),
            "pricing": m.get("pricing"),
            "created": m.get("created"),
            "deprecated": False,
            "enriched_from": "openrouter_mirror",
        })
    return out


def _alias_entries_for_provider(provider: str):
    """Project MODEL_ALIASES entries that work for the given provider into
    the same per-entry shape as catalog entries. Pulled into every
    per-provider search response so operators always see the friendly
    aliases — even when there's no API key configured for that provider
    and the live catalog is empty.

    Each alias entry is enriched against the OpenRouter catalog (via the
    alias's `openrouter` mapping as canonical_id) so the dropdown shows
    full Context / Max output / Pricing for aliases too.
    """
    from services.agentic.analyzers import MODEL_ALIASES
    from services.llm_catalogs import openrouter as or_catalog

    or_models = or_catalog.load_catalog()
    or_by_id = {m["id"]: m for m in or_models}

    out = []
    for alias_name, entry in MODEL_ALIASES.items():
        if provider not in entry:
            continue
        canonical = entry.get("openrouter") or f"alias/{alias_name}"
        or_match = or_by_id.get(canonical) or {}
        out.append({
            "id": alias_name,
            "canonical_id": canonical,
            "name": alias_name,
            "max_output_tokens": entry.get("max_output_tokens") or or_match.get("max_output_tokens"),
            "context_length": or_match.get("context_length"),
            "pricing": or_match.get("pricing"),
            "created": or_match.get("created"),
            "deprecated": False,
            "enriched_from": "alias",
        })
    return out


# How long to leave a provider's bootstrap refresh alone after one fails.
#
# "Bootstrap when the catalog file is missing" re-fired on EVERY request,
# because on an air-gapped box the file is missing permanently. The 2026-08-16
# install logged ~15 of these in 24 seconds, each a DNS lookup + HTTPS attempt
# blocking a request thread while the dashboard polled:
#
#   [OPENROUTER-CATALOG] Fetching OpenRouter model catalog from https://openrouter.ai/api/v1/models...
#   [OPENROUTER-CATALOG] [warning] Fetch failed: ... Temporary failure in name resolution
#   ... x15
#
# Five minutes is short enough that a box which has just been given a network
# recovers on its own without anyone thinking about it, and long enough that a
# permanently offline box stops hammering a name it cannot resolve.
#
# Per provider, in memory only: a backend restart is itself a reasonable "try
# again now" signal, and persisting a negative result risks outliving the
# condition that caused it.
_CATALOG_BOOTSTRAP_COOLDOWN_S = 300
_catalog_bootstrap_failed_at: dict = {}


def _serve_catalog(catalog_module, provider_name: str, bootstrap: bool = True):
    """Standard wrapper: prepend alias entries, then catalog matches.

    `bootstrap` triggers a one-shot refresh when the catalog file is
    missing (operator may not have run install bootstrap yet). For
    direct providers this is a no-op when the API key isn't configured
    — `refresh_catalog` returns success=False without raising.

    A failed bootstrap is remembered for _CATALOG_BOOTSTRAP_COOLDOWN_S so an
    offline box stops retrying on every poll. The explicit
    "Update catalog" button calls refresh_catalog() directly and is
    deliberately NOT gated by this — an operator who has just plugged in a
    network should not be told to wait.

    Aliases ALWAYS appear (modulo the search filter) so the dropdown is
    never empty, even when no API key is configured for the provider.
    """
    q, limit, offset = _parse_catalog_query()
    if bootstrap and not catalog_module.load_catalog():
        last_fail = _catalog_bootstrap_failed_at.get(provider_name, 0)
        if (time.time() - last_fail) < _CATALOG_BOOTSTRAP_COOLDOWN_S:
            pass  # cooling down; serve aliases/mirror instead of re-dialling
        else:
            try:
                result = catalog_module.refresh_catalog()
                # refresh_catalog reports failure by return value, not by
                # raising — an unreachable host comes back {'success': False}.
                if isinstance(result, dict) and not result.get("success"):
                    _catalog_bootstrap_failed_at[provider_name] = time.time()
                else:
                    _catalog_bootstrap_failed_at.pop(provider_name, None)
            except Exception as e:
                _catalog_bootstrap_failed_at[provider_name] = time.time()
                print(f"[CATALOG] Bootstrap refresh failed: {e}", flush=True)
    catalog_result = catalog_module.search(q=q, limit=limit, offset=offset)
    q_lower = (q or "").strip().lower()

    combined = []
    seen = set()

    # 1. Direct-catalog entries (populated when the operator has saved
    #    a direct API key — usually 15-50 models per provider).
    for m in catalog_result.get("models", []):
        if m["id"] not in seen:
            combined.append(m)
            seen.add(m["id"])

    # 2. OpenRouter-mirror fallback for direct providers. Gives a rich
    #    dropdown without requiring a direct API key. Each entry's `id`
    #    is the direct-SDK form (e.g. claude-opus-4-6), `canonical_id`
    #    is the OpenRouter id; metadata comes from OpenRouter.
    if provider_name in ("claude", "openai", "gemini"):
        for m in _openrouter_mirror_for_provider(provider_name, q):
            if m["id"] not in seen:
                combined.append(m)
                seen.add(m["id"])

    # 3. Friendly-alias fallback. Only surfaces when steps 1+2 produced
    #    nothing — e.g. offline install with no OpenRouter catalog and
    #    no direct API key. Operators familiar with the codebase don't
    #    need these labels cluttering their dropdown in normal use.
    if not combined:
        for a in _alias_entries_for_provider(provider_name):
            if q_lower and q_lower not in a["id"].lower() \
                    and q_lower not in (a.get("name") or "").lower():
                continue
            if a["id"] not in seen:
                combined.append(a)
                seen.add(a["id"])

    catalog_result["models"] = combined[offset:offset + max(1, int(limit))]
    catalog_result["total"] = len(combined)
    catalog_result["limit"] = limit
    catalog_result["offset"] = offset
    return jsonify(catalog_result)


@config_bp.route('/api/config/openrouter/models', methods=['GET'])
def get_openrouter_models():
    """Search the OpenRouter model catalog persisted on disk.

    Reads the full ~300-model catalog at
    `/app/data/openrouter_models.json`. Catalog is bootstrapped at
    install time and refreshed by the maintenance workflow — see
    `services/llm_catalogs/openrouter.py` and the
    `/api/maintenance/refresh-openrouter-models` route.

    Query params:
        q      — case-insensitive substring (matches model id, name,
                 or canonical_id)
        limit  — max results (default 10)
        offset — pagination cursor
    """
    from services.llm_catalogs import openrouter as catalog_module
    return _serve_catalog(catalog_module, "openrouter", bootstrap=True)


@config_bp.route('/api/config/codex/models', methods=['GET'])
def get_codex_models():
    """Search the Codex-subscription model catalog.

    Sourced from `codex debug models` — the CLI's own catalog, scoped to the
    connected account. The vendor's web /models endpoint is NOT usable here:
    its slugs are refused by `codex exec -m`. See services/llm_catalogs/codex.py.

    Aliases are not prepended: the entitled set is per-account, so a fixed alias
    could name a model this plan cannot use.
    """
    from services.llm_catalogs import codex as catalog_module
    return _serve_catalog(catalog_module, "codex", bootstrap=True)


@config_bp.route('/api/config/anthropic/models', methods=['GET'])
def get_anthropic_models():
    """Search the Anthropic model catalog persisted on disk.

    Catalog is built from Anthropic's `/v1/models` endpoint then
    enriched against the OpenRouter catalog for max_output_tokens /
    context_length / pricing. Requires the operator to have configured
    a Claude API key (the bootstrap fetch is best-effort and skips
    when no key is present)."""
    from services.llm_catalogs import anthropic as catalog_module
    # Direct providers expose the same alias names that map to the
    # `claude` provider in MODEL_ALIASES.
    return _serve_catalog(catalog_module, "claude", bootstrap=True)


@config_bp.route('/api/config/openai/models', methods=['GET'])
def get_openai_models():
    """Search the OpenAI model catalog persisted on disk. Filtered to
    chat/completion-capable models (drops embeddings, audio, image,
    tuning). Enriched from OpenRouter for max_output_tokens /
    context_length / pricing."""
    from services.llm_catalogs import openai as catalog_module
    return _serve_catalog(catalog_module, "openai", bootstrap=True)


@config_bp.route('/api/config/gemini/models', methods=['GET'])
def get_gemini_models():
    """Search the Gemini model catalog persisted on disk. Filtered to
    `generateContent`-capable models. Native max_output_tokens /
    context_length come from Gemini's response; pricing is enriched
    from OpenRouter."""
    from services.llm_catalogs import gemini as catalog_module
    return _serve_catalog(catalog_module, "gemini", bootstrap=True)


@config_bp.route('/api/config/ollama/models', methods=['GET'])
def get_ollama_models():
    """Models a SELF-HOSTED server actually has, asked live.

    Query params: `url` (required), `kind` (ollama | openai-compatible),
    `api_key` (optional, for gateways that require auth).

    Deliberately not routed through _serve_catalog: that machinery serves one
    global on-disk catalog per provider, which is the wrong shape here. The
    answer belongs to one specific host — the operator's server is usually
    another machine on the network, two customers point at different ones, and
    the list changes whenever someone runs `ollama pull` there.

    Errors return 200 with {ok: false, reason, error} rather than a 4xx: the
    settings page asks this on every keystroke in the URL field, and a
    half-typed URL is a normal state to be in, not a failure worth a red
    console entry.
    """
    from services.llm_catalogs.ollama import list_models, OllamaListError
    url = (request.args.get('url') or '').strip()
    kind = (request.args.get('kind') or 'ollama').strip()
    api_key = (request.args.get('api_key') or '').strip() or None
    try:
        models = list_models(url, kind=kind, api_key=api_key)
    except OllamaListError as e:
        return jsonify({"ok": False, "reason": e.reason, "error": e.message,
                        "models": []})
    return jsonify({"ok": True, "models": models, "count": len(models)})


@config_bp.route('/api/config/ollama-cloud/models', methods=['GET'])
def get_ollama_cloud_models():
    """Models Ollama's hosted API offers this key.

    Shaped like the other /api/config/<provider>/models routes so the online
    model combobox can reach it with no special case — it builds the URL from
    the provider id. Without this the box would simply be empty for
    Ollama Cloud, which is the same dead end as an unlisted provider.

    Asked live rather than served from a CatalogStore: the list is key-scoped
    and short, so there is no quota to protect by caching, and a cached copy
    would go stale the moment a plan changes. Never 4xx — a missing or wrong
    key returns an empty list with a reason, because the operator is typing.
    """
    from services.llm_catalogs.ollama import list_cloud_models, OllamaListError
    from services.llm_catalogs.base import get_provider_api_key
    q, limit, offset = _parse_catalog_query()

    # get_provider_api_key, NOT a direct read of online_llm.api_key. The config
    # stores ONE key, belonging to whichever provider is currently selected, so
    # reading the field directly hands it to whoever asks: this route first did
    # exactly that and posted a saved OpenRouter key to ollama.com as a Bearer
    # token. The helper returns the key only when it is this provider's.
    api_key = get_provider_api_key('ollama-cloud')
    if not api_key:
        return jsonify({"models": [], "total": 0, "limit": limit, "offset": offset,
                        "error": "Select Ollama Cloud and save its API key to list models."})
    try:
        models = list_cloud_models(api_key)
    except OllamaListError as e:
        return jsonify({"models": [], "total": 0, "limit": limit, "offset": offset,
                        "error": e.message})

    ql = (q or "").strip().lower()
    if ql:
        models = [m for m in models if ql in m["id"].lower()]
    return jsonify({"models": models[offset:offset + max(1, int(limit))],
                    "total": len(models), "limit": limit, "offset": offset})


@config_bp.route('/api/config/llm/test', methods=['POST'])
def test_llm_connection():
    """Prove the configured LLM actually answers, before a report needs it.

    Until now the only signal was a model-catalog refresh, which proves a key
    can LIST models — not that a completion works, not that the chosen model is
    one this key may use, and nothing at all for a self-hosted server. The first
    real confirmation came mid-case, when a report failed.

    Sends max_tokens=1 with a trivial prompt: enough to exercise auth, routing,
    the model id and the response shape, while costing effectively nothing on a
    metered provider.

    Body is optional and overlays the saved config, so the operator can test
    what is on screen before saving it.
    """
    import time as _time
    from services.agentic.analyzers._llm import call_llm

    overlay = request.get_json(silent=True) or {}
    cfg = _load_config()
    agentic = dict((cfg.get('agentic') or {}))
    for k, v in (overlay.get('agentic') or {}).items():
        if isinstance(v, dict) and isinstance(agentic.get(k), dict):
            merged = dict(agentic[k]); merged.update(v); agentic[k] = merged
        else:
            agentic[k] = v

    # A masked key means "keep what is saved" — the UI never holds the real one.
    # The mask is bullets, matching what GET /api/config returns and what
    # save_config guards on. Checking for '*' here (as this first did) never
    # matched, so the bullet string was sent as the key and every test of an
    # already-saved provider failed as an auth error.
    on = agentic.get('online_llm') or {}
    if isinstance(on.get('api_key'), str) and on['api_key'].startswith(_API_KEY_MASK_PREFIX):
        on = dict(on)
        on['api_key'] = ((cfg.get('agentic') or {}).get('online_llm') or {}).get('api_key', '')
        agentic['online_llm'] = on

    # One token is all this needs; the saved cap would otherwise let a test
    # bill like a real report.
    agentic['max_response_tokens'] = 1

    mode = str(agentic.get('llm_mode', 'online')).lower()
    provider = ((agentic.get('offline_llm') if mode == 'offline'
                 else agentic.get('online_llm')) or {}).get('provider')

    started = _time.time()
    try:
        reply = call_llm("Reply with exactly: OK", "You are a connectivity probe.",
                         {'agentic': agentic})
    except Exception as e:      # noqa: BLE001 — every failure is a REPORTABLE result
        # Classify through the SAME vocabulary chat, report generation and the
        # Analysis-tab reachability banner already use, so an operator sees one
        # consistent, actionable sentence wherever a call fails — not the raw
        # exception here and a friendly reason everywhere else. This is exactly
        # where "no_credit" was found missing: OpenRouter's 402 landed as a bare
        # APIStatusError dump ("Insufficient credits...") instead of "the key is
        # fine, top up or switch provider" — see _classify_llm_error's docstring.
        from services.fusion import llm_sim
        cls = llm_sim.classify_llm_failure(e)
        friendly = cls["reason"] + (f" {cls['fix']}" if cls["fix"] else "")
        return jsonify({
            "success": False, "stage": "prompt", "provider": provider, "mode": mode,
            "elapsed_ms": int((_time.time() - started) * 1000),
            "error": friendly, "code": cls["code"],
            "detail": f"{type(e).__name__}: {e}"[:400],
        })
    return jsonify({
        "success": True, "stage": "prompt", "provider": provider, "mode": mode,
        "elapsed_ms": int((_time.time() - started) * 1000),
        "reply": (reply or "")[:200],
    })


@config_bp.route('/api/config/llm/reachability', methods=['GET'])
def llm_reachability():
    """Cheap, cached "can the configured model actually be reached RIGHT NOW".

    Unlike /api/config/llm/test (operator-triggered, always live, accepts an
    unsaved overlay to test before Save), this is polled passively by the Case
    Analysis page on every navigation into a case and every tab switch, so it
    must default to near-free: when no model/key is configured it costs nothing
    (llm_status() already knows that for free), and when one is configured the
    live probe result is cached briefly — see llm_reachability()'s docstring in
    llm_sim.py for the caching contract.
    """
    from services.fusion import llm_sim
    return jsonify(llm_sim.llm_reachability())


# =============================================================================
# Frontend Configuration Endpoints
# =============================================================================

@config_bp.route('/api/config', methods=['GET'])
def get_config():
    """Get frontend configuration."""
    try:
        config = _load_config()
        # Mask the LLM key the same way GET /api/config/cloud already masks
        # its cloud secrets — this endpoint previously returned it unmasked.
        if config.get('agentic', {}).get('online_llm', {}).get('api_key'):
            config = json.loads(json.dumps(config))  # cheap deep copy
            key = config['agentic']['online_llm']['api_key']
            config['agentic']['online_llm']['api_key'] = '••••••••' + key[-4:] if len(key) > 4 else '••••••••'
        return jsonify(config)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@config_bp.route('/api/config', methods=['PUT', 'POST'])
def save_config():
    """Save frontend configuration."""
    try:
        config = request.json
        if not config:
            return jsonify({"error": "No configuration provided"}), 400

        # Don't overwrite the real key with the masked placeholder GET
        # returns — same protection /api/config/cloud's PUT already has.
        key = config.get('agentic', {}).get('online_llm', {}).get('api_key', '')
        if key.startswith('••••'):
            existing = _load_config()
            config['agentic']['online_llm']['api_key'] = \
                existing.get('agentic', {}).get('online_llm', {}).get('api_key', '')

        _save_config(config)
        return jsonify({"status": "saved", "message": "Configuration saved successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Cloud Configuration Endpoints
# =============================================================================

@config_bp.route('/api/config/cloud', methods=['GET'])
def get_cloud_config():
    """Get cloud provider configuration."""
    try:
        config = _load_cloud_config()
        # Mask sensitive fields for GET requests
        masked = config.copy()
        if masked.get('aws', {}).get('secret_access_key'):
            masked['aws']['secret_access_key'] = '••••••••' + masked['aws']['secret_access_key'][-4:]
        if masked.get('aws', {}).get('session_token'):
            masked['aws']['session_token'] = '••••••••'
        if masked.get('azure', {}).get('client_secret'):
            masked['azure']['client_secret'] = '••••••••'
        return jsonify(masked)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@config_bp.route('/api/config/cloud', methods=['PUT', 'POST'])
def save_cloud_config_endpoint():
    """Save cloud provider configuration."""
    try:
        config = request.json
        if not config:
            return jsonify({"error": "No configuration provided"}), 400

        # Load existing config to preserve masked fields
        existing = _load_cloud_config()

        # Don't overwrite with masked values
        if config.get('aws', {}).get('secret_access_key', '').startswith('••••'):
            config['aws']['secret_access_key'] = existing.get('aws', {}).get('secret_access_key', '')
        if config.get('aws', {}).get('session_token') == '••••••••':
            config['aws']['session_token'] = existing.get('aws', {}).get('session_token', '')
        if config.get('azure', {}).get('client_secret') == '••••••••':
            config['azure']['client_secret'] = existing.get('azure', {}).get('client_secret', '')

        _save_cloud_config(config)
        print(f"[CLOUD] Saved cloud config for provider: {config.get('provider', 'unknown')}", flush=True)
        return jsonify({"status": "saved", "message": "Cloud configuration saved successfully"})
    except Exception as e:
        print(f"[CLOUD] Error saving config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@config_bp.route('/api/config/azure/certificate', methods=['GET'])
def get_azure_certificate():
    """Get Azure DFIR-O365RC certificate status and public key."""
    try:
        from services.azure.dfir_o365rc import is_available, get_public_certificate

        status = is_available()
        public_key = get_public_certificate()

        return jsonify({
            "has_certificate": status['has_certificate'],
            "has_image": status['has_image'],
            "available": status['available'],
            "public_key": public_key,
            "message": status['message']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@config_bp.route('/api/config/azure/certificate/download', methods=['GET'])
def download_azure_certificate():
    """Download the public certificate file for uploading to Azure App Registration."""
    try:
        from services.azure.dfir_o365rc import CERT_PUBLIC_PATH
        import os
        from flask import send_file

        if not os.path.exists(CERT_PUBLIC_PATH):
            return jsonify({"error": "Certificate not generated. Run install.sh first."}), 404

        return send_file(
            CERT_PUBLIC_PATH,
            as_attachment=True,
            download_name="risx_azure_certificate.pem",
            mimetype="application/x-pem-file"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
