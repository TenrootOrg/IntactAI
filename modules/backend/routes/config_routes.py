#!/usr/bin/env python3
"""
Config Routes - Configuration endpoints (frontend config, cloud config)
"""

import json
from flask import Blueprint, jsonify, request
from services.file_storage_service import load_frontend_config, save_frontend_config

config_bp = Blueprint('config', __name__)

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


def _serve_catalog(catalog_module, provider_name: str, bootstrap: bool = True):
    """Standard wrapper: prepend alias entries, then catalog matches.

    `bootstrap` triggers a one-shot refresh when the catalog file is
    missing (operator may not have run install bootstrap yet). For
    direct providers this is a no-op when the API key isn't configured
    — `refresh_catalog` returns success=False without raising.

    Aliases ALWAYS appear (modulo the search filter) so the dropdown is
    never empty, even when no API key is configured for the provider.
    """
    q, limit, offset = _parse_catalog_query()
    if bootstrap and not catalog_module.load_catalog():
        try:
            catalog_module.refresh_catalog()
        except Exception as e:
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
