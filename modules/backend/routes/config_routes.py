#!/usr/bin/env python3
"""
Config Routes - Configuration endpoints (frontend config, cloud config)
"""

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
            "url": "http://localhost:11434",
            "batch_size": 100
        },
        "online_llm": {
            "provider": "openrouter",
            "api_key": "",
            "model": "claude-sonnet",
            "batch_size": 100
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


# Cache for OpenRouter models (fetched once, reused)
_openrouter_models_cache = {"models": None, "fetched_at": 0}

@config_bp.route('/api/config/openrouter/models', methods=['GET'])
def get_openrouter_models():
    """Fetch available models from OpenRouter API with caching."""
    import time, requests

    # Return cache if less than 1 hour old
    if _openrouter_models_cache["models"] and (time.time() - _openrouter_models_cache["fetched_at"]) < 3600:
        return jsonify({"models": _openrouter_models_cache["models"]})

    # Only show models from these providers
    ALLOWED_PROVIDERS = ['anthropic', 'openai', 'google', 'qwen']
    # Skip non-text models, old versions, weak models, and noise
    SKIP_PATTERNS = [':free', ':extended', ':thinking', '-image', '-audio', '-vl-', 'vl-', '-search-',
                     'gpt-3.5', 'gpt-4-turbo', 'gpt-4-1106', 'gpt-4-0314', 'gpt-4o-2024',
                     'gpt-4o-mini', 'gpt-4.1-nano', 'gpt-4', 'gpt-5-nano', 'gpt-5.4-nano',
                     'gemma-', 'nano-banana', 'safeguard', 'gpt-oss',
                     '-deep-research', '-codex', '-chat', 'customtools',
                     'claude-3-haiku', 'claude-3.5', 'claude-3.7', 'claude-sonnet-4:',
                     'claude-opus-4:', 'claude-opus-4.1',
                     'qwen-2.5', 'qwen2.5', 'qwq-', 'qwen3-8b', 'qwen3-14b', 'qwen3-32b',
                     'qwen3-235b', 'qwen3-30b', 'qwen3-next', 'qwen3.5-9b', 'qwen3.5-27b',
                     'qwen3.5-35b', 'qwen3.5-122b', 'qwen3.5-397b', 'qwen3-coder-30b',
                     'qwen-plus-2025', 'thinking-2507',
                     'preview', 'flash-lite', 'gemini-2.0',
                     'o1-pro', 'o3-mini', 'o4-mini-high',
                     'gpt-5.1', 'gpt-5.2', 'gpt-5.3']

    try:
        resp = requests.get("https://openrouter.ai/api/v1/models", timeout=10)
        resp.raise_for_status()
        data = resp.json()

        # Filter to popular providers, skip noise
        all_models = []
        for m in data.get("data", []):
            model_id = m.get("id", "")
            provider = model_id.split("/")[0] if "/" in model_id else ""
            if provider not in ALLOWED_PROVIDERS:
                continue
            if any(skip in model_id.lower() for skip in SKIP_PATTERNS):
                continue
            all_models.append({
                "id": model_id,
                "name": m.get("name", ""),
                "created": m.get("created", 0),
            })

        # Group by model family, keep only 2 newest per family
        # Family = base name without version (e.g. "claude-opus", "gpt-5", "o3", "qwen3-max")
        import re
        from collections import defaultdict
        families = defaultdict(list)
        for m in all_models:
            # Extract family: provider/name without trailing version numbers
            # anthropic/claude-opus-4.6 → anthropic/claude-opus
            # openai/gpt-5.4-pro → openai/gpt-pro (strip middle versions too)
            model_id = m["id"]
            # Remove version at end: -4.6, -4.5, -4, .4, -2.5
            family = re.sub(r'[-.][\d]+(?:\.[\d]+)?$', '', model_id)
            families[family].append(m)

        # Keep 2 newest per family
        models = []
        for family, group in families.items():
            group.sort(key=lambda x: x.get("created", 0), reverse=True)
            for m in group[:2]:
                models.append({"id": m["id"], "name": m["name"]})

        models.sort(key=lambda x: x["name"].lower())

        _openrouter_models_cache["models"] = models
        _openrouter_models_cache["fetched_at"] = time.time()

        return jsonify({"models": models})
    except Exception as e:
        # Return cache if available, otherwise empty
        if _openrouter_models_cache["models"]:
            return jsonify({"models": _openrouter_models_cache["models"]})
        return jsonify({"models": [], "error": str(e)})


# =============================================================================
# Frontend Configuration Endpoints
# =============================================================================

@config_bp.route('/api/config', methods=['GET'])
def get_config():
    """Get frontend configuration."""
    try:
        config = _load_config()
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
