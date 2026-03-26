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
