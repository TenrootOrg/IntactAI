#!/usr/bin/env python3
"""
Offline Collector Config - Configuration management for offline collectors
"""

import time
from services.file_storage_service import (
    save_offline_collector_config,
    load_offline_collector_configs,
    get_offline_collector_config as file_get_config,
    delete_offline_collector_config
)
from services.offline_collector.constants import DEFAULT_ARTIFACTS, QUICK_TRIAGE_ARTIFACTS

print("[OFFLINE] Using SQLite storage for offline collector configurations", flush=True)


def init_offline_collector_index():
    """Initialize offline collector storage and seed/update default templates"""
    try:
        # Always reseed default templates to pick up artifact updates
        # This uses INSERT OR REPLACE so it updates existing templates
        seed_default_templates()

        return True
    except Exception as e:
        print(f"[OFFLINE] Failed to init storage: {e}", flush=True)
        return False


def seed_default_templates():
    """Seed default collector templates"""
    templates = [
        {
            "config_id": "template_test",
            "config_name": "Test",
            "description": "Single artifact for testing - Windows.System.Pslist only",
            "artifacts": ["Windows.System.Pslist"],
            "parameters": {
                "CpuLimit": 80,
                "MaxExecutionTimeInSeconds": 300,
                "MaxIdleTimeInSeconds": 60,
                "EncryptionScheme": "None"
            },
            "is_template": True
        },
        {
            "config_id": "template_quicktriage",
            "config_name": "Quick Triage",
            "description": "Ultra-fast collection (< 2 min) - processes, network, renamed binaries",
            "artifacts": QUICK_TRIAGE_ARTIFACTS,
            "parameters": {
                "CpuLimit": 80,
                "MaxExecutionTimeInSeconds": 300,
                "MaxIdleTimeInSeconds": 60,
                "EncryptionScheme": "None"
            },
            "is_template": True
        },
        {
            "config_id": "template_bestpractice",
            "config_name": "Best Practice Collection",
            "description": "Comprehensive collection with all recommended artifacts",
            "artifacts": DEFAULT_ARTIFACTS,
            "parameters": {
                "CpuLimit": 80,
                "MaxExecutionTimeInSeconds": 3600,
                "MaxIdleTimeInSeconds": 600,
                "EncryptionScheme": "None"
            },
            "is_template": True
        }
    ]

    try:
        for template in templates:
            save_offline_collector_config(template)
        print(f"[OFFLINE] Seeded {len(templates)} default templates", flush=True)
    except Exception as e:
        print(f"[OFFLINE] Failed to seed templates: {e}", flush=True)


def get_all_configs():
    """Get all offline collector configurations"""
    try:
        configs = load_offline_collector_configs()
        # Add 'id' field for compatibility
        for cfg in configs:
            if 'id' not in cfg:
                cfg['id'] = cfg.get('config_id', '')
        return configs
    except Exception as e:
        print(f"[OFFLINE] Error getting configs: {e}", flush=True)
        return []


def get_config(config_id):
    """Get a specific configuration"""
    return file_get_config(config_id)


def save_config(config_data, config_id=None):
    """Save or update a configuration"""
    try:
        if not config_id:
            config_id = f"config_{int(time.time() * 1000)}"
            config_data["config_id"] = config_id

        result = save_offline_collector_config(config_data)

        if result:
            return {"success": True, "config_id": config_id}
        else:
            return {"success": False, "error": "Failed to save configuration"}
    except Exception as e:
        print(f"[OFFLINE] Error saving config: {e}", flush=True)
        return {"success": False, "error": str(e)}


def delete_config(config_id):
    """Delete a configuration"""
    try:
        result = delete_offline_collector_config(config_id)
        return {"success": result}
    except Exception as e:
        print(f"[OFFLINE] Error deleting config {config_id}: {e}", flush=True)
        return {"success": False, "error": str(e)}
