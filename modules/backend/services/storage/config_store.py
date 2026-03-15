#!/usr/bin/env python3
"""
Config Storage - Frontend and cloud configuration storage
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional

from .base import get_connection


# ============================================================================
# Frontend Config Storage
# ============================================================================

def save_frontend_config(config: Dict[str, Any]) -> bool:
    """Save frontend configuration to the database"""
    try:
        conn = get_connection()
        now = datetime.now().isoformat()
        for key, value in config.items():
            conn.execute(
                "INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), now)
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving frontend config: {e}", flush=True)
        return False


def load_frontend_config() -> Dict[str, Any]:
    """Load frontend configuration from the database"""
    try:
        conn = get_connection()
        rows = conn.execute("SELECT key, value FROM frontend_config").fetchall()
        config = {}
        for row in rows:
            try:
                config[row['key']] = json.loads(row['value'])
            except (json.JSONDecodeError, TypeError):
                config[row['key']] = row['value']
        return config
    except Exception as e:
        print(f"[STORAGE] Error loading frontend config: {e}", flush=True)
        return {}


# ============================================================================
# Cloud Configuration
# ============================================================================

def save_cloud_config(config: Dict[str, Any]) -> bool:
    """Save cloud provider configuration to the database"""
    try:
        conn = get_connection()
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
            ("cloud", json.dumps(config), now)
        )
        conn.commit()
        print(f"[STORAGE] Cloud config saved for provider: {config.get('provider', 'unknown')}", flush=True)
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving cloud config: {e}", flush=True)
        return False


def load_cloud_config() -> Optional[Dict[str, Any]]:
    """Load cloud provider configuration from the database"""
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT value FROM frontend_config WHERE key = ?",
            ("cloud",)
        ).fetchone()
        if row:
            return json.loads(row['value'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error loading cloud config: {e}", flush=True)
        return None
