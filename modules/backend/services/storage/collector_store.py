#!/usr/bin/env python3
"""
Collector Storage - CRUD operations for offline collector configurations
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from .base import get_connection, row_to_dict


def save_offline_collector_config(config_data: Dict[str, Any]) -> bool:
    """Save or update an offline collector configuration"""
    try:
        conn = get_connection()
        now = datetime.now().isoformat()

        # Check if existing
        existing = conn.execute(
            "SELECT config_id FROM offline_collectors WHERE config_id = ?",
            (config_data.get('config_id'),)
        ).fetchone()

        created_at = config_data.get('created_at', now) if not existing else \
            conn.execute("SELECT created_at FROM offline_collectors WHERE config_id = ?",
                         (config_data.get('config_id'),)).fetchone()['created_at']

        conn.execute(
            """INSERT OR REPLACE INTO offline_collectors
               (config_id, config_name, description, artifacts, parameters, is_template, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (config_data.get('config_id'),
             config_data.get('config_name'),
             config_data.get('description'),
             json.dumps(config_data.get('artifacts')) if config_data.get('artifacts') is not None else '[]',
             json.dumps(config_data.get('parameters')) if config_data.get('parameters') is not None else '{}',
             1 if config_data.get('is_template') else 0,
             created_at,
             now)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving offline collector config: {e}", flush=True)
        return False


def load_offline_collector_configs() -> List[Dict[str, Any]]:
    """Load all offline collector configurations"""
    try:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM offline_collectors").fetchall()
        return [row_to_dict(r, ['artifacts', 'parameters']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading offline collector configs: {e}", flush=True)
        return []


def get_offline_collector_config(config_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific offline collector configuration by config_id"""
    try:
        conn = get_connection()
        row = conn.execute("SELECT * FROM offline_collectors WHERE config_id = ?", (config_id,)).fetchone()
        if row:
            d = row_to_dict(row, ['artifacts', 'parameters'])
            d['id'] = d['config_id']  # Add 'id' field for compatibility
            return d
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting offline collector config: {e}", flush=True)
        return None


def delete_offline_collector_config(config_id: str) -> bool:
    """Delete an offline collector configuration"""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM offline_collectors WHERE config_id = ?", (config_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting offline collector config: {e}", flush=True)
        return False
