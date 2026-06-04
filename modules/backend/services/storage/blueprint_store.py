#!/usr/bin/env python3
"""
Blueprint Storage - CRUD operations for all blueprint types
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from .base import get_connection, row_to_dict


# Blueprint type configurations
_BLUEPRINT_CONFIGS = {
    'velociraptor': {'table': 'blueprints_velociraptor', 'has_artifacts': True, 'json_fields': ['artifacts', 'settings']},
    'timesketch': {'table': 'blueprints_timesketch', 'has_artifacts': False, 'json_fields': ['settings']},
    'memory': {'table': 'blueprints_memory', 'has_artifacts': False, 'json_fields': ['settings']},
}


# ============================================================================
# Generic Blueprint Operations
# ============================================================================

def _save_blueprint(blueprint_type: str, blueprint_data: Dict[str, Any]) -> bool:
    """Generic save/update for any blueprint type"""
    config = _BLUEPRINT_CONFIGS.get(blueprint_type)
    if not config:
        print(f"[STORAGE] Unknown blueprint type: {blueprint_type}", flush=True)
        return False

    try:
        conn = get_connection()
        table = config['table']
        now = datetime.now().isoformat()

        existing = conn.execute(f"SELECT id FROM {table} WHERE id = ?", (blueprint_data.get('id'),)).fetchone()
        created_at = blueprint_data.get('created_at', now) if not existing else \
            conn.execute(f"SELECT created_at FROM {table} WHERE id = ?", (blueprint_data.get('id'),)).fetchone()['created_at']

        if config['has_artifacts']:
            conn.execute(
                f"""INSERT OR REPLACE INTO {table}
                   (id, name, description, is_default, artifacts, settings, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (blueprint_data.get('id'), blueprint_data.get('name'), blueprint_data.get('description'),
                 1 if blueprint_data.get('is_default') else 0,
                 json.dumps(blueprint_data.get('artifacts')) if blueprint_data.get('artifacts') is not None else '[]',
                 json.dumps(blueprint_data.get('settings')) if blueprint_data.get('settings') is not None else '{}',
                 created_at, now)
            )
        else:
            conn.execute(
                f"""INSERT OR REPLACE INTO {table}
                   (id, name, description, is_default, settings, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (blueprint_data.get('id'), blueprint_data.get('name'), blueprint_data.get('description'),
                 1 if blueprint_data.get('is_default') else 0,
                 json.dumps(blueprint_data.get('settings')) if blueprint_data.get('settings') is not None else '{}',
                 created_at, now)
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving {blueprint_type} blueprint: {e}", flush=True)
        return False


def _load_blueprints(blueprint_type: str) -> List[Dict[str, Any]]:
    """Generic load all blueprints of a type"""
    config = _BLUEPRINT_CONFIGS.get(blueprint_type)
    if not config:
        return []
    try:
        conn = get_connection()
        rows = conn.execute(f"SELECT * FROM {config['table']}").fetchall()
        return [row_to_dict(r, config['json_fields']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading {blueprint_type} blueprints: {e}", flush=True)
        return []


def _get_blueprint(blueprint_type: str, blueprint_id: str) -> Optional[Dict[str, Any]]:
    """Generic get single blueprint"""
    config = _BLUEPRINT_CONFIGS.get(blueprint_type)
    if not config:
        return None
    try:
        conn = get_connection()
        row = conn.execute(f"SELECT * FROM {config['table']} WHERE id = ?", (blueprint_id,)).fetchone()
        return row_to_dict(row, config['json_fields']) if row else None
    except Exception as e:
        print(f"[STORAGE] Error getting {blueprint_type} blueprint: {e}", flush=True)
        return None


def _delete_blueprint(blueprint_type: str, blueprint_id: str) -> bool:
    """Generic delete blueprint"""
    config = _BLUEPRINT_CONFIGS.get(blueprint_type)
    if not config:
        return False
    try:
        conn = get_connection()
        conn.execute(f"DELETE FROM {config['table']} WHERE id = ?", (blueprint_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting {blueprint_type} blueprint: {e}", flush=True)
        return False


# ============================================================================
# Velociraptor Blueprint Storage
# ============================================================================

def save_velociraptor_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    return _save_blueprint('velociraptor', blueprint_data)

def load_velociraptor_blueprints() -> List[Dict[str, Any]]:
    return _load_blueprints('velociraptor')

def get_velociraptor_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    return _get_blueprint('velociraptor', blueprint_id)

def delete_velociraptor_blueprint(blueprint_id: str) -> bool:
    return _delete_blueprint('velociraptor', blueprint_id)


# ============================================================================
# Agentic Blueprint Storage (aliases to velociraptor - same blueprints)
# ============================================================================

def save_agentic_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    return save_velociraptor_blueprint(blueprint_data)

def load_agentic_blueprints() -> List[Dict[str, Any]]:
    return load_velociraptor_blueprints()

def get_agentic_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    return get_velociraptor_blueprint(blueprint_id)

def delete_agentic_blueprint(blueprint_id: str) -> bool:
    return delete_velociraptor_blueprint(blueprint_id)


# ============================================================================
# Timesketch Blueprint Storage
# ============================================================================

def save_timesketch_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    return _save_blueprint('timesketch', blueprint_data)

def load_timesketch_blueprints() -> List[Dict[str, Any]]:
    return _load_blueprints('timesketch')

def get_timesketch_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    return _get_blueprint('timesketch', blueprint_id)

def delete_timesketch_blueprint(blueprint_id: str) -> bool:
    return _delete_blueprint('timesketch', blueprint_id)


# ============================================================================
# Memory-forensics Blueprint Storage
# ============================================================================

def save_memory_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    return _save_blueprint('memory', blueprint_data)

def load_memory_blueprints() -> List[Dict[str, Any]]:
    return _load_blueprints('memory')

def get_memory_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    return _get_blueprint('memory', blueprint_id)

def delete_memory_blueprint(blueprint_id: str) -> bool:
    return _delete_blueprint('memory', blueprint_id)


# ============================================================================
# Public type-dispatch wrappers (used by routes that know the type at runtime)
# ============================================================================

def save_blueprint(blueprint_type: str, blueprint_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Save and return the saved blueprint (or None on failure)."""
    ok = _save_blueprint(blueprint_type, blueprint_data)
    if not ok:
        return None
    return _get_blueprint(blueprint_type, blueprint_data.get('id'))


def list_blueprints(blueprint_type: str) -> List[Dict[str, Any]]:
    return _load_blueprints(blueprint_type)


def get_blueprint(blueprint_type: str, blueprint_id: str) -> Optional[Dict[str, Any]]:
    return _get_blueprint(blueprint_type, blueprint_id)


def delete_blueprint(blueprint_type: str, blueprint_id: str) -> bool:
    return _delete_blueprint(blueprint_type, blueprint_id)
