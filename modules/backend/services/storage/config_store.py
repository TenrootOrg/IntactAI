#!/usr/bin/env python3
"""
Config Storage - Frontend and cloud configuration storage
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional

from .base import get_connection
from . import cloud_secrets


# The "cloud" row holds the cloud credentials: encrypted at rest and deleted when
# they expire (cloud_secrets). Every read and write of that row goes through the
# two helpers below, so nothing else ever sees ciphertext or a stale credential.
def _read_cloud_plain(conn):
    row = conn.execute("SELECT value FROM frontend_config WHERE key = ?", ("cloud",)).fetchone()
    if not row:
        return None
    try:
        stored = json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return None
    plain, rewrite = cloud_secrets.reveal(stored)
    if rewrite:          # legacy plaintext gets encrypted; an expired credential deleted for good
        _write_cloud(conn, plain, old_plain=plain)
    return plain


def _write_cloud(conn, plain, old_plain=None):
    stored = cloud_secrets.protect(plain, old_plain)       # raises rather than store plaintext
    conn.execute("INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
                 ("cloud", json.dumps(stored), datetime.now().isoformat()))
    conn.commit()


# ============================================================================
# Frontend Config Storage
# ============================================================================

def save_frontend_config(config: Dict[str, Any]) -> bool:
    """Save frontend configuration to the database"""
    try:
        conn = get_connection()
        now = datetime.now().isoformat()
        for key, value in config.items():
            if key == "cloud":
                _write_cloud(conn, value, old_plain=_read_cloud_plain(conn))
                continue
            conn.execute(
                "INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), now)
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving frontend config: {e}", flush=True)
        return False


def _legacy_agentic(config):
    """The decision-model settings were stored as agentic.jev before the feature was
    renamed (2026-10). Read them as agentic.decision_model. No write here, so a
    rollback during an upgrade still finds the old block; the operator's next Save
    stores only the new key. Also used on import (an old export carries `jev`).
    Remove once no box or export can still hold agentic.jev."""
    ag = config.get("agentic") if isinstance(config, dict) else None
    if isinstance(ag, dict) and "jev" in ag:
        old = ag.pop("jev")
        if not isinstance(ag.get("decision_model"), dict) and isinstance(old, dict):
            ag["decision_model"] = old
    return config


def load_frontend_config() -> Dict[str, Any]:
    """Load frontend configuration from the database"""
    try:
        conn = get_connection()
        rows = conn.execute("SELECT key, value FROM frontend_config").fetchall()
        config = {}
        for row in rows:
            if row['key'] == "cloud":
                continue
            try:
                config[row['key']] = json.loads(row['value'])
            except (json.JSONDecodeError, TypeError):
                config[row['key']] = row['value']
        cloud = _read_cloud_plain(conn)
        if cloud is not None:
            config["cloud"] = cloud
        return _legacy_agentic(config)
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
        _write_cloud(conn, config, old_plain=_read_cloud_plain(conn))
        print(f"[STORAGE] Cloud config saved for provider: {config.get('provider', 'unknown')}", flush=True)
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving cloud config: {e}", flush=True)
        return False


def load_cloud_config() -> Optional[Dict[str, Any]]:
    """Load cloud provider configuration from the database"""
    try:
        return _read_cloud_plain(get_connection())
    except Exception as e:
        print(f"[STORAGE] Error loading cloud config: {e}", flush=True)
        return None
