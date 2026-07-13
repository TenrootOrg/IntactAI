#!/usr/bin/env python3
"""Secret store — runtime credentials persisted in SQLite.

Why not frontend_config: that table gets dumped by export_db() into
backup files. This one is deliberately separate so secrets never leak
into a backup or the import/export round-trip.

Used by:
- services/upgrade/iris.py at IRIS module install/upgrade — bootstraps and
  verifies the IRIS administrator's api_key so it's available for direct/
  manual use later (IRIS has no other module wired to it; it's an
  install-and-upgrade-only stack — see services/upgrade/iris.py).
"""

from datetime import datetime
from typing import Optional

from .base import get_connection


def set_secret(key: str, value: str) -> bool:
    """Insert or replace a secret. Returns True on success."""
    if not key or value is None:
        return False
    try:
        conn = get_connection()
        conn.execute(
            "INSERT OR REPLACE INTO secrets (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, datetime.now().isoformat()),
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving secret {key!r}: {e}", flush=True)
        return False


def get_secret(key: str) -> Optional[str]:
    """Return secret value, or None if missing/empty/storage-error."""
    if not key:
        return None
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT value FROM secrets WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            return None
        val = row["value"]
        return val if val else None
    except Exception as e:
        print(f"[STORAGE] Error loading secret {key!r}: {e}", flush=True)
        return None


def delete_secret(key: str) -> bool:
    """Remove a secret. Returns True even if it didn't exist."""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM secrets WHERE key = ?", (key,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting secret {key!r}: {e}", flush=True)
        return False
