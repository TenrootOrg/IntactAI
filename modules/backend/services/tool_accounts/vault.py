#!/usr/bin/env python3
"""Generated tool passwords, encrypted at rest.

Kibana, Velociraptor and VolWeb need a password the backend presents again and
again (nginx injects it), so it is stored recoverably -- encrypted with the
box's Fernet key (services/storage/cloud_secrets.py: a root-only file under
data/state/backend/, outside the database). The `tool_accounts` table is not
in export_db()'s allowlist, and the DB backup download blanks it, so a
copied database or a backup leaks nothing.

Encryption protects backups and stolen files, not a live compromise: whoever
controls the running backend or the host can use every tool account -- as they
already could use the shared admin passwords before this existed.

No route returns these values and nothing logs them. Reads come from an
in-process cache (the verify path is hot); every write here refreshes it.
"""

import threading
import time
from typing import Dict, List, Optional, Tuple

from services.storage.base import get_connection
from services.storage.cloud_secrets import _fernet

_lock = threading.Lock()
_cache: Optional[Dict[Tuple[str, str], dict]] = None


def ensure_table() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tool_accounts (
            username TEXT NOT NULL,
            tool TEXT NOT NULL,
            tool_user TEXT NOT NULL,
            secret TEXT,
            state TEXT,
            error TEXT,
            updated_at REAL,
            PRIMARY KEY (username, tool)
        );
    """)
    conn.commit()


def _enc(password: Optional[str]) -> Optional[str]:
    return _fernet().encrypt(password.encode()).decode() if password else None


def _dec(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except Exception:                       # noqa: BLE001 -- a blanked backup, a new key
        return None


def _load() -> Dict[Tuple[str, str], dict]:
    global _cache
    with _lock:
        if _cache is None:
            ensure_table()
            rows = get_connection().execute("SELECT * FROM tool_accounts").fetchall()
            _cache = {(r["username"], r["tool"]): {
                "tool_user": r["tool_user"], "password": _dec(r["secret"]),
                "state": r["state"], "error": r["error"], "updated_at": r["updated_at"],
            } for r in rows}
        return _cache


def _invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def get(username: str, tool: str) -> Optional[dict]:
    return _load().get((username, tool))


def put(username: str, tool: str, tool_user: str, password: Optional[str], state: str) -> None:
    ensure_table()
    conn = get_connection()
    conn.execute("INSERT INTO tool_accounts (username, tool, tool_user, secret, state, error, updated_at) "
                 "VALUES (?, ?, ?, ?, ?, NULL, ?) ON CONFLICT(username, tool) DO UPDATE SET "
                 "tool_user = excluded.tool_user, secret = excluded.secret, state = excluded.state, "
                 "updated_at = excluded.updated_at",
                 (username, tool, tool_user, _enc(password), state, time.time()))
    conn.commit()
    _invalidate()


def mark(username: str, tool: str, state: str, error: Optional[str]) -> None:
    ensure_table()
    conn = get_connection()
    conn.execute("UPDATE tool_accounts SET state = ?, error = ?, updated_at = ? "
                 "WHERE username = ? AND tool = ?", (state, error, time.time(), username, tool))
    conn.commit()
    _invalidate()


def forget(username: str, tool: str) -> None:
    ensure_table()
    conn = get_connection()
    conn.execute("DELETE FROM tool_accounts WHERE username = ? AND tool = ?", (username, tool))
    conn.commit()
    _invalidate()


def all_keys() -> List[Tuple[str, str, str]]:
    return [(u, t, v["tool_user"]) for (u, t), v in _load().items()]


def summary() -> Dict[str, Dict[str, dict]]:
    """{username: {tool: {state, error, updated_at, tool_user}}} -- no secrets."""
    out: Dict[str, Dict[str, dict]] = {}
    for (u, t), v in _load().items():
        out.setdefault(u, {})[t] = {k: v[k] for k in ("tool_user", "state", "error", "updated_at")}
    return out
