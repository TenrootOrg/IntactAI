#!/usr/bin/env python3
"""Per-user API tokens for scripts calling the dashboard API.

A token belongs to one user and acts as that user, capped by its scope:
"read" acts as Read-only, "write" as the user's own role (never above it).
auth_service.gate_decision() checks it on every request that sends
`Authorization: Bearer intact_...`; the routes are routes/api_token_routes.py.

Only a SHA-256 of the token is stored: it is 256 random bits, so a plain hash
cannot be brute-forced and no salt or slow hash is needed (unlike a password).
A token dies when it expires, is revoked (row deleted; the audit log keeps the
history), or its user's `generation` moves (role, password, disable, two-step
reset): the generation is stored at creation and compared on every use.

Rows live in intact.db's `api_tokens` table, which export_db() does not export
and the downloadable backup empties (routes/db_routes.py).
"""

import hashlib
import secrets
import time
from typing import List, Optional, Tuple

from services import users
from services.storage.base import get_connection

TOKEN_PREFIX = "intact_"
READ, WRITE = "read", "write"
SCOPES = (READ, WRITE)
MIN_DAYS, MAX_DAYS = 1, 365
NAME_MAX = 64
# A stamp per request would be one SQLite write per scripted call: once a minute is enough to see use.
LAST_USED_EVERY_SECONDS = 60

# lookup() reasons. The session ones are reused so login.html-style clients read them the same way.
INVALID = "token_invalid"           # unknown, revoked or malformed
EXPIRED = "token_expired"
DISABLED = "disabled"               # auth_service.SESSION_DISABLED
CHANGED = "credentials_changed"     # auth_service.SESSION_CREDENTIALS_CHANGED


def ensure_table() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            scope TEXT NOT NULL,
            generation INTEGER NOT NULL,
            created_at REAL NOT NULL,
            created_by TEXT,
            expires_at REAL NOT NULL,
            last_used_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
    """)
    conn.commit()


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def problem(name: str, scope: str, days) -> Optional[str]:
    """None when a new token's fields are acceptable, else the reason."""
    if not name or len(name) > NAME_MAX or not name.isprintable():
        return f"give it a name of 1 to {NAME_MAX} characters"
    if scope not in SCOPES:
        return "scope must be read or write"
    if isinstance(days, bool) or not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
        return f"it must expire in {MIN_DAYS} to {MAX_DAYS} days"
    return None


def create(user: dict, name: str, scope: str, days: int, created_by: str) -> Tuple[str, dict]:
    """(the token, its public row). The token is returned this once and never stored."""
    prefix = secrets.token_hex(4)
    raw = f"{TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"     # 256 random bits after the prefix
    now = time.time()
    ensure_table()
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO api_tokens (user_id, name, prefix, token_hash, scope, generation, "
        "created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user["id"], name, prefix, _hash(raw), scope, user["generation"], now, created_by,
         now + days * 86400))
    conn.commit()
    return raw, public(get(cur.lastrowid))


def get(token_id) -> Optional[dict]:
    ensure_table()
    row = get_connection().execute("SELECT * FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
    return dict(row) if row else None


def lookup(raw: str) -> Tuple[Optional[dict], str]:
    """(the token row, "") when `raw` is a live token whose user may use it,
    else (None, reason)."""
    if not isinstance(raw, str) or not raw.startswith(TOKEN_PREFIX) or len(raw) > 200:
        return None, INVALID
    ensure_table()
    row = get_connection().execute("SELECT * FROM api_tokens WHERE token_hash = ?",
                                   (_hash(raw),)).fetchone()
    if row is None:
        return None, INVALID
    tok = dict(row)
    if time.time() >= tok["expires_at"]:
        return None, EXPIRED
    user = users.get(tok["user_id"])
    if user is None or not user["enabled"]:
        return None, DISABLED
    if user["generation"] != tok["generation"]:
        return None, CHANGED
    return tok, ""


def effective_role(tok: dict, user: dict) -> str:
    return users.READONLY if tok["scope"] == READ else user["role"]


def mark_used(tok: dict) -> bool:
    """Stamp last_used_at (at most once a minute). True on the token's first use."""
    now = time.time()
    first = tok.get("last_used_at") is None
    if first or now - tok["last_used_at"] > LAST_USED_EVERY_SECONDS:
        conn = get_connection()
        conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now, tok["id"]))
        conn.commit()
    return first


def status(tok: dict) -> str:
    """active, expired, or stopped (the user's role, password or account changed since)."""
    if time.time() >= tok["expires_at"]:
        return "expired"
    user = users.get(tok["user_id"])
    if user is None or not user["enabled"] or user["generation"] != tok["generation"]:
        return "stopped"
    return "active"


def public(tok: dict) -> dict:
    """What the UI may show. Never the hash."""
    owner = users.get(tok["user_id"])
    return {"id": tok["id"], "name": tok["name"], "prefix": tok["prefix"], "scope": tok["scope"],
            "user": owner["username"] if owner else None,
            "created_at": tok["created_at"], "created_by": tok["created_by"],
            "expires_at": tok["expires_at"], "last_used_at": tok["last_used_at"],
            "status": status(tok)}


def list_for(user_id: int) -> List[dict]:
    ensure_table()
    rows = get_connection().execute(
        "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [public(dict(r)) for r in rows]


def delete(token_id: int) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
    conn.commit()
