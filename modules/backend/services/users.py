#!/usr/bin/env python3
"""Dashboard users and roles.

Four roles on one ladder (docs/PLAN_multi_user_accounts.md):

    readonly < operator < admin < superadmin

One rule covers all user management (NIST SP 800-53 AC-6(10), OWASP ASVS 5.0
V8.2): an actor may create, edit, disable or reset only users strictly BELOW
their own rank, and may grant only roles strictly below their own. Nobody edits
their own role or enabled flag. So Admins manage Operators and Read-only users,
only the Super-admin manages Admins, and nobody can touch the Super-admin --
the role moves only by transfer_superadmin(), from the Super-admin's own
session.

Rows live in intact.db's `users` table. export_db() exports an allowlist of
tables, so password hashes never reach a backup file.

The gate runs on every request (and on one nginx auth_request per tus PATCH),
so lookups come from an in-process snapshot of the table, reloaded after every
write here and at least every SNAPSHOT_SECONDS, so a row written by another
process (a host script, a test harness) is seen within that time.
"""

import secrets
import threading
import time
from typing import Dict, List, Optional

from services.storage.base import get_connection

READONLY, OPERATOR, ADMIN, SUPERADMIN = "readonly", "operator", "admin", "superadmin"
ROLES = (READONLY, OPERATOR, ADMIN, SUPERADMIN)
RANK = {r: i for i, r in enumerate(ROLES)}
ROLE_LABELS = {READONLY: "Read-only", OPERATOR: "Operator", ADMIN: "Admin",
               SUPERADMIN: "Super-admin"}

# Two-step login (services/mfa.py) is required for these roles: they can
# change who may do what, so a stolen password alone must not be enough.
MFA_REQUIRED_ROLES = frozenset({"admin", "superadmin"})

# A temporary password (new user, or a reset) works for this long, and
# only to choose a real one (ASVS 6.4.1). The admin who hands it over never
# learns the password the user ends up with (ASVS 6.4.6).
TEMP_PASSWORD_HOURS = 24

# Login names are forever (they key audit lines, Velociraptor ACLs, Timesketch
# grants later), so keep them boring: no spaces, no case games.
NAME_MIN, NAME_MAX = 2, 32
_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789._-")

SNAPSHOT_SECONDS = 30

_lock = threading.Lock()
_snapshot: Optional[Dict[int, dict]] = None
_snapshot_at = 0.0
# Called after every write that changes who may do what (services.tool_accounts
# registers its reconciler here). Not after a login stamp: that changes nothing.
on_change: list = []


def ensure_table() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            pw_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            generation INTEGER NOT NULL DEFAULT 1,
            temp_expires REAL,
            created_at REAL,
            created_by TEXT,
            last_login REAL
        );
    """)
    # Two-step login, added after the table shipped. Secrets are Fernet tokens
    # (encrypted by auth_service), recovery codes only their hashes (JSON list).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    for col, decl in (("mfa_enabled", "INTEGER NOT NULL DEFAULT 0"), ("mfa_secret", "TEXT"),
                      ("mfa_pending", "TEXT"), ("mfa_last_step", "INTEGER NOT NULL DEFAULT -1"),
                      ("mfa_recovery", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
    conn.commit()


def _load() -> Dict[int, dict]:
    global _snapshot, _snapshot_at
    with _lock:
        if _snapshot is None or time.monotonic() - _snapshot_at > SNAPSHOT_SECONDS:
            _snapshot_at = time.monotonic()
            ensure_table()
            rows = get_connection().execute("SELECT * FROM users").fetchall()
            _snapshot = {r["id"]: dict(r) for r in rows}
        return _snapshot


def invalidate() -> None:
    global _snapshot
    with _lock:
        _snapshot = None


def _notify() -> None:
    for hook in list(on_change):
        try:
            hook()
        except Exception as exc:            # noqa: BLE001 -- a hook must not fail a write
            print(f"[USERS] change hook failed: {exc}", flush=True)


def _write(sql: str, args: tuple, notify: bool = True) -> int:
    ensure_table()
    conn = get_connection()
    cur = conn.execute(sql, args)
    conn.commit()
    invalidate()
    if notify:
        _notify()
    return cur.lastrowid


# --- reads -------------------------------------------------------------------

def get(uid) -> Optional[dict]:
    try:
        return _load().get(int(uid))
    except (TypeError, ValueError):
        return None


def by_name(username: str) -> Optional[dict]:
    name = (username or "").strip().lower()
    return next((u for u in _load().values() if u["username"] == name), None)


def superadmin() -> Optional[dict]:
    return next((u for u in _load().values() if u["role"] == SUPERADMIN), None)


def count() -> int:
    return len(_load())


def public(u: dict) -> dict:
    """What the Users page may show. Never the hash."""
    return {"username": u["username"], "role": u["role"], "enabled": bool(u["enabled"]),
            "temp_password_pending": bool(u.get("temp_expires")),
            "mfa_enabled": bool(u.get("mfa_enabled")),
            "mfa_required": u["role"] in MFA_REQUIRED_ROLES,
            "created_at": u.get("created_at"), "created_by": u.get("created_by"),
            "last_login": u.get("last_login")}


def list_all() -> List[dict]:
    return [public(u) for u in sorted(_load().values(),
                                      key=lambda u: (-RANK.get(u["role"], -1), u["username"]))]


def rank(role: str) -> int:
    return RANK.get(role, -1)


# --- rules -------------------------------------------------------------------

def name_problem(username: str) -> Optional[str]:
    name = (username or "").strip().lower()
    if not (NAME_MIN <= len(name) <= NAME_MAX):
        return f"it must be {NAME_MIN} to {NAME_MAX} characters"
    if not set(name) <= _NAME_CHARS or name[0] in ".-":
        return "use only a-z, 0-9, dot, dash and underscore, starting with a letter or digit"
    if name.endswith("-intact"):
        # services/tool_accounts maps a name a tool already uses (e.g. the
        # install's "tenroot") to "<name>-intact" there: two people, one account.
        return "it may not end in -intact"
    return None


def may_manage(actor: dict, target: dict) -> bool:
    """Strictly below, and never yourself."""
    return (actor is not None and target is not None and actor["id"] != target["id"]
            and rank(actor["role"]) > rank(target["role"]))


def may_grant(actor: dict, role: str) -> bool:
    return actor is not None and role in RANK and role != SUPERADMIN \
        and rank(actor["role"]) > rank(role)


# --- writes ------------------------------------------------------------------

def new_temp_password() -> str:
    return secrets.token_urlsafe(18)          # 24 chars, ~144 bits


def create(username: str, pw_hash: str, role: str, created_by: Optional[str],
           temporary: bool) -> int:
    expires = time.time() + TEMP_PASSWORD_HOURS * 3600 if temporary else None
    return _write("INSERT INTO users (username, pw_hash, role, enabled, generation, "
                  "temp_expires, created_at, created_by) VALUES (?, ?, ?, 1, 1, ?, ?, ?)",
                  (username.strip().lower(), pw_hash, role, expires, time.time(), created_by))


def set_password(uid: int, pw_hash: str, temporary: bool = False) -> None:
    """New hash and a new generation: every session of that user ends."""
    expires = time.time() + TEMP_PASSWORD_HOURS * 3600 if temporary else None
    _write("UPDATE users SET pw_hash = ?, temp_expires = ?, generation = generation + 1 "
           "WHERE id = ?", (pw_hash, expires, uid))


def set_role(uid: int, role: str) -> None:
    _write("UPDATE users SET role = ?, generation = generation + 1 WHERE id = ?", (role, uid))


def set_enabled(uid: int, enabled: bool) -> None:
    _write("UPDATE users SET enabled = ?, generation = generation + 1 WHERE id = ?",
           (1 if enabled else 0, uid))


def rename(uid: int, username: str) -> None:
    _write("UPDATE users SET username = ?, generation = generation + 1 WHERE id = ?",
           (username.strip().lower(), uid))


def touch_login(uid: int) -> None:
    _write("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), uid), notify=False)


def transfer_superadmin(from_uid: int, to_uid: int) -> None:
    """One transaction, so the box never has zero or two Super-admins."""
    ensure_table()
    conn = get_connection()
    with conn:
        conn.execute("UPDATE users SET role = ?, generation = generation + 1 WHERE id = ?",
                     (ADMIN, from_uid))
        conn.execute("UPDATE users SET role = ?, generation = generation + 1 WHERE id = ?",
                     (SUPERADMIN, to_uid))
    invalidate()
    _notify()


# --- the caller, inside a route ---------------------------------------------

def caller_has(session, role: str) -> bool:
    """For a role check INSIDE a route, where one endpoint serves runs of
    different weight (a case's run vs an upgrade's). A request with no session
    reached the route through the loopback exemption: the box itself."""
    if not session or not session.get("uid"):
        return True
    row = get(session.get("uid"))
    return row is not None and rank(row["role"]) >= rank(role)


def caller_name(session) -> str:
    return (session or {}).get("user") or "system"


# --- two-step login ---------------------------------------------------------------

def set_mfa_pending(uid: int, secret_token: Optional[str]) -> None:
    _write("UPDATE users SET mfa_pending = ? WHERE id = ?", (secret_token, uid), notify=False)


def enable_mfa(uid: int, secret_token: str, step: int, recovery_json: str) -> None:
    _write("UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_pending = NULL, "
           "mfa_last_step = ?, mfa_recovery = ? WHERE id = ?",
           (secret_token, step, recovery_json, uid), notify=False)


def clear_mfa(uid: int) -> None:
    """Turned off or reset by an Admin: a new generation ends every session, so
    a session opened with the old factor does not outlive it."""
    _write("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_pending = NULL, "
           "mfa_last_step = -1, mfa_recovery = NULL, generation = generation + 1 WHERE id = ?",
           (uid,), notify=False)


def mfa_used(uid: int, step: Optional[int] = None, recovery_json: Optional[str] = None) -> None:
    if step is not None:
        _write("UPDATE users SET mfa_last_step = ? WHERE id = ?", (step, uid), notify=False)
    if recovery_json is not None:
        _write("UPDATE users SET mfa_recovery = ? WHERE id = ?", (recovery_json, uid), notify=False)
