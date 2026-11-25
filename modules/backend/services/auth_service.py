#!/usr/bin/env python3
"""Dashboard authentication: users, roles, sessions, the request gate.

Replaces the nginx server-level HTTP Basic Auth gate that used to be the
platform's ONLY authentication (see modules/nginx/config/nginx.conf). That gate
was a browser popup with no logout, no session, no audit trail, and no recovery
path other than `sudo cat modules/nginx/secrets/nginx_basic_auth_password`. It
also did nothing for audit finding F-010: the Flask backend performed no auth of
its own, so any peer container on intact_network could reach intact_backend:5001
and bypass nginx entirely. The `require_auth` gate below closes that too.

Several users, four roles (services/users.py). Who may call which route is
services/access_policy.py; gate_decision() below enforces it on every request.

Three things in here are load-bearing and easy to "simplify" into a security
hole. Each is commented at its implementation:

  1. write_first_login() truncates in place and MUST NOT rename-into-place.
  2. The setup endpoint consumes the one-time setup token and writes
     first_login=false BEFORE storing the credential.
  3. A lockout must never flip first_login to true.
"""

import collections
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

import yaml
from werkzeug.security import check_password_hash, generate_password_hash

from services import access_policy, users
from services.storage.base import STORAGE_BASE
from services.storage.secret_store import get_secret, set_secret

# --- where state lives -------------------------------------------------------
#
# The credential hash and session key live in the `secrets`
# table of /app/data/intact.db. /app/data is a HOST BIND MOUNT
# (../../data:/app/data → /home/tenroot/intact/data), which is the most durable
# location in the appliance: it survives container recreate, image swap,
# `docker volume rm`, `scripts/clean.sh --data` (which only removes data/*.json)
# and is excluded from upgrade packaging (services/upgrade/package.py). Every
# /api/maintenance/purge path does targeted `DELETE FROM workflows/reports` plus
# purge_dir on specific subdirs — none of them touch the `secrets` table.
#
# secret_store is also deliberately excluded from export_db(), so a DB
# export/import round-trip carries no credential. That means "first_login=false
# with no stored hash" is a reachable state, and it must fail CLOSED — see
# verify_password().
_K_HASH = "auth_password_hash"
_K_USER = "auth_username"
_K_SESSION_KEY = "auth_session_key"
# auth_failed_count / auth_lock_until / auth_lock_strikes rows may still sit in
# old boxes' DBs from the global lockout; nothing reads them any more.
_K_GENERATION = "auth_credential_generation"

# --- session policy ----------------------------------------------------------
#
# The cookie's max-age and the session's real lifetime are deliberately
# DIFFERENT. A plain 7-day cookie cannot satisfy "tell the operator why they
# were logged out": once max-age elapses the browser simply stops sending the
# cookie, and the server cannot distinguish "expired" from "never logged in"
# from "logged out". So the cookie lives much longer than the session and the
# 7-day sliding window is enforced server-side from a timestamp inside the
# signed payload — the stale cookie still arrives, so we can answer
# reason=expired instead of showing a bare login form.
SESSION_MAX_AGE_DAYS = 30          # cookie max-age
# NIST SP 800-63B-4 AAL2: at most 1 h idle and 24 h in all; 12 h is the
# decided default (one working day). Several people share the box now, so a
# forgotten browser must not stay signed in for the week the old value allowed.
SESSION_IDLE_LIMIT_SECONDS = 60 * 60            # real sliding window
SESSION_ABSOLUTE_LIMIT_SECONDS = 12 * 60 * 60   # from login, however active
# Only re-stamp `seen` (and therefore re-sign the cookie) this often, rather
# than on literally every request. nginx's auth_request fires a subrequest per
# tus PATCH — ~2000 of them for a 10 GB upload — and re-signing each one is
# pure overhead. Well inside the idle limit, so an active user never expires.
SESSION_TOUCH_INTERVAL_SECONDS = 5 * 60
# User management needs a password typed this recently (ASVS 7.5.3 step-up).
REAUTH_SECONDS = 15 * 60

# --- lockout policy ----------------------------------------------------------
#
# 10 failures from one client address locks THAT address for 15 minutes; each
# further block of 10 doubles it, capped at 24h. Timed, so it self-heals.
#
# PER CLIENT, not global (QA). The counter used to be one global row, so anyone
# who could route to port 443 locked the real operator out in 10 requests --
# and the documented way out (reopen setup) then handed the box to whoever
# reached the setup page first, i.e. the attacker who caused the lockout. Now a
# locked address only locks itself, and setup needs a token from the host.
#
# The address is X-Real-IP, which nginx sets from $remote_addr -- but ONLY when
# the request really comes from nginx (see client_address). Kept in memory: a
# restart forgets the counters, which an attacker cannot trigger, and it keeps
# an unauthenticated endpoint from writing to SQLite per request.
LOCKOUT_THRESHOLD = 10
LOCKOUT_BASE_MINUTES = 15
LOCKOUT_CAP_MINUTES = 24 * 60

# Independent of the counter above: without this, ten failures burn in ~10ms and
# the "10 strikes" rule is decorative against a script. Per client too, or one
# scanner's attempts would bounce the operator's login with "too fast".
MIN_SECONDS_BETWEEN_ATTEMPTS = 1.0

# Bound on tracked addresses: /api/auth/login is unauthenticated, so a sweep
# from many addresses must not grow this without limit. An entry with no lock
# in force and no attempt for a day is forgotten (its strikes with it).
MAX_TRACKED_CLIENTS = 4096
CLIENT_FORGET_SECONDS = 24 * 60 * 60

# Global soft brake (red team): per-address counters do nothing against a
# sweep from many addresses. More than GLOBAL_BRAKE_FAILURES failures across ALL
# clients inside GLOBAL_BRAKE_WINDOW seconds => the whole box accepts at most
# one login/setup attempt per GLOBAL_BRAKE_INTERVAL until the rate drops.
# Rejected, not slept: a sleep would park a server thread per attempt, which a
# parallel attacker turns into a denial of service. The operator's own attempt
# still gets through on a retry.
GLOBAL_BRAKE_FAILURES = 100
GLOBAL_BRAKE_WINDOW = 60.0
GLOBAL_BRAKE_INTERVAL = 1.0

_attempt_lock = threading.Lock()
# addr -> {"failed", "strikes", "lock_until", "last"}; times are time.monotonic()
_clients = {}
# The last GLOBAL_BRAKE_FAILURES+1 failure times: bounded whatever the sweep size.
_recent_failures = collections.deque(maxlen=GLOBAL_BRAKE_FAILURES + 1)
_last_braked_attempt = 0.0

# --- audit log ---------------------------------------------------------------
#
# NOT /app/logs — that bind mount was removed, so a log written there dies on
# every container recreate. /app/data is the bind mount that persists.
AUTH_DIR = os.environ.get("INTACT_AUTH_DIR", "/app/data/auth")
AUDIT_LOG = os.path.join(AUTH_DIR, "audit.jsonl")
# Rotate, because /api/auth/login is unauthenticated by necessity: a scanner
# hammering it would otherwise write unbounded lines into a host bind mount and
# fill the operator's disk.
AUDIT_MAX_BYTES = 5 * 1024 * 1024
# Every write by every user lands here now, not only logins: keep 50 MB.
AUDIT_KEEP = 10

_audit_lock = threading.Lock()


# =============================================================================
# config.yaml — the first_login flag
# =============================================================================
#
# Resolution order matters. /app/config.yaml is mounted READ-ONLY
# (modules/backend/docker-compose.yaml) so writes there raise OSError;
# /app/workdir is the read-write mount of the repo root and is what
# services/upgrade/base.py already uses. We read from the SAME path we write to,
# so there is never a stale-view discrepancy between the two mounts of the same
# host file.
_CONFIG_CANDIDATES = (
    "/app/workdir/config.yaml",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "config.yaml"),
    "/home/tenroot/intact/config.yaml",
)

FIRST_LOGIN_TRUE = "true"
FIRST_LOGIN_FALSE = "false"
FIRST_LOGIN_ABSENT = "absent"
FIRST_LOGIN_ERROR = "error"


def config_path() -> Optional[str]:
    """Absolute path to the config.yaml we read AND write, or None."""
    override = os.environ.get("INTACT_CONFIG_PATH")
    if override:
        return override if os.path.isfile(override) else None
    for candidate in _CONFIG_CANDIDATES:
        resolved = os.path.abspath(candidate)
        if os.path.isfile(resolved):
            return resolved
    return None


def read_first_login() -> str:
    """One of FIRST_LOGIN_{TRUE,FALSE,ABSENT,ERROR}.

    Re-read from disk on EVERY call, never cached. The documented recovery path
    for a forgotten password is `sudo scripts/reset-login.sh`, which sets
    first_login: true in config.yaml on the host — caching would silently make
    that a no-op until someone remembered to `docker restart intact_backend`.

    ABSENT means the key isn't in the file at all, which identifies a box
    upgraded from a version that predates app-level auth (the shipped
    config.yaml carries the key, so a fresh install always has it). ERROR means
    the file is missing or unparseable, and callers must fail CLOSED on it — do
    not copy the deliberately fail-open idiom in
    services/upgrade/intact.py:_read_dashboard_credentials, which degrades to a
    generated password; degrading open here would unlock the appliance.
    """
    path = config_path()
    if not path:
        return FIRST_LOGIN_ERROR
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle.read())
    except Exception:
        return FIRST_LOGIN_ERROR
    if not isinstance(data, dict):
        return FIRST_LOGIN_ERROR
    if "first_login" not in data:
        return FIRST_LOGIN_ABSENT
    return FIRST_LOGIN_TRUE if bool(data.get("first_login")) else FIRST_LOGIN_FALSE


def write_first_login(value: bool) -> bool:
    """Set the top-level `first_login:` key, preserving everything else byte
    for byte. Returns True on success.

    TRUNCATE IN PLACE — `open(path, 'w')`. Never write-a-temp-then-os.replace().
    Docker bind-mounts single files BY INODE, and this file is mounted twice
    (read-only at /app/config.yaml, read-write via /app/workdir). Replacing the
    inode would leave the read-only mount — and therefore
    config.py:load_main_config() — pinned to the OLD content, so a completed
    setup would keep reporting first_login: true and the appliance would serve
    its unauthenticated setup page forever. lib/modules.sh:_write_nginx_htpasswd
    documents the same trap for the same reason.

    Edits by text rather than yaml.safe_load + yaml.dump so the operator's
    comments, blank lines and key order survive — same rationale as
    services/upgrade/intact.py:merge_versions_from_new_config. Everything
    outside the first_login line is asserted unchanged before we commit.
    """
    path = config_path()
    if not path:
        print("[AUTH] Cannot write first_login: config.yaml not found", flush=True)
        return False

    literal = "true" if value else "false"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read()
    except Exception as exc:
        print(f"[AUTH] Cannot read {path}: {exc}", flush=True)
        return False

    lines = original.splitlines(keepends=True)
    # Top-level key only: no leading whitespace. A `first_login:` nested under
    # some other key is a different setting and must not be touched.
    pattern = re.compile(r"^first_login\s*:.*$")
    replaced = False
    for index, line in enumerate(lines):
        if pattern.match(line.rstrip("\r\n")):
            newline = "\n" if line.endswith("\n") else ""
            lines[index] = f"first_login: {literal}{newline}"
            replaced = True
            break

    if not replaced:
        # Key absent (pre-auth box). Insert at the top, after schema_version if
        # present, so the flag an operator may need to edit by hand is the
        # first thing they see.
        insert_at = 0
        for index, line in enumerate(lines):
            if re.match(r"^schema_version\s*:", line.rstrip("\r\n")):
                insert_at = index + 1
                break
        lines.insert(insert_at, f"first_login: {literal}\n")

    updated = "".join(lines)

    # Safety assert: the ONLY difference may be the first_login line. Protects
    # the operator's domain, module passwords and versions pins from a parser
    # bug in the loop above.
    if _strip_first_login(original) != _strip_first_login(updated):
        print("[AUTH] Refusing to write config.yaml: edit would have changed "
              "content outside the first_login line", flush=True)
        return False

    try:
        with open(path, "w", encoding="utf-8") as handle:   # truncate in place
            handle.write(updated)
        return True
    except Exception as exc:
        print(f"[AUTH] Cannot write {path}: {exc}", flush=True)
        return False


def _strip_first_login(text: str) -> str:
    """`text` with any top-level first_login line removed, for the diff assert."""
    keep = [ln for ln in text.splitlines(keepends=True)
            if not re.match(r"^first_login\s*:", ln.rstrip("\r\n"))]
    return "".join(keep)


# =============================================================================
# Credential storage
# =============================================================================

def _int_secret(key: str, default: int = 0) -> int:
    raw = get_secret(key)
    try:
        return int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default


def credential_generation() -> int:
    """The pre-users scheme's generation (one box-wide counter). Still bumped
    by _sync_legacy() so that a box rolled back to an older release drops every
    session issued by this one."""
    return _int_secret(_K_GENERATION, 0)


# The legacy generation _sync_legacy() last wrote. A different value at boot
# means the box ran the older release since (a rollback) and someone changed
# the password or ran setup there: that credential is the current one.
_K_LEGACY_SYNCED = "auth_legacy_synced_generation"


def migrate_legacy_credential() -> bool:
    """The single pre-users login becomes the Super-admin, same name and same
    hash, so nobody types anything new after the upgrade. Runs on every boot.
    True when it created or refreshed the Super-admin."""
    stored_hash, stored_user = get_secret(_K_HASH), get_secret(_K_USER)
    if not stored_hash or not stored_user:
        return False
    sa = users.superadmin()
    if sa is None and not users.count():
        # Kept even if the name fails users.name_problem() (it only governs NEW
        # names): refusing it here would lock the operator out of their own box.
        users.create(stored_user, stored_hash, users.SUPERADMIN, "migration", False)
    elif sa is not None and get_secret(_K_LEGACY_SYNCED) not in (None, str(credential_generation())):
        users.set_password(sa["id"], stored_hash) if stored_hash != sa["pw_hash"] else None
        other = users.by_name(stored_user)
        if stored_user.strip().lower() != sa["username"] and other is None:
            users.rename(sa["id"], stored_user)
    else:
        if get_secret(_K_LEGACY_SYNCED) is None:
            _sync_legacy()
        return False
    # Moves the legacy generation, so no cookie the older release issued, and
    # none this one issues, is valid in the other after a rollback.
    _sync_legacy()
    return True


def _sync_legacy() -> None:
    """Keep the old single-credential rows equal to the Super-admin.

    The release before this one reads only those rows. Mirroring them means a
    rollback still signs the Super-admin in (with their current password) and
    no one else -- never a stale credential nobody remembers."""
    sa = users.superadmin()
    if not sa:
        return
    gen = str(credential_generation() + 1)
    set_secret(_K_HASH, sa["pw_hash"])
    set_secret(_K_USER, sa["username"])
    set_secret(_K_GENERATION, gen)
    set_secret(_K_LEGACY_SYNCED, gen)


def has_credential() -> bool:
    return users.superadmin() is not None


def username() -> Optional[str]:
    sa = users.superadmin()
    return sa["username"] if sa else None


def set_credential(user: str, password: str) -> bool:
    """Set the Super-admin's name and password (setup, and the config.yaml
    carry-over in auth_migrate). Creates the Super-admin on a box with none.
    Other users are never touched: a reset-login.sh recovery resets only the
    top account. pbkdf2 via werkzeug.security — no new packages."""
    if not user or not password:
        return False
    sa = users.superadmin()
    # A recovery keeps the Super-admin's name: renaming would free it for a new
    # user, and names are never reused (they key audit lines and records).
    name = sa["username"] if sa else user.strip().lower()
    other = users.by_name(name)
    if other and other["role"] != users.SUPERADMIN:
        return False                    # would hijack an existing account
    pw_hash = generate_password_hash(password)
    try:
        if sa:
            users.set_password(sa["id"], pw_hash)
            if not sa["enabled"]:
                users.set_enabled(sa["id"], True)
        else:
            users.create(name, pw_hash, users.SUPERADMIN, "setup", False)
    except Exception as exc:
        print(f"[AUTH] Could not store the Super-admin: {exc}", flush=True)
        return False
    _sync_legacy()
    reset_lockout()
    return True


# A real hash to burn time on when the name is unknown, so a wrong username is
# not measurably faster to reject than a wrong password.
_DUMMY_HASH = None


def authenticate(user: str, password: str) -> Optional[dict]:
    """The user row when `user`/`password` are right, the account is enabled
    and a temporary password has not expired; else None. Fails CLOSED when no
    user exists (reachable after a DB export/import, since the users table is
    not in export_db) — never "nothing configured" as "anything goes"."""
    global _DUMMY_HASH
    row = users.by_name(user)
    if not row:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = generate_password_hash(os.urandom(8).hex())
        check_password_hash(_DUMMY_HASH, password or "")
        return None
    try:
        ok = check_password_hash(row["pw_hash"], password or "")
    except (ValueError, TypeError):
        ok = False          # a redacted or foreign hash: refuse, never crash
    if not ok:
        return None
    if not row["enabled"]:
        return None
    if row.get("temp_expires") and time.time() > row["temp_expires"]:
        return None
    return row


def verify_password(user: str, password: str) -> bool:
    return authenticate(user, password) is not None


def set_user_password(row: dict, password: str, temporary: bool = False) -> None:
    users.set_password(row["id"], generate_password_hash(password), temporary)
    if row["role"] == users.SUPERADMIN:
        _sync_legacy()


def create_user(username_value: str, role: str, created_by: str) -> str:
    """Create a user with a one-time temporary password and return it. The
    caller shows it ONCE; only its hash is stored."""
    temp = users.new_temp_password()
    users.create(username_value, generate_password_hash(temp), role, created_by, True)
    return temp


def reset_user_password(row: dict) -> str:
    temp = users.new_temp_password()
    set_user_password(row, temp, temporary=True)
    return temp


def transfer_superadmin(from_row: dict, to_row: dict) -> None:
    users.transfer_superadmin(from_row["id"], to_row["id"])
    _sync_legacy()


def session_secret_key() -> str:
    """Flask's signing key, persisted so a backend restart doesn't log everyone
    out. Generated once on first use.

    Safe to call at import time: services/storage/__init__ runs init_storage()
    on import and the `secrets` table is in its CREATE TABLE IF NOT EXISTS
    block, so the table exists before app.py builds the Flask app.
    """
    existing = get_secret(_K_SESSION_KEY)
    if existing:
        return existing
    generated = os.urandom(32).hex()
    set_secret(_K_SESSION_KEY, generated)
    return generated


# =============================================================================
# Lockout
# =============================================================================

# =============================================================================
# Which address a request counts against
# =============================================================================
#
# X-Real-IP is only as trustworthy as whoever set it. nginx overwrites it with
# $remote_addr, but the backend is also reachable WITHOUT nginx: any peer
# container on intact_network (the F-010 threat) and 127.0.0.1:5001 on the host.
# Trusting the header from those let a script send a fresh X-Real-IP per guess
# and never meet the lockout (red team). So the header counts only when the TCP
# peer is the nginx container; anyone else is keyed by their real address.
NGINX_HOST = "intact_nginx"
NGINX_REFRESH_SECONDS = 300     # nginx recreated -> new address; re-resolve
NGINX_MISS_RETRY_SECONDS = 30   # bound DNS lookups a non-nginx caller can cause
_nginx = {"addrs": frozenset(), "at": None}


def _resolve_nginx() -> frozenset:
    try:
        return frozenset(socket.gethostbyname_ex(NGINX_HOST)[2])
    except (OSError, UnicodeError):
        return frozenset()      # not on intact_network (tests, dev): trust nobody


def _is_nginx(addr: str) -> bool:
    now = time.monotonic()
    at = _nginx["at"]
    if (at is None or now - at > NGINX_REFRESH_SECONDS
            or (addr not in _nginx["addrs"] and now - at > NGINX_MISS_RETRY_SECONDS)):
        _nginx["addrs"], _nginx["at"] = _resolve_nginx(), now
    return addr in _nginx["addrs"]


def client_address(request) -> str:
    """The address lockout and audit count `request` against."""
    addr = request.remote_addr or "unknown"
    real = (request.headers.get("X-Real-IP") or "").strip()
    return real if real and _is_nginx(addr) else addr


def _entry(client: str) -> dict:
    """The counters for one address (caller holds _attempt_lock)."""
    client = client or "unknown"
    entry = _clients.get(client)
    if entry is None:
        if len(_clients) >= MAX_TRACKED_CLIENTS:
            _prune(time.monotonic())
        entry = _clients[client] = {"failed": 0, "strikes": 0,
                                    "lock_until": 0.0, "last": 0.0}
    return entry


def _prune(now: float) -> None:
    for addr in [a for a, e in _clients.items()
                 if e["lock_until"] <= now and now - e["last"] > CLIENT_FORGET_SECONDS]:
        del _clients[addr]
    # Still full (a sweep from many fresh addresses): drop the least recently
    # seen. That can free a locked address early, but an attacker holding that
    # many addresses is not slowed by a per-address lock anyway.
    while len(_clients) >= MAX_TRACKED_CLIENTS:
        del _clients[min(_clients, key=lambda a: _clients[a]["last"])]


def lock_remaining_seconds(client: str) -> int:
    """Seconds until `client`'s lock lifts, or 0 if not locked."""
    with _attempt_lock:
        entry = _clients.get(client or "unknown")
        if not entry:
            return 0
        remaining = entry["lock_until"] - time.monotonic()
        return int(remaining + 0.999) if remaining > 0 else 0


def reset_lockout(client: Optional[str] = None) -> None:
    """Clear one address's counters, or every address's when None (a new
    credential starts everyone afresh)."""
    with _attempt_lock:
        if client is None:
            _clients.clear()
            _recent_failures.clear()
        else:
            _clients.pop(client or "unknown", None)


def password_guess_refusal(client: str) -> Optional[Tuple[dict, int]]:
    """None to go on, else (body, 429). Every route that checks a password
    typed by a signed-in user (re-auth, change-password, Super-admin transfer)
    counts its misses against the same per-address lockout as login, or a
    stolen cookie could guess the password online at hash speed."""
    locked = lock_remaining_seconds(client)
    if locked > 0:
        return ({'success': False, 'error': 'locked', 'lock_remaining_seconds': locked,
                 'message': f'Too many failed attempts. Try again in {max(1, round(locked / 60))} minute(s).'},
                429)
    if not throttle_ok(client):
        return {'success': False, 'error': 'too_fast', 'message': 'Slow down and try again.'}, 429
    return None


def password_guess_result(client: str, ok: bool) -> None:
    if ok:
        reset_lockout(client)
    else:
        register_failure(client)


def lock_duration_minutes(strikes: int) -> int:
    """15, 30, 60, 120 ... capped at 24h. `strikes` is 1-based."""
    if strikes < 1:
        return 0
    minutes = LOCKOUT_BASE_MINUTES * (2 ** (strikes - 1))
    return min(minutes, LOCKOUT_CAP_MINUTES)


def register_failure(client: str) -> int:
    """Count one failed attempt from `client`. Returns the lock duration in
    seconds if this attempt triggered a lock, else 0.

    Never touches first_login. Flipping it here would mean an attacker could
    deliberately fail 10 times to open the unauthenticated setup page and claim
    the account — turning the lockout into an account-takeover primitive.
    """
    with _attempt_lock:
        entry = _entry(client)
        entry["last"] = time.monotonic()
        _recent_failures.append(entry["last"])
        entry["failed"] += 1
        if entry["failed"] % LOCKOUT_THRESHOLD != 0:
            return 0
        entry["strikes"] += 1
        minutes = lock_duration_minutes(entry["strikes"])
        entry["lock_until"] = time.monotonic() + minutes * 60
        return minutes * 60


def _braked(now: float) -> bool:
    """More than GLOBAL_BRAKE_FAILURES failures inside the window (lock held)."""
    return (len(_recent_failures) > GLOBAL_BRAKE_FAILURES
            and now - _recent_failures[0] <= GLOBAL_BRAKE_WINDOW)


def throttle_ok(client: str) -> bool:
    """False if `client`'s attempts arrive faster than MIN_SECONDS_BETWEEN_ATTEMPTS,
    or the global brake is on and another attempt was let through < 1 s ago."""
    global _last_braked_attempt
    with _attempt_lock:
        entry = _entry(client)
        now = time.monotonic()
        if entry["last"] and now - entry["last"] < MIN_SECONDS_BETWEEN_ATTEMPTS:
            return False
        if _braked(now):
            if now - _last_braked_attempt < GLOBAL_BRAKE_INTERVAL:
                return False
            _last_braked_attempt = now
        entry["last"] = now
        return True


def failures_before_lock(client: str) -> int:
    """How many more failures until the next lock — shown on the login page."""
    with _attempt_lock:
        entry = _clients.get(client or "unknown")
        failed = entry["failed"] if entry else 0
    return LOCKOUT_THRESHOLD - (failed % LOCKOUT_THRESHOLD)


# =============================================================================
# One-time setup token
# =============================================================================
#
# While first_login is true the setup endpoint used to accept the FIRST visitor
# from the network (QA): an attacker could lock the operator out, wait for them
# to reopen setup, and claim the box. Now setup also needs the token that
# lib/setup_token.sh writes on the host (install.sh prints it; so does
# `sudo scripts/reset-login.sh`). Only root on the host can read the file, so
# reaching the page is no longer enough. Deleting the file is how it is spent.

def setup_token_path() -> str:
    return (os.environ.get("INTACT_SETUP_TOKEN_PATH")
            or os.path.join(STORAGE_BASE, "state", "backend", "setup_token"))


def read_setup_token() -> Optional[str]:
    """The current token, or None when there is none (spent, or never made)."""
    try:
        with open(setup_token_path(), "r", encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def setup_token_matches(given) -> bool:
    expected = read_setup_token()
    if not expected or not isinstance(given, str) or not given.strip():
        return False
    return hmac.compare_digest(given.strip().encode("utf-8"), expected.encode("utf-8"))


_token_stamp = None


def forgive_lockouts_on_new_token() -> None:
    """Clear every lockout the first time a new token file is seen.

    The usual reason to run reset-login.sh is having locked OUR OWN address
    with ten wrong passwords; without this the operator would then be refused
    setup for 15+ minutes. Only root on the host can make a token, so an
    attacker cannot use this to shed a lock.
    """
    global _token_stamp
    try:
        st = os.stat(setup_token_path())
    except OSError:
        return
    stamp = (st.st_ino, st.st_mtime_ns)
    with _attempt_lock:
        if stamp != _token_stamp:
            _clients.clear()
            _token_stamp = stamp


def consume_setup_token() -> bool:
    """Delete the token. True only for the caller whose unlink removed it, so
    two concurrent setups with the right token cannot both succeed."""
    try:
        os.unlink(setup_token_path())
        return True
    except OSError:
        return False


# =============================================================================
# Password rule — setup and change-password only
# =============================================================================
#
# Same rule as lib/secrets.sh:secret_check. The minimum used to be removed on
# purpose so the shipped default (123123) could be the dashboard password; QA
# flagged that as a known/weak credential on a tool that controls every
# endpoint. Applied only when a password is SET -- never at login, so a box
# whose operator set a short password before this rule keeps signing in.
KNOWN_DEFAULT_PASSWORDS = frozenset({"123123", "Ch4nge-Me!Intact2026", "1234qwer!@#$", "changeme"})
# NIST SP 800-63B-4 (single-factor): 15+ characters, any characters including
# spaces, NO composition rules, checked against known and trivial values. It
# no longer matches lib/secrets.sh's module-password rule on purpose: a
# dashboard password is only ever hashed, never written into a shell file.
PASSWORD_MIN, PASSWORD_MAX = 15, 256
PASSWORD_RULE = (f"at least {PASSWORD_MIN} characters; any characters, spaces "
                 f"included. A passphrase of a few words works well")
# shortcut: a short built-in list, not a breached-password corpus (air-gapped
# boxes cannot fetch one); ship a bundled list if customers ask for it.
_COMMON_PREFIXES = ("password", "123456789", "qwertyuiop", "abcdefghij", "letmein",
                    "welcome", "iloveyou", "admin", "intact")


def weak_passwords_allowed() -> bool:
    """True on a LAB box whose config.yaml says `allow_weak_passwords: true`.

    Same switch lib/secrets.sh:secret_weak_allowed reads. Shipped false, and the
    pre-commit sanitizer forces it back to false. Re-read on every call, like
    first_login, so flipping it needs no backend restart. Any doubt (no file,
    unparseable) answers False -- the rule stays on. Only true/True/TRUE, like
    the shell: YAML 1.1 also reads `yes`/`on` as True, which secret_weak_allowed
    does not, so the raw line must say true as well.
    """
    if os.environ.get("INTACT_ALLOW_WEAK_PASSWORDS") == "1":
        return True
    path = config_path()
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        data = yaml.safe_load(text)
    except Exception:
        return False
    return (isinstance(data, dict) and data.get("allow_weak_passwords") is True
            and re.search(r"^allow_weak_passwords:[ \t]*(true|True|TRUE)[ \t]*(#.*)?$", text, re.M) is not None)


def password_problem(password: str, username_value: str = "") -> Optional[str]:
    """None when a password being SET meets the rule, else the reason (never
    the value). Applied only when a password is set, never at login."""
    if not password:
        return "it is empty"
    if not password.isprintable():
        return "it has control characters"
    if weak_passwords_allowed():
        return None                     # lab box: anything printable
    if password in KNOWN_DEFAULT_PASSWORDS:
        return "it is a publicly known default"
    if len(password) < PASSWORD_MIN:
        return f"it is shorter than {PASSWORD_MIN} characters"
    if len(password) > PASSWORD_MAX:
        return f"it is longer than {PASSWORD_MAX} characters"
    low = password.lower()
    if len(set(low)) < 5 or low.startswith(_COMMON_PREFIXES):
        return "it is too easy to guess"
    if username_value and username_value.strip().lower() in low:
        return "it contains the user name"
    return None


def needs_change(password: str) -> bool:
    """True when a password that just LOGGED IN must be replaced before the
    session may do anything else: a publicly known default. A password set
    under an older, shorter rule keeps working (decided: the new rule applies
    at the next change). Never on a lab box."""
    if weak_passwords_allowed():
        return False
    return password in KNOWN_DEFAULT_PASSWORDS


MUST_CHANGE_TEMP = "temp"


def must_change(session) -> bool:
    """The session logged in with a password that needs_change(), or with a
    one-time password. The lab switch lifts the first without a re-login,
    never the second: a one-time password expires, and its user must have
    chosen their own by then."""
    flag = session.get("must_change") if session else None
    if flag == MUST_CHANGE_TEMP:
        return True
    return bool(flag) and not weak_passwords_allowed()


# =============================================================================
# Session validation
# =============================================================================

SESSION_OK = "ok"
SESSION_NONE = "none"
SESSION_EXPIRED = "expired"
SESSION_CREDENTIALS_CHANGED = "credentials_changed"
# The account was disabled (or removed) since the session was issued.
SESSION_DISABLED = "disabled"
# Not session states: gate_decision's answers for a valid session that must
# change its password first, lacks the role, or must re-enter its password
# (403, not 401 -- the session itself is fine).
PASSWORD_CHANGE_REQUIRED = "password_change_required"
FORBIDDEN = "forbidden"
REAUTH_REQUIRED = "reauth_required"
CSRF_REJECTED = "csrf_rejected"


# Last activity per session, in memory. Someone working only inside a tool
# (Kibana in its own window) reaches the backend only through nginx's per-tool
# auth_request, and nginx drops a subrequest's Set-Cookie, so the cookie's
# `seen` never moves for them and the 1-hour idle limit would sign them out
# mid-work. Every allowed request -- the tool check included -- stamps this.
# A backend restart forgets it; the cookie's own `seen` is the floor.
_last_active = {}
_ACTIVE_MAX = 10000


def note_activity(session) -> None:
    key = (session.get("uid"), session.get("iat"))
    if key[0] is None:
        return
    now = time.time()
    if len(_last_active) >= _ACTIVE_MAX:
        for k in [k for k, t in _last_active.items() if now - t > SESSION_IDLE_LIMIT_SECONDS]:
            del _last_active[k]
        if len(_last_active) >= _ACTIVE_MAX:
            _last_active.clear()
    _last_active[key] = now


def _num(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def evaluate_session(session) -> str:
    """Classify a Flask session dict: SESSION_OK / NONE / EXPIRED /
    CREDENTIALS_CHANGED / DISABLED. No mutation, and no SQLite on the hot path:
    users.get() reads the in-process snapshot.

    A cookie from before users existed carries no `uid`: CREDENTIALS_CHANGED,
    so the upgrade signs everyone in once more."""
    if not session or not session.get("user"):
        return SESSION_NONE
    row = users.get(session.get("uid"))
    if row is None:
        return SESSION_CREDENTIALS_CHANGED
    if not row["enabled"]:
        return SESSION_DISABLED
    if session.get("gen") != _session_gen(row):
        return SESSION_CREDENTIALS_CHANGED
    now = time.time()
    seen = max(_num(session.get("seen")),
               _last_active.get((session.get("uid"), session.get("iat")), 0.0))
    if now - seen > SESSION_IDLE_LIMIT_SECONDS:
        return SESSION_EXPIRED
    if now - _num(session.get("iat")) > SESSION_ABSOLUTE_LIMIT_SECONDS:
        return SESSION_EXPIRED
    return SESSION_OK


def session_user(session) -> Optional[dict]:
    """The signed-in user's row, or None. The ROLE always comes from here (the
    table), never from the cookie, so a demotion applies on the next request."""
    if evaluate_session(session) != SESSION_OK:
        return None
    return users.get(session.get("uid"))


def _session_gen(row: dict) -> str:
    """A string, never an int. The release before users accepts any cookie
    whose `gen` equals its box-wide integer counter (same signing key, same
    cookie name), and a new user's generation starts at 1 too: a Read-only
    user's cookie would be the all-powerful single user after a rollback."""
    return f"u{row['generation']}"


def start_session(session, row: dict) -> None:
    session.clear()
    session.permanent = True
    now = time.time()
    session["uid"] = row["id"]
    session["user"] = row["username"]
    session["gen"] = _session_gen(row)
    session["iat"] = now
    session["seen"] = now
    session["auth_at"] = now


def mark_reauthenticated(session) -> None:
    session["auth_at"] = time.time()


def recently_authenticated(session) -> bool:
    return time.time() - _num(session.get("auth_at")) <= REAUTH_SECONDS


# --- the request gate -------------------------------------------------------
#
# Reachable without a session. Everything else under /api/ requires one.
# (logout and status stay reachable for a must_change session too: they are here.)
EXEMPT_PATHS = frozenset({
    '/api/auth/status',
    '/api/auth/login',
    '/api/auth/setup',
    '/api/auth/logout',
    '/api/auth/verify',
    '/api/health',
    # tusd (a separate container) posts upload lifecycle hooks here — see
    # -hooks-http in modules/backend/docker-compose.yaml. Not reachable from a
    # browser: nginx rewrites /api/uploads/* to /files/* for tusd, so an external
    # request to this path never arrives at the backend at all.
    '/api/uploads/hook',
})

# Requests originating on the box itself bypass the gate. Safe HERE
# specifically, and all three conditions must hold:
#   1. The host port is published 127.0.0.1:5001:5001 (see
#      modules/backend/docker-compose.yaml), so loopback is unreachable off-box.
#   2. There is no ProxyFix installed, so remote_addr is the real peer rather
#      than a client-controlled X-Forwarded-For. nginx-proxied requests arrive as
#      nginx's 172.x address on intact_network, never as loopback.
#   3. Peer containers — the F-010 threat this gate exists to close — are
#      therefore also 172.x and stay blocked. This does NOT reopen F-010.
# Without it these all break with 401: the container healthcheck, install.sh's
# wait loop and LLM catalog bootstrap (lib/modules.sh), the post-upgrade health
# check in services/upgrade/__init__.py (which would report DEGRADED on every
# single upgrade), and the whole tests/live suite. Anyone with a shell on the box
# can already read data/intact.db, so this concedes nothing new.
LOOPBACK_ADDRS = frozenset({'127.0.0.1', '::1'})


# The one gated route a must_change session may call.
CHANGE_PASSWORD_PATH = '/api/auth/change-password'


_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def csrf_problem(method: str, headers) -> bool:
    """True when a state-changing request came from another ORIGIN.

    SameSite=Lax is not enough here: Kibana (5602), Timesketch (5443) and VolWeb
    (8002) are on the same host, and "same-site" ignores the port (RFC 6265
    §8.5), so a script bug in any of them could POST to this API with the
    user's cookie -- for example to create an Admin. Sec-Fetch-Site does tell
    origins apart. A request without browser headers (curl, a script with its
    own cookie) is no CSRF vector and passes."""
    if method not in _UNSAFE_METHODS:
        return False
    site = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if site:
        return site not in ("same-origin", "none")
    origin = (headers.get("Origin") or "").strip()
    if not origin or origin == "null":
        return bool(origin)             # "null" is an opaque, foreign origin
    # nginx passes $host (no port). shortcut: a browser without Sec-Fetch-Site
    # on a non-443 dashboard port is refused; every current browser sends it.
    host = (headers.get("Host") or "").strip()
    return origin.split("://", 1)[-1] != host


def gate_decision(path: str, method: str, remote_addr: str, session,
                  endpoint: Optional[str] = None, headers=None) -> Optional[str]:
    """None to allow the request; otherwise the reason: for the 401 one of
    SESSION_NONE / EXPIRED / CREDENTIALS_CHANGED / DISABLED; for a 403
    PASSWORD_CHANGE_REQUIRED, FORBIDDEN (the role may not), REAUTH_REQUIRED
    (step-up) or CSRF_REJECTED.

    Pure and side-effect free so it can be tested directly rather than through a
    live Flask app — app.py's before_request hook is a thin wrapper over this.
    `endpoint` is Flask's request.endpoint ("blueprint.function"), the key of
    services/access_policy.POLICY.
    """
    # Browsers send a credential-less preflight; CORS handles it.
    if method == 'OPTIONS':
        return None
    # Only the API is gated. Flask serves no dashboard HTML (nginx does), so in
    # practice everything here is /api/*, but be explicit rather than assume.
    if not (path or '').startswith('/api/'):
        return None
    if remote_addr in LOOPBACK_ADDRS:
        return None
    # Before the exemptions: login and setup are state changes too (login CSRF).
    if headers is not None and csrf_problem(method, headers):
        return CSRF_REJECTED
    if path in EXEMPT_PATHS:
        return None
    state = evaluate_session(session)
    if state != SESSION_OK:
        return state
    if path != CHANGE_PASSWORD_PATH and must_change(session):
        return PASSWORD_CHANGE_REQUIRED
    row = users.get(session.get("uid"))
    rule = access_policy.rule_for(endpoint, method)
    if users.rank(row["role"]) < users.rank(rule.role):
        return FORBIDDEN
    if rule.step_up and not recently_authenticated(session):
        return REAUTH_REQUIRED
    return None


def tool_allowed(session, tool: str) -> bool:
    """nginx's per-tool auth_request: a valid session whose role may open
    `tool` (access_policy.TOOLS). An unknown tool name is refused."""
    if evaluate_session(session) != SESSION_OK or must_change(session):
        return False
    need = access_policy.TOOLS.get(tool or "")
    row = users.get(session.get("uid"))
    return need is not None and users.rank(row["role"]) >= users.rank(need)


def touch_session(session) -> bool:
    """Slide the window. Returns True if the session was re-stamped (and so the
    cookie needs re-signing)."""
    seen = session.get("seen") or 0
    try:
        seen = float(seen)
    except (TypeError, ValueError):
        seen = 0
    if time.time() - seen > SESSION_TOUCH_INTERVAL_SECONDS:
        session["seen"] = time.time()
        return True
    return False


# =============================================================================
# Audit log
# =============================================================================

def _rotate_if_needed() -> None:
    try:
        if os.path.getsize(AUDIT_LOG) < AUDIT_MAX_BYTES:
            return
    except OSError:
        return
    for index in range(AUDIT_KEEP, 0, -1):
        older = f"{AUDIT_LOG}.{index}"
        newer = AUDIT_LOG if index == 1 else f"{AUDIT_LOG}.{index - 1}"
        if os.path.exists(newer):
            try:
                shutil.move(newer, older)
            except OSError:
                pass


# Hash chain (NIST SP 800-53 AU-9(3)): every line carries the hash of the line
# before it, across rotations, so an edited, inserted or deleted line breaks
# the chain where it happened (verify_audit_chain). It cannot stop root on the
# host from rewriting the whole file; an off-box copy is what does that.
_last_hash: Optional[str] = None


def _entry_hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, default=str))
                          .encode("utf-8")).hexdigest()


def _tail_hash() -> str:
    """The last line's hash, read once after a restart."""
    for path in [AUDIT_LOG] + [f"{AUDIT_LOG}.{i}" for i in range(1, AUDIT_KEEP + 1)]:
        try:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - 65536))
                lines = handle.read().splitlines()
        except OSError:
            continue
        for raw in reversed(lines):
            try:
                found = json.loads(raw).get("hash")
            except (ValueError, AttributeError):
                found = None
            if found:
                return found
    return ""


def verify_audit_chain(paths) -> Optional[int]:
    """None when the lines in `paths` (oldest first) chain correctly, else the
    1-based line number where the chain breaks. Lines from before the chain
    existed (no "hash") are skipped."""
    prev, n = None, 0
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                n += 1
                entry = json.loads(line)
                got = entry.pop("hash", None)
                if got is None:
                    continue
                if prev is not None and entry.get("prev") != prev:
                    return n
                if _entry_hash(entry.get("prev", ""), entry) != got:
                    return n
                prev = got
    return None


def audit(event: str, request=None, username_value: str = None, **extra) -> None:
    """Append one JSON object to the auth audit log.

    Never raises — an unwritable log must not be able to break login.
    """
    global _last_hash
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "user": username_value,
    }
    if request is not None:
        try:
            entry["ip"] = client_address(request)
            entry["user_agent"] = (request.headers.get("User-Agent") or "")[:200]
        except Exception:
            pass
    entry.update(extra)

    try:
        with _audit_lock:
            os.makedirs(AUTH_DIR, exist_ok=True)
            _rotate_if_needed()
            if _last_hash is None:
                _last_hash = _tail_hash()
            entry["prev"] = _last_hash
            entry["hash"] = _entry_hash(_last_hash, entry)
            with _open_audit_append() as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
            _last_hash = entry["hash"]
    except Exception as exc:
        print(f"[AUTH] Could not write audit log: {exc}", flush=True)


def _open_audit_append():
    """Open the audit log for append, creating it 0600.

    A plain `open(path, "a")` creates with the process umask, which is 022 for
    the root backend container — so the log lands 0644 and is readable by every
    account on the host. install.sh chmods it to 0600, but that runs at install
    time and this file is created on the FIRST AUTH EVENT, which is always
    afterwards. So the hardening was reliably undone within seconds of the
    install finishing, and a fresh box always ended up with a world-readable
    audit log. Found by the QA harness's post-install permission sweep.

    It records usernames, source IPs and user agents for every login, setup and
    lockout — an attacker-useful map of who administers the appliance and from
    where.

    The chmod on the existing path is for boxes already carrying a 0644 file
    from before this fix; without it they stay wrong forever, since the file is
    only created once.
    """
    try:
        if os.stat(AUDIT_LOG).st_mode & 0o077:
            os.chmod(AUDIT_LOG, 0o600)
    except OSError:
        pass          # does not exist yet, or not ours to chmod — O_CREAT covers it
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")


# =============================================================================
# Public state summary — drives both the login/setup pages and the gate
# =============================================================================

MODE_SETUP = "setup"
MODE_LOGIN = "login"
MODE_ERROR = "error"


def auth_mode() -> str:
    """MODE_SETUP when the appliance is waiting to be claimed, MODE_LOGIN when a
    credential is expected, MODE_ERROR when config.yaml can't be read.

    ABSENT maps to MODE_LOGIN, not MODE_SETUP: a box upgraded from a pre-auth
    version has its existing nginx Basic Auth credential migrated in by
    services/upgrade/intact.py, so it should be asking for a password, not
    offering itself up to whoever reaches it first. If that migration could not
    recover a credential it writes first_login: true explicitly.
    """
    flag = read_first_login()
    if flag == FIRST_LOGIN_ERROR:
        return MODE_ERROR
    if flag == FIRST_LOGIN_TRUE:
        return MODE_SETUP
    return MODE_LOGIN


def recovery_hint() -> str:
    """Shown on the login page ALWAYS, not only while locked — a forgotten
    password needs a visible way out, and the operator asked for it to be
    stated up front.

    Not "edit first_login" any more: setup also needs the one-time token, and
    reset-login.sh writes both. No restart: read_first_login() and
    read_setup_token() re-read the files on every call.
    """
    return ("Forgotten your password? Ask an Admin for a one-time password. "
            "Super-admin locked out? On the appliance, run "
            "sudo scripts/reset-login.sh, then open the setup page and enter "
            "the setup token it prints. It resets only the Super-admin. "
            "No restart needed.")
