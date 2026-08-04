#!/usr/bin/env python3
"""Single-user dashboard authentication.

Replaces the nginx server-level HTTP Basic Auth gate that used to be the
platform's ONLY authentication (see modules/nginx/config/nginx.conf). That gate
was a browser popup with no logout, no session, no audit trail, and no recovery
path other than `sudo cat modules/nginx/secrets/nginx_basic_auth_password`. It
also did nothing for audit finding F-010: the Flask backend performed no auth of
its own, so any peer container on intact_network could reach intact_backend:5001
and bypass nginx entirely. The `require_auth` gate below closes that too.

Deliberately single-user, no roles — this is an appliance with one operator.

Three things in here are load-bearing and easy to "simplify" into a security
hole. Each is commented at its implementation:

  1. write_first_login() truncates in place and MUST NOT rename-into-place.
  2. The setup endpoint writes first_login=false BEFORE storing the credential.
  3. A lockout must never flip first_login to true.
"""

import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

import yaml
from werkzeug.security import check_password_hash, generate_password_hash

from services.storage.secret_store import get_secret, set_secret

# --- where state lives -------------------------------------------------------
#
# The credential hash, session key and lockout counters live in the `secrets`
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
_K_FAILED = "auth_failed_count"
_K_LOCK_UNTIL = "auth_lock_until"
_K_STRIKES = "auth_lock_strikes"
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
SESSION_IDLE_LIMIT_SECONDS = 7 * 24 * 60 * 60   # real sliding window
# Only re-stamp `seen` (and therefore re-sign the cookie) this often, rather
# than on literally every request. nginx's auth_request fires a subrequest per
# tus PATCH — ~2000 of them for a 10 GB upload — and re-signing each one is
# pure overhead.
SESSION_TOUCH_INTERVAL_SECONDS = 60 * 60

# --- lockout policy ----------------------------------------------------------
#
# 10 consecutive failures locks for 15 minutes; each further block of 10 doubles
# it, capped at 24h. A TIMED lock rather than a permanent one on purpose:
# /api/auth/login has to be reachable unauthenticated, and with a single user
# the failure counter is inherently global, so a permanent lock would let anyone
# who can route to port 443 lock the real operator out of their own appliance in
# 10 requests and force a trip to the console. This self-heals.
LOCKOUT_THRESHOLD = 10
LOCKOUT_BASE_MINUTES = 15
LOCKOUT_CAP_MINUTES = 24 * 60

# Independent of the counter above: without this, ten failures burn in ~10ms and
# the "10 strikes" rule is decorative against a script.
MIN_SECONDS_BETWEEN_ATTEMPTS = 1.0

_attempt_lock = threading.Lock()
_last_attempt_at = 0.0

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
AUDIT_KEEP = 2

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
    for a forgotten password is "edit config.yaml on the host and set
    first_login: true" — caching would silently make that a no-op until someone
    remembered to `docker restart intact_backend`.

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
    """Bumped on every credential change. Embedded in issued sessions so a
    password change invalidates every existing one and the login page can say
    WHY rather than showing a bare form."""
    return _int_secret(_K_GENERATION, 0)


def has_credential() -> bool:
    return bool(get_secret(_K_HASH))


def username() -> Optional[str]:
    return get_secret(_K_USER)


def set_credential(user: str, password: str) -> bool:
    """Store the single user's id + password hash and bump the generation.

    pbkdf2 via werkzeug.security — already a dependency, no new packages.
    """
    if not user or not password:
        return False
    ok = set_secret(_K_HASH, generate_password_hash(password))
    ok = set_secret(_K_USER, user) and ok
    ok = set_secret(_K_GENERATION, str(credential_generation() + 1)) and ok
    reset_lockout()
    return ok


def verify_password(user: str, password: str) -> bool:
    """Constant-ish-time credential check. Fails CLOSED when no credential is
    stored (reachable after a DB export/import, since secret_store is excluded
    from export_db) — never treat "nothing configured" as "anything goes"."""
    stored_hash = get_secret(_K_HASH)
    stored_user = get_secret(_K_USER)
    if not stored_hash or not stored_user:
        return False
    if not user or user.strip().lower() != stored_user.strip().lower():
        # Still run the hash comparison so a wrong username isn't measurably
        # faster to reject than a wrong password.
        check_password_hash(stored_hash, password or "")
        return False
    return check_password_hash(stored_hash, password or "")


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

def lock_remaining_seconds() -> int:
    """Seconds until the lock lifts, or 0 if not locked."""
    until = _int_secret(_K_LOCK_UNTIL, 0)
    if until <= 0:
        return 0
    remaining = until - int(time.time())
    return remaining if remaining > 0 else 0


def reset_lockout() -> None:
    set_secret(_K_FAILED, "0")
    set_secret(_K_STRIKES, "0")
    set_secret(_K_LOCK_UNTIL, "0")


def lock_duration_minutes(strikes: int) -> int:
    """15, 30, 60, 120 ... capped at 24h. `strikes` is 1-based."""
    if strikes < 1:
        return 0
    minutes = LOCKOUT_BASE_MINUTES * (2 ** (strikes - 1))
    return min(minutes, LOCKOUT_CAP_MINUTES)


def register_failure() -> int:
    """Count one failed attempt. Returns the lock duration in seconds if this
    attempt triggered a lock, else 0.

    Never touches first_login. Flipping it here would mean an attacker could
    deliberately fail 10 times to open the unauthenticated setup page and claim
    the account — turning the lockout into an account-takeover primitive.
    """
    failed = _int_secret(_K_FAILED, 0) + 1
    set_secret(_K_FAILED, str(failed))

    if failed % LOCKOUT_THRESHOLD != 0:
        return 0

    strikes = _int_secret(_K_STRIKES, 0) + 1
    set_secret(_K_STRIKES, str(strikes))
    minutes = lock_duration_minutes(strikes)
    set_secret(_K_LOCK_UNTIL, str(int(time.time()) + minutes * 60))
    return minutes * 60


def throttle_ok() -> bool:
    """False if attempts are arriving faster than MIN_SECONDS_BETWEEN_ATTEMPTS."""
    global _last_attempt_at
    with _attempt_lock:
        now = time.monotonic()
        if now - _last_attempt_at < MIN_SECONDS_BETWEEN_ATTEMPTS:
            return False
        _last_attempt_at = now
        return True


def failures_before_lock() -> int:
    """How many more failures until the next lock — shown on the login page."""
    failed = _int_secret(_K_FAILED, 0)
    return LOCKOUT_THRESHOLD - (failed % LOCKOUT_THRESHOLD)


# =============================================================================
# Session validation
# =============================================================================

SESSION_OK = "ok"
SESSION_NONE = "none"
SESSION_EXPIRED = "expired"
SESSION_CREDENTIALS_CHANGED = "credentials_changed"

# Cached so the hot path (every gated request, plus one nginx auth_request
# subrequest per tus PATCH) is a pure signed-cookie check with no SQLite hit.
# The backend is single-process, and every write goes through
# bump_generation_cache(), so this cannot drift.
_generation_cache: Optional[int] = None


def generation_cached() -> int:
    global _generation_cache
    if _generation_cache is None:
        _generation_cache = credential_generation()
    return _generation_cache


def bump_generation_cache() -> None:
    global _generation_cache
    _generation_cache = credential_generation()


def evaluate_session(session) -> str:
    """Classify a Flask session dict: SESSION_OK / NONE / EXPIRED /
    CREDENTIALS_CHANGED. Pure — no DB, no mutation."""
    if not session or not session.get("user"):
        return SESSION_NONE
    if session.get("gen") != generation_cached():
        return SESSION_CREDENTIALS_CHANGED
    seen = session.get("seen") or 0
    try:
        seen = float(seen)
    except (TypeError, ValueError):
        return SESSION_EXPIRED
    if time.time() - seen > SESSION_IDLE_LIMIT_SECONDS:
        return SESSION_EXPIRED
    return SESSION_OK


def start_session(session, user: str) -> None:
    session.permanent = True
    session["user"] = user
    session["gen"] = generation_cached()
    session["iat"] = time.time()
    session["seen"] = time.time()


# --- the request gate -------------------------------------------------------
#
# Reachable without a session. Everything else under /api/ requires one.
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


def gate_decision(path: str, method: str, remote_addr: str, session) -> Optional[str]:
    """None to allow the request; otherwise the reason to report in the 401
    (one of SESSION_NONE / SESSION_EXPIRED / SESSION_CREDENTIALS_CHANGED).

    Pure and side-effect free so it can be tested directly rather than through a
    live Flask app — app.py's before_request hook is a thin wrapper over this.
    """
    # Browsers send a credential-less preflight; CORS handles it.
    if method == 'OPTIONS':
        return None
    # Only the API is gated. Flask serves no dashboard HTML (nginx does), so in
    # practice everything here is /api/*, but be explicit rather than assume.
    if not (path or '').startswith('/api/'):
        return None
    if path in EXEMPT_PATHS:
        return None
    if remote_addr in LOOPBACK_ADDRS:
        return None
    state = evaluate_session(session)
    return None if state == SESSION_OK else state


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


def audit(event: str, request=None, username_value: str = None, **extra) -> None:
    """Append one JSON object to the auth audit log.

    Never raises — an unwritable log must not be able to break login.
    """
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "user": username_value,
    }
    if request is not None:
        try:
            entry["ip"] = request.headers.get("X-Real-IP") or request.remote_addr
            entry["user_agent"] = (request.headers.get("User-Agent") or "")[:200]
        except Exception:
            pass
    entry.update(extra)

    try:
        with _audit_lock:
            os.makedirs(AUTH_DIR, exist_ok=True)
            _rotate_if_needed()
            with _open_audit_append() as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
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

    No restart in the instructions on purpose: read_first_login() re-reads
    config.yaml on every call, so the edit takes effect on the next page load.
    """
    return ("Locked out, or forgotten the password? On the appliance host, set "
            "first_login: true in config.yaml (top level), then reload this "
            "page to set up new credentials. No restart needed.")
