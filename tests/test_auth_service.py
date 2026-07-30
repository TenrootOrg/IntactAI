"""The dashboard login must not be able to fail open, and must not lock you out
of your own appliance.

These cover services/auth_service.py, which replaced the nginx HTTP Basic Auth
gate that used to be the platform's only authentication. Five things in there are
security-critical in the sense that getting them subtly wrong leaves the
appliance either wide open or permanently unreachable, and none of them are
obvious from reading the call sites:

  1. write_first_login() must TRUNCATE IN PLACE. config.yaml is bind-mounted into
     the backend twice (read-only at /app/config.yaml, read-write via
     /app/workdir), and docker binds single files BY INODE. A
     write-temp-then-rename would leave the read-only mount — and therefore
     config.py:load_main_config() — pinned to the pre-setup content, so a
     completed setup would keep reporting first_login: true and the appliance
     would serve its unauthenticated setup page forever.

  2. It must also not disturb ANYTHING else in config.yaml. That file holds the
     operator's domain, every module password and the version pins.

  3. read_first_login() must fail CLOSED. An unreadable config.yaml is not
     "no auth configured", and verify_password() with nothing stored is not
     "accept anything" — that state is reachable, because secret_store is
     deliberately excluded from export_db(), so a DB export/import round-trip
     produces exactly it.

  4. The lockout must be a TIMED cooldown that escalates, not a permanent lock.
     /api/auth/login is necessarily unauthenticated and there is a single global
     failure counter, so a permanent lock would let anyone who can route to the
     appliance lock the real operator out in 10 requests.

  5. register_failure() must never touch first_login. If a lockout flipped it to
     true, an attacker could deliberately fail 10 times to open the
     unauthenticated setup page and claim the account — turning the lockout into
     an account-takeover primitive.

Runs the real functions with the SQLite secret store swapped for an in-memory
dict and config.yaml pointed at a temp file, so this exercises the actual logic
rather than a re-implementation of it.

Run: docker exec intact_backend python3 /app/workdir/tests/test_auth_service.py
"""

import os
import shutil
import sys
import tempfile
import time

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
BACKEND = os.path.join(REPO, "modules", "backend")


# --- load auth_service, then redirect ONLY its own storage bindings ----------
#
# We must not let these tests read or write the real credential in
# /app/data/intact.db. The obvious shortcut — installing a fake
# services.storage.secret_store into sys.modules — is wrong, and was actively
# harmful: run_all.py gives each file its own process, but CI also runs the whole
# tests/ tree under pytest in ONE process, where a replaced sys.modules entry is
# still in place when tests/test_secret_store.py imports it. That test then
# exercises the fake and fails on behaviour the fake never promised
# (delete_secret returning True for an absent key).
#
# So import the real module graph and rebind the two names auth_service pulled
# into its OWN namespace. auth_service calls them as module globals, so this
# redirects every internal use while leaving the shared registry untouched.

_FAKE_SECRETS = {}


def _fake_set_secret(key, value):
    if not key or value is None:
        return False
    _FAKE_SECRETS[key] = value
    return True


def _fake_get_secret(key):
    val = _FAKE_SECRETS.get(key)
    return val if val else None


if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "services.auth_service", os.path.join(BACKEND, "services", "auth_service.py"))
auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth)

# Scoped to this module object only — nothing else in the process is affected.
auth.set_secret = _fake_set_secret
auth.get_secret = _fake_get_secret


# --- fixtures ----------------------------------------------------------------

# Deliberately messy: comments, blank lines, quoted values, a nested key that
# happens to share the name, and a trailing section. A text-level edit that is
# even slightly too greedy will corrupt one of these.
SAMPLE_CONFIG = """\
schema_version: 2
first_login: true

# Dashboard / API login — set up in the browser.
domain: 192.168.120.10

options:
  download_tools: false
  github_token: ghp_EXAMPLEONLYNOTAREALTOKEN
modules:
  elk:
    enabled: true
    id: elastic
    password: '123123'
  velociraptor:
    enabled: true
    # a nested key with the same name must NOT be touched
    first_login: whatever
    password: '123123'
versions:
  backend: 1.2.3
  nginx: 1.31.2-alpine
"""


class _Session(dict):
    """Stand-in for Flask's session object.

    It is a dict, but start_session() also sets `.permanent` on it (which is what
    makes Flask apply PERMANENT_SESSION_LIFETIME to the cookie), so a bare dict
    isn't a faithful double.
    """
    permanent = False
    modified = False


class _Tmp:
    """Temp config.yaml + clean secret store for one test."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="auth-test-")
        self.path = os.path.join(self.dir, "config.yaml")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE_CONFIG)
        os.environ["INTACT_CONFIG_PATH"] = self.path
        _FAKE_SECRETS.clear()
        auth._generation_cache = None
        return self

    def __exit__(self, *exc):
        os.environ.pop("INTACT_CONFIG_PATH", None)
        shutil.rmtree(self.dir, ignore_errors=True)

    def text(self):
        with open(self.path, "r", encoding="utf-8") as fh:
            return fh.read()

    def inode(self):
        return os.stat(self.path).st_ino


# --- 1. the inode trap -------------------------------------------------------


def test_write_first_login_truncates_in_place_same_inode():
    """The whole reason this is a text edit and not a rename: a new inode would
    strand the read-only bind mount on the old content."""
    with _Tmp() as tmp:
        before = tmp.inode()
        assert auth.write_first_login(False) is True
        assert tmp.inode() == before, (
            "config.yaml was replaced with a new inode. Docker bind-mounts this "
            "file by inode, so /app/config.yaml would keep serving the OLD "
            "first_login value and the setup page would never close.")


def test_write_first_login_actually_changes_the_value():
    with _Tmp() as tmp:
        assert auth.read_first_login() == auth.FIRST_LOGIN_TRUE
        auth.write_first_login(False)
        assert auth.read_first_login() == auth.FIRST_LOGIN_FALSE
        auth.write_first_login(True)
        assert auth.read_first_login() == auth.FIRST_LOGIN_TRUE


# --- 2. everything else in the file survives ---------------------------------


def test_write_first_login_changes_nothing_else():
    with _Tmp() as tmp:
        original = tmp.text()
        auth.write_first_login(False)
        updated = tmp.text()

        def without_flag(text):
            return "".join(ln for ln in text.splitlines(keepends=True)
                           if not ln.startswith("first_login:"))

        assert without_flag(original) == without_flag(updated), (
            "the edit changed content outside the top-level first_login line")


def test_a_nested_key_of_the_same_name_is_not_touched():
    """`first_login: whatever` under modules.velociraptor is a different setting
    (and in the fixture, not even a boolean). Only the top-level key is ours."""
    with _Tmp() as tmp:
        auth.write_first_login(False)
        assert "    first_login: whatever" in tmp.text(), \
            "the nested first_login key was rewritten"


def test_operator_secrets_and_version_pins_survive():
    with _Tmp() as tmp:
        auth.write_first_login(False)
        text = tmp.text()
        for needle in ("domain: 192.168.120.10", "id: elastic",
                       "password: '123123'", "backend: 1.2.3",
                       "ghp_EXAMPLEONLYNOTAREALTOKEN"):
            assert needle in text, f"{needle!r} was lost from config.yaml"


def test_the_key_is_added_when_absent():
    """A box upgraded from a pre-auth release has no such key at all — the
    migration needs to be able to write one in."""
    with _Tmp() as tmp:
        stripped = "".join(ln for ln in SAMPLE_CONFIG.splitlines(keepends=True)
                           if not ln.startswith("first_login:"))
        with open(tmp.path, "w", encoding="utf-8") as fh:
            fh.write(stripped)
        assert auth.read_first_login() == auth.FIRST_LOGIN_ABSENT
        assert auth.write_first_login(True) is True
        assert auth.read_first_login() == auth.FIRST_LOGIN_TRUE


# --- 3. fail closed ---------------------------------------------------------


def test_absent_key_is_reported_as_absent_not_as_setup_mode():
    """ABSENT identifies a pre-auth box, which the upgrade migrates by carrying
    the OLD Basic Auth password over. If this were reported as setup mode, that
    upgrade would instead publish an unauthenticated setup page and the first
    visitor would own the account."""
    with _Tmp() as tmp:
        with open(tmp.path, "w", encoding="utf-8") as fh:
            fh.write("schema_version: 2\ndomain: x\n")
        assert auth.read_first_login() == auth.FIRST_LOGIN_ABSENT
        assert auth.auth_mode() == auth.MODE_LOGIN, \
            "an absent flag must not open the setup page"


def test_malformed_config_fails_closed():
    with _Tmp() as tmp:
        with open(tmp.path, "w", encoding="utf-8") as fh:
            fh.write("this: is: not: valid: yaml: [[[\n")
        assert auth.read_first_login() == auth.FIRST_LOGIN_ERROR
        assert auth.auth_mode() == auth.MODE_ERROR, \
            "an unreadable config.yaml must not be treated as 'no auth needed'"


def test_missing_config_fails_closed():
    with _Tmp() as tmp:
        os.remove(tmp.path)
        assert auth.read_first_login() == auth.FIRST_LOGIN_ERROR
        assert auth.auth_mode() == auth.MODE_ERROR


def test_verify_password_refuses_when_no_credential_is_stored():
    """Reachable after a DB export/import: secret_store is excluded from
    export_db(), so the flag can say "set up" while no hash exists."""
    with _Tmp():
        assert auth.has_credential() is False
        assert auth.verify_password("admin", "") is False
        assert auth.verify_password("admin", "anything") is False
        assert auth.verify_password("", "") is False


def test_credentials_round_trip_and_reject_wrong_input():
    with _Tmp():
        auth.set_credential("admin", "correct horse battery")
        assert auth.verify_password("admin", "correct horse battery") is True
        assert auth.verify_password("admin", "wrong") is False
        assert auth.verify_password("someone-else", "correct horse battery") is False


def test_the_password_is_not_stored_in_recoverable_form():
    with _Tmp():
        auth.set_credential("admin", "correct horse battery")
        blob = " ".join(str(v) for v in _FAKE_SECRETS.values())
        assert "correct horse battery" not in blob, \
            "the plaintext password is retrievable from the store"


# --- 4. escalating, self-healing lockout ------------------------------------


def test_ten_failures_locks_and_the_first_lock_is_fifteen_minutes():
    with _Tmp():
        auth.set_credential("admin", "pw")
        for _ in range(auth.LOCKOUT_THRESHOLD - 1):
            assert auth.register_failure() == 0, "locked too early"
        locked_for = auth.register_failure()
        assert locked_for == 15 * 60, f"expected a 15-minute lock, got {locked_for}s"
        assert auth.lock_remaining_seconds() > 0


def test_the_lock_escalates_by_doubling_and_is_capped():
    assert auth.lock_duration_minutes(1) == 15
    assert auth.lock_duration_minutes(2) == 30
    assert auth.lock_duration_minutes(3) == 60
    assert auth.lock_duration_minutes(4) == 120
    # Capped, so it never becomes an effectively permanent lock.
    assert auth.lock_duration_minutes(20) == auth.LOCKOUT_CAP_MINUTES
    assert auth.lock_duration_minutes(99) == auth.LOCKOUT_CAP_MINUTES


def test_the_lock_is_timed_not_permanent():
    """A permanent lock would let any passer-by on the network force the real
    operator to go and edit config.yaml on the host."""
    with _Tmp():
        for _ in range(auth.LOCKOUT_THRESHOLD):
            auth.register_failure()
        assert auth.lock_remaining_seconds() > 0
        # Wind the stored deadline into the past — the lock must lift itself.
        _FAKE_SECRETS[auth._K_LOCK_UNTIL] = str(int(time.time()) - 1)
        assert auth.lock_remaining_seconds() == 0, \
            "the lockout did not expire on its own"


def test_a_successful_login_resets_the_counter():
    with _Tmp():
        for _ in range(auth.LOCKOUT_THRESHOLD - 1):
            auth.register_failure()
        auth.reset_lockout()
        assert auth.lock_remaining_seconds() == 0
        assert auth.failures_before_lock() == auth.LOCKOUT_THRESHOLD
        # And the next failure starts a fresh run rather than tripping instantly.
        assert auth.register_failure() == 0


# --- 5. the lockout must not hand over the account ---------------------------


def test_a_lockout_never_flips_first_login():
    """If it did, failing 10 times on purpose would open the unauthenticated
    setup page and let the attacker claim the appliance."""
    with _Tmp() as tmp:
        auth.write_first_login(False)
        for _ in range(auth.LOCKOUT_THRESHOLD * 3):
            auth.register_failure()
        assert auth.read_first_login() == auth.FIRST_LOGIN_FALSE, \
            "the lockout re-opened the setup page — this is account takeover"
        assert auth.auth_mode() == auth.MODE_LOGIN


def test_the_recovery_hint_is_always_available():
    """The operator asked for the reset path to be stated up front, not only once
    already locked out — a forgotten password has no in-app way out."""
    hint = auth.recovery_hint().lower()
    assert "first_login" in hint
    assert "config.yaml" in hint


# --- the request gate -------------------------------------------------------


def test_the_gate_blocks_a_peer_container_but_not_loopback():
    """F-010: peer containers on intact_network reach intact_backend:5001
    directly, bypassing nginx entirely. The loopback exemption exists for the
    healthcheck / installer / upgrade self-check / live tests, and must not
    extend one hop further."""
    with _Tmp():
        assert auth.gate_decision('/api/cases', 'GET', '127.0.0.1', {}) is None
        assert auth.gate_decision('/api/cases', 'GET', '::1', {}) is None
        for peer in ('172.18.0.7', '172.20.0.2', '192.168.120.11', '10.0.0.5'):
            assert auth.gate_decision('/api/cases', 'GET', peer, {}) is not None, \
                f"{peer} was allowed through unauthenticated — F-010 is reopened"


def test_only_the_intended_paths_are_exempt():
    with _Tmp():
        for path in sorted(auth.EXEMPT_PATHS):
            assert auth.gate_decision(path, 'GET', '172.18.0.7', {}) is None, \
                f"{path} should be reachable unauthenticated"
        for path in ('/api/cases', '/api/maintenance/purge', '/api/config',
                     '/api/upgrade/start', '/api/auth/change-password'):
            assert auth.gate_decision(path, 'GET', '172.18.0.7', {}) is not None, \
                f"{path} must NOT be reachable unauthenticated"


def test_the_exempt_list_has_not_quietly_grown():
    """A new entry here widens the unauthenticated attack surface, so changing
    this set should be a deliberate, reviewed act."""
    assert auth.EXEMPT_PATHS == frozenset({
        '/api/auth/status', '/api/auth/login', '/api/auth/setup',
        '/api/auth/logout', '/api/auth/verify', '/api/health',
        '/api/uploads/hook',
    }), "the unauthenticated allowlist changed — is that intended?"


def test_purge_is_not_reachable_without_a_session():
    """Named explicitly because it is the single most destructive endpoint, and
    the nginx.conf comment called it out as the reason auth existed at all."""
    with _Tmp():
        assert auth.gate_decision(
            '/api/maintenance/purge', 'POST', '172.18.0.9', {}) is not None


def test_a_preflight_is_not_gated():
    with _Tmp():
        assert auth.gate_decision('/api/cases', 'OPTIONS', '172.18.0.7', {}) is None


def test_non_api_paths_are_not_gated():
    with _Tmp():
        assert auth.gate_decision('/login.html', 'GET', '172.18.0.7', {}) is None


# --- session reasons: the point of tracking expiry server-side ---------------


def test_a_valid_session_passes():
    with _Tmp():
        auth.set_credential("admin", "pw")
        auth.bump_generation_cache()
        sess = _Session()
        auth.start_session(sess, "admin")
        assert auth.evaluate_session(sess) == auth.SESSION_OK
        assert auth.gate_decision('/api/cases', 'GET', '172.18.0.7', sess) is None


def test_no_session_reports_none_not_expired():
    with _Tmp():
        assert auth.evaluate_session({}) == auth.SESSION_NONE


def test_an_idle_session_reports_expired():
    """A plain 7-day cookie could not do this: once max-age elapses the browser
    stops sending it and the server cannot tell "expired" from "never logged
    in". The cookie deliberately outlives the session so this reason exists."""
    with _Tmp():
        auth.set_credential("admin", "pw")
        auth.bump_generation_cache()
        sess = _Session()
        auth.start_session(sess, "admin")
        sess["seen"] = time.time() - (auth.SESSION_IDLE_LIMIT_SECONDS + 60)
        assert auth.evaluate_session(sess) == auth.SESSION_EXPIRED
        assert auth.gate_decision('/api/cases', 'GET', '172.18.0.7', sess) \
            == auth.SESSION_EXPIRED


def test_the_cookie_outlives_the_session_window():
    """If the cookie died with the session there would be nothing to inspect and
    no way to report a reason."""
    assert auth.SESSION_MAX_AGE_DAYS * 24 * 60 * 60 > auth.SESSION_IDLE_LIMIT_SECONDS


def test_changing_the_password_invalidates_existing_sessions_with_a_reason():
    with _Tmp():
        auth.set_credential("admin", "pw")
        auth.bump_generation_cache()
        sess = _Session()
        auth.start_session(sess, "admin")
        assert auth.evaluate_session(sess) == auth.SESSION_OK

        auth.set_credential("admin", "a different password")
        auth.bump_generation_cache()
        assert auth.evaluate_session(sess) == auth.SESSION_CREDENTIALS_CHANGED


def test_the_sliding_window_only_restamps_periodically():
    """Re-signing the cookie on every request would mean one extra write per tus
    PATCH — roughly 2000 of them for a 10 GB upload."""
    with _Tmp():
        auth.set_credential("admin", "pw")
        auth.bump_generation_cache()
        sess = _Session()
        auth.start_session(sess, "admin")
        assert auth.touch_session(sess) is False, "re-stamped immediately"
        sess["seen"] = time.time() - (auth.SESSION_TOUCH_INTERVAL_SECONDS + 10)
        assert auth.touch_session(sess) is True, "never slid the window"
        assert auth.evaluate_session(sess) == auth.SESSION_OK


# --- audit log --------------------------------------------------------------


def test_the_audit_log_records_events_and_never_raises():
    with _Tmp() as tmp:
        auth.AUTH_DIR = os.path.join(tmp.dir, "auth")
        auth.AUDIT_LOG = os.path.join(auth.AUTH_DIR, "audit.jsonl")
        auth.audit("setup", username_value="admin")
        auth.audit("login_failed", username_value="admin", reason="bad_password")
        with open(auth.AUDIT_LOG, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        assert len(lines) == 2
        import json
        first = json.loads(lines[0])
        assert first["event"] == "setup"
        assert first["user"] == "admin"
        assert "ts" in first


def test_an_unwritable_audit_log_does_not_break_login():
    with _Tmp() as tmp:
        auth.AUTH_DIR = "/proc/definitely/not/writable"
        auth.AUDIT_LOG = os.path.join(auth.AUTH_DIR, "audit.jsonl")
        auth.audit("login_ok", username_value="admin")   # must not raise


def test_the_audit_log_never_records_a_password():
    with _Tmp() as tmp:
        auth.AUTH_DIR = os.path.join(tmp.dir, "auth2")
        auth.AUDIT_LOG = os.path.join(auth.AUTH_DIR, "audit.jsonl")
        auth.audit("login_failed", username_value="admin")
        with open(auth.AUDIT_LOG, "r", encoding="utf-8") as fh:
            body = fh.read()
        assert "password" not in body.lower() or "bad_password" in body, \
            "the audit log appears to contain password material"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
