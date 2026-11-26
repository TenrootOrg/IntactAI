"""Per-user API tokens (services/api_tokens.py, routes/api_token_routes.py, and
the token branch of services/auth_service.gate_decision).

The point most worth pinning: a token request has no session, and inside a
route "no session" used to mean "the loopback box" (users.caller_has -> True).
A token request must instead carry its own capped identity everywhere a route
asks who is calling.

flask is a container dependency, so the routes run against a minimal stand-in
(same pattern as test_dashboard_login_auth.py); the services run for real
against a throwaway SQLite DB.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-tokentest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_AUTH_DIR"] = os.path.join(_BASE, "auth")
os.environ["INTACT_CONFIG_PATH"] = os.path.join(_BASE, "config.yaml")
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402

try:
    import werkzeug.security  # noqa: F401
except ImportError:
    sec = types.ModuleType("werkzeug.security")
    sec.generate_password_hash = lambda pw: "sha256$" + hashlib.sha256(pw.encode()).hexdigest()
    sec.check_password_hash = lambda h, pw: h == sec.generate_password_hash(pw)
    wz = types.ModuleType("werkzeug")
    wz.security = sec
    sys.modules["werkzeug"] = wz
    sys.modules["werkzeug.security"] = sec


class _Session(dict):
    permanent = False


REQUEST = types.SimpleNamespace(headers={}, remote_addr="172.18.0.9", body=None, args={})
REQUEST.get_json = lambda silent=False: REQUEST.body
SESSION = _Session()
G = types.SimpleNamespace()


class _Blueprint:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda fn: fn


_flask = types.ModuleType("flask")
_flask.Blueprint = _Blueprint
_flask.send_file = lambda *a, **k: None
_flask.Response = object
_flask.after_this_request = lambda fn: fn
_flask.jsonify = lambda body=None, **k: body if body is not None else k
_flask.request = REQUEST
_flask.session = SESSION
_flask.g = G
_flask.has_app_context = lambda: True
sys.modules["flask"] = _flask

from services import access_policy  # noqa: E402
from services import api_tokens  # noqa: E402
from services import auth_service as auth  # noqa: E402
from services import users  # noqa: E402
from services.storage.base import get_connection  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "api_token_routes_under_test", os.path.join(ROOT, "modules/backend/routes/api_token_routes.py"))
routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(routes)

# The entries the access policy gets for the new routes (added by hand there).
POLICY_ENTRIES = {
    "api_tokens.list_tokens": users.READONLY,
    "api_tokens.create_token": access_policy.step_up(users.READONLY),
    "api_tokens.revoke_token": users.READONLY,
}
access_policy.POLICY.update({k: v for k, v in POLICY_ENTRIES.items()
                             if k not in access_policy.POLICY})

PEER = "172.18.0.5"
# (path, endpoint) pairs used below; roles come from the real POLICY.
READ_EP = ("/api/cases", "case.list_cases")             # READONLY
OPERATOR_EP = ("/api/cases", "case.create_case")        # OPERATOR
ADMIN_EP = ("/api/security/default-passwords", "security.get_default_passwords")  # ADMIN
SUPER_EP = ("/api/db/import", "db.import_database")     # SUPERADMIN


def make_user(name, role, mfa=None):
    users.create(name, "x", role, "test", False)
    row = users.by_name(name)
    if mfa if mfa is not None else role in users.MFA_REQUIRED_ROLES:
        conn = get_connection()
        conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        users.invalidate()
    return users.by_name(name)


def new_token(row, scope="write", days=30, name="t"):
    raw, _ = api_tokens.create(users.get(row["id"]), name, scope, days, row["username"])
    return raw


def gate(raw, ep=READ_EP, method="GET", session=None, headers=None, peer=PEER):
    """One request through the gate with a fresh request-local g."""
    G.__dict__.clear()
    h = {"Authorization": "Bearer " + raw} if raw else {}
    h.update(headers or {})
    return auth.gate_decision(ep[0], method, peer, session if session is not None else {},
                              endpoint=ep[1], headers=h)


def as_session(row):
    """Run the next route call as `row`'s browser session (no token)."""
    G.__dict__.clear()
    SESSION.clear()
    auth.start_session(SESSION, users.get(row["id"]))


def call(fn, *args, body=None, query=None):
    REQUEST.headers = {}
    REQUEST.remote_addr = PEER
    REQUEST.body = body
    REQUEST.args = query or {}
    out = fn(*args)
    return out if isinstance(out, tuple) else (out, 200)


def audit_lines():
    try:
        with open(auth.AUDIT_LOG) as fh:
            return [json.loads(x) for x in fh]
    except OSError:
        return []


_n = [0]


def uname(prefix):
    _n[0] += 1
    return f"{prefix}{_n[0]}"


class TokenStorage(unittest.TestCase):
    def test_create_shows_once_and_stores_only_a_hash(self):
        op = make_user(uname("op"), users.OPERATOR)
        as_session(op)
        body, code = call(routes.create_token, body={"name": "ci", "scope": "read", "days": 7})
        self.assertEqual(code, 200)
        raw = body["token"]
        self.assertRegex(raw, r"^intact_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$")
        self.assertTrue(raw.startswith("intact_" + body["prefix"] + "_"))
        self.assertAlmostEqual(body["expires_at"], time.time() + 7 * 86400, delta=5)
        stored = [tuple(r) for r in get_connection().execute(
            "SELECT * FROM api_tokens WHERE prefix = ?", (body["prefix"],)).fetchall()]
        self.assertEqual(len(stored), 1)
        self.assertNotIn(raw, stored[0])
        self.assertIn(hashlib.sha256(raw.encode()).hexdigest(), stored[0])
        listed, _ = call(routes.list_tokens)
        dumped = json.dumps(listed)
        self.assertNotIn(raw, dumped)
        self.assertNotIn("token_hash", dumped)
        self.assertEqual(listed["tokens"][0]["status"], "active")

    def test_fields_are_validated(self):
        for name, scope, days in (("", "read", 30), ("x" * 65, "read", 30), ("a", "admin", 30),
                                  ("a", "read", 0), ("a", "read", 366), ("a", "read", "30"),
                                  ("a", "read", True), ("a", "read", None)):
            self.assertIsNotNone(api_tokens.problem(name, scope, days), (name, scope, days))
        self.assertIsNone(api_tokens.problem("a", "write", 365))
        self.assertIsNone(api_tokens.problem("a", "read", 1))

    def test_create_refused_until_two_step_login_is_set_up(self):
        adm = make_user(uname("adm"), users.ADMIN, mfa=False)
        as_session(adm)
        body, code = call(routes.create_token, body={"name": "x", "scope": "read", "days": 7})
        self.assertEqual(code, 403)
        self.assertEqual(api_tokens.list_for(adm["id"]), [])

    def test_create_is_step_up_and_token_routes_are_policy_complete(self):
        self.assertTrue(access_policy.rule_for("api_tokens.create_token", "POST").step_up)
        for ep in POLICY_ENTRIES:
            self.assertIn(ep, access_policy.POLICY)

    def test_redacted_backup_drops_tokens(self):
        try:
            spec = importlib.util.spec_from_file_location(
                "db_routes_under_test", os.path.join(ROOT, "modules/backend/routes/db_routes.py"))
            dbr = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(dbr)
        except ImportError as exc:
            self.skipTest(f"db_routes needs a container dependency: {exc}")
        op = make_user(uname("op"), users.OPERATOR)
        new_token(op)
        from services.storage.base import DB_PATH
        conn = get_connection()
        conn.execute("CREATE TABLE IF NOT EXISTS secrets (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS frontend_config (key TEXT PRIMARY KEY, value TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(FULL)")     # the copy is of the file alone
        copy = dbr._make_redacted_backup_copy(DB_PATH)
        try:
            n = sqlite3.connect(copy).execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0]
        finally:
            os.unlink(copy)
        self.assertEqual(n, 0)


class TokenGate(unittest.TestCase):
    def test_read_token_only_passes_readonly_gets(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op, scope="read")
        self.assertIsNone(gate(raw, READ_EP))
        self.assertEqual(gate(raw, OPERATOR_EP, "POST"), auth.FORBIDDEN)
        # A READONLY rule but a write method: still refused for a read token.
        self.assertEqual(gate(raw, READ_EP, "POST"), auth.FORBIDDEN)

    def test_write_token_never_above_the_users_role(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op, scope="write")
        self.assertIsNone(gate(raw, OPERATOR_EP, "POST"))
        self.assertEqual(gate(raw, ADMIN_EP, "POST"), auth.FORBIDDEN)
        ro = make_user(uname("ro"), users.READONLY)
        self.assertEqual(gate(new_token(ro, scope="write"), OPERATOR_EP, "POST"), auth.FORBIDDEN)

    def test_superadmin_routes_stay_browser_only(self):
        # A leaked script token of the Super-admin must not be root on the box.
        sa = make_user(uname("sa"), users.SUPERADMIN)
        raw = new_token(sa, scope="write")
        self.assertEqual(gate(raw, SUPER_EP, "POST"), auth.TOKEN_REFUSED)
        self.assertIsNone(gate(raw, ADMIN_EP))

    def test_dead_token_is_audited_with_its_prefix(self):
        gate("intact_0badc0de_" + "x" * 43)
        last = audit_lines()[-1]
        self.assertEqual((last["event"], last["reason"], last["token"]),
                         ("token_denied", auth.TOKEN_INVALID, "0badc0de"))

    def test_identity_flows_to_caller_helpers_not_loopback(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op, scope="write")
        self.assertIsNone(gate(raw, OPERATOR_EP, "POST"))
        empty = {}
        # Without the identity, an empty session is the loopback box: True.
        self.assertFalse(users.caller_has(empty, users.ADMIN))
        self.assertFalse(users.caller_has(empty, users.SUPERADMIN))
        self.assertTrue(users.caller_has(empty, users.OPERATOR))
        self.assertEqual(users.caller_name(empty), op["username"])
        me = auth.session_user(empty)
        self.assertEqual((me["username"], me["role"]), (op["username"], users.OPERATOR))
        # A read token is Read-only everywhere a route asks.
        adm = make_user(uname("adm"), users.ADMIN)
        self.assertIsNone(gate(new_token(adm, scope="read"), READ_EP))
        self.assertFalse(users.caller_has(empty, users.OPERATOR))
        self.assertEqual(auth.session_user(empty)["role"], users.READONLY)

    def test_no_identity_keeps_the_loopback_meaning(self):
        G.__dict__.clear()
        self.assertTrue(users.caller_has({}, users.SUPERADMIN))
        self.assertEqual(users.caller_name({}), "system")

    def test_token_from_loopback_is_still_the_token(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op, scope="read")
        self.assertEqual(gate(raw, OPERATOR_EP, "POST", peer="127.0.0.1"), auth.FORBIDDEN)
        self.assertEqual(gate("intact_bogus_x", READ_EP, peer="127.0.0.1"), auth.TOKEN_INVALID)
        self.assertIsNone(gate(raw, READ_EP, peer="127.0.0.1"))
        self.assertFalse(users.caller_has({}, users.OPERATOR))

    def test_refused_on_auth_users_token_routes_verify_and_step_up(self):
        sa = make_user(uname("sa"), users.SUPERADMIN)
        raw = new_token(sa, scope="write")
        for ep, method in ((("/api/users", "users.create_user"), "POST"),
                           (("/api/users", "users.list_users"), "GET"),
                           (("/api/auth/mfa/setup", "auth.auth_mfa_setup"), "POST"),
                           (("/api/auth/mfa/disable", "auth.auth_mfa_disable"), "POST"),
                           (("/api/auth/change-password", "auth.auth_change_password"), "POST"),
                           (("/api/auth/reauth", "auth.auth_reauth"), "POST"),
                           (("/api/tokens", "api_tokens.create_token"), "POST"),
                           (("/api/tokens", "api_tokens.list_tokens"), "GET"),
                           (("/api/tokens/1", "api_tokens.revoke_token"), "DELETE"),
                           (("/api/auth/verify", "auth.auth_verify"), "GET"),
                           (("/api/auth/login", "auth.auth_login"), "POST"),
                           (("/api/auth/logout", "auth.auth_logout"), "POST"),
                           (("/api/auth/status", "auth.auth_status"), "GET")):
            self.assertEqual(gate(raw, ep, method), auth.TOKEN_REFUSED, ep)
        self.assertIsNone(gate(raw, ("/api/health", "system.health"), "GET"))

    def test_any_step_up_rule_refuses_a_token(self):
        sa = make_user(uname("sa"), users.SUPERADMIN)
        raw = new_token(sa)
        access_policy.POLICY["case.list_cases_stepup_probe"] = access_policy.step_up(users.READONLY)
        try:
            self.assertEqual(gate(raw, ("/api/x", "case.list_cases_stepup_probe")), auth.TOKEN_REFUSED)
        finally:
            del access_policy.POLICY["case.list_cases_stepup_probe"]

    def test_expired(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        conn = get_connection()
        conn.execute("UPDATE api_tokens SET expires_at = ? WHERE token_hash = ?",
                     (time.time() - 1, hashlib.sha256(raw.encode()).hexdigest()))
        conn.commit()
        self.assertEqual(gate(raw), auth.TOKEN_EXPIRED)

    def test_generation_change_kills_tokens(self):
        for change in (lambda r: users.set_role(r["id"], users.READONLY),
                       lambda r: users.set_password(r["id"], "y"),
                       lambda r: users.clear_mfa(r["id"])):
            op = make_user(uname("op"), users.OPERATOR)
            raw = new_token(op)
            self.assertIsNone(gate(raw))
            change(op)
            self.assertEqual(gate(raw), auth.SESSION_CREDENTIALS_CHANGED)
            self.assertEqual(api_tokens.list_for(op["id"])[0]["status"], "stopped")

    def test_disabled_user(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        users.set_enabled(op["id"], False)
        self.assertEqual(gate(raw), auth.SESSION_DISABLED)
        users.set_enabled(op["id"], True)        # a new generation: still dead
        self.assertEqual(gate(raw), auth.SESSION_CREDENTIALS_CHANGED)

    def test_unknown_and_malformed(self):
        self.assertEqual(gate("intact_00000000_nope"), auth.TOKEN_INVALID)
        self.assertEqual(gate("intact_" + "a" * 300), auth.TOKEN_INVALID)
        # Not ours (no intact_ prefix): ignored, so the request is just unauthenticated.
        self.assertEqual(gate(None, headers={"Authorization": "Bearer abc"}), auth.SESSION_NONE)

    def test_cookie_and_bearer_refused(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        s = _Session()
        auth.start_session(s, users.get(op["id"]))
        self.assertEqual(gate(raw, session=s), auth.TOKEN_CONFLICT)
        # A cookie the server could not read (bad signature: empty session) counts too.
        self.assertEqual(gate(raw, headers={"Cookie": "a=1; intact_session=zzz"}), auth.TOKEN_CONFLICT)
        self.assertIsNone(gate(raw, headers={"Cookie": "intact_case=c1"}))

    def test_no_csrf_check_for_a_bearer_request(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        self.assertIsNone(gate(raw, OPERATOR_EP, "POST", headers={"Sec-Fetch-Site": "cross-site"}))

    def test_identity_not_stored_means_refused(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        real = users.set_request_identity
        users.set_request_identity = lambda ident: False
        try:
            self.assertEqual(gate(raw, OPERATOR_EP, "POST"), auth.TOKEN_REFUSED)
        finally:
            users.set_request_identity = real

    def test_audit_and_last_used(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        prefix = raw.split("_")[1]
        self.assertIsNone(gate(raw, READ_EP))
        self.assertIsNone(gate(raw, OPERATOR_EP, "POST"))
        self.assertEqual(gate(raw, ADMIN_EP, "POST"), auth.FORBIDDEN)
        mine = [e for e in audit_lines() if e.get("token") == prefix]
        self.assertEqual([e["event"] for e in mine], ["token_first_use", "token_action", "token_denied"])
        self.assertTrue(all(e["user"] == op["username"] for e in mine))
        self.assertIsNotNone(api_tokens.list_for(op["id"])[0]["last_used_at"])


class TokenManagement(unittest.TestCase):
    def test_revoke_own(self):
        op = make_user(uname("op"), users.OPERATOR)
        raw = new_token(op)
        tid = api_tokens.list_for(op["id"])[0]["id"]
        as_session(op)
        _, code = call(routes.revoke_token, tid)
        self.assertEqual(code, 200)
        self.assertEqual(gate(raw), auth.TOKEN_INVALID)
        events = [e["event"] for e in audit_lines() if e.get("token") == raw.split("_")[1]]
        self.assertIn("token_revoked", events)

    def test_rank_rule_for_listing_and_revoking_others(self):
        sa = make_user(uname("sa"), users.SUPERADMIN)
        adm = make_user(uname("adm"), users.ADMIN)
        adm2 = make_user(uname("adm"), users.ADMIN)
        op = make_user(uname("op"), users.OPERATOR)
        new_token(op)
        new_token(adm2)
        op_tid = api_tokens.list_for(op["id"])[0]["id"]
        adm2_tid = api_tokens.list_for(adm2["id"])[0]["id"]

        as_session(adm)
        body, code = call(routes.list_tokens, query={"user": op["username"]})
        self.assertEqual((code, len(body["tokens"])), (200, 1))
        self.assertEqual(call(routes.list_tokens, query={"user": adm2["username"]})[1], 403)
        self.assertEqual(call(routes.revoke_token, adm2_tid)[1], 404)

        as_session(op)
        self.assertEqual(call(routes.list_tokens, query={"user": adm["username"]})[1], 403)
        self.assertEqual(call(routes.revoke_token, adm2_tid)[1], 404)

        as_session(adm)
        self.assertEqual(call(routes.revoke_token, op_tid)[1], 200)
        as_session(sa)
        self.assertEqual(call(routes.list_tokens, query={"user": adm2["username"]})[1], 200)
        self.assertEqual(call(routes.revoke_token, adm2_tid)[1], 200)
        self.assertEqual(api_tokens.list_for(adm2["id"]), [])

    def test_loopback_without_session_cannot_manage_tokens(self):
        G.__dict__.clear()
        SESSION.clear()
        self.assertEqual(call(routes.list_tokens)[1], 401)
        self.assertEqual(call(routes.create_token, body={"name": "a", "scope": "read", "days": 1})[1], 401)


if __name__ == "__main__":
    unittest.main()
