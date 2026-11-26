"""Dashboard login: one-time setup token, per-client lockout, password rule,
must-change gate for a publicly known password, global brake; and the users
and roles on top (services/users.py, services/access_policy.py,
routes/user_routes.py): rank rule, one-time passwords, disable/demote ending
sessions, per-route and per-tool roles, step-up, CSRF, audit hash chain.

QA found that while config.yaml had first_login: true, /api/auth/setup accepted
the FIRST visitor from the network, and the lockout was one global counter: an
attacker locked the operator out with 10 requests and then claimed the box
during the recovery. These pin the fixes in services/auth_service.py and
routes/auth_routes.py.

flask (and werkzeug's markupsafe) are container dependencies, so the routes
run against a minimal stand-in for the flask names auth_routes uses; the
service runs for real against a throwaway SQLite DB, config.yaml and token.
"""
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-authtest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_AUTH_DIR"] = os.path.join(_BASE, "auth")
CFG = os.path.join(_BASE, "config.yaml")
TOKEN = os.path.join(_BASE, "state", "backend", "setup_token")
os.environ["INTACT_CONFIG_PATH"] = CFG
os.environ["INTACT_SETUP_TOKEN_PATH"] = TOKEN
os.environ["INTACT_CLOUD_KEY_PATH"] = os.path.join(_BASE, "state", "backend", "cloud_secrets.key")
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402

try:
    import werkzeug.security  # noqa: F401
except ImportError:
    # Stand-in with the same contract; the hash scheme is not under test.
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

_flask = types.ModuleType("flask")


class _Blueprint:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda fn: fn


_flask.Blueprint = _Blueprint
_flask.send_file = lambda *a, **k: None
_flask.Response = object
_flask.after_this_request = lambda fn: fn
_flask.jsonify = lambda body=None, **k: body if body is not None else k
_flask.request = REQUEST
_flask.session = SESSION
sys.modules["flask"] = _flask

from services import auth_service as auth  # noqa: E402
from services import users  # noqa: E402
_REAL_RESOLVE = auth._resolve_nginx

_spec = importlib.util.spec_from_file_location(
    "auth_routes_under_test", os.path.join(ROOT, "modules/backend/routes/auth_routes.py"))
routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(routes)

GOOD = "Str0ng-Pass.word9"
OLD_RULE = "Abcdefghijk1!"   # met the old 12-character rule; too short for a NEW password


NGINX = "172.18.0.9"       # REQUEST.remote_addr by default: the stub resolver says nginx


def call(fn, body=None, ip="10.0.0.1", peer=NGINX):
    """Run one route as a request from `ip` (nginx's X-Real-IP) arriving from `peer`."""
    REQUEST.headers = {"X-Real-IP": ip} if ip else {}
    REQUEST.remote_addr = peer
    REQUEST.body = body
    out = fn()
    return out if isinstance(out, tuple) else (out, 200)


def write_token(value="tok-" + "A" * 40):
    os.makedirs(os.path.dirname(TOKEN), exist_ok=True)
    with open(TOKEN, "w") as fh:
        fh.write(value + "\n")
    return value


def setup_body(token, password=GOOD, user="admin"):
    return {"setup_token": token, "username": user, "password": password, "confirm": password}


class Base(unittest.TestCase):
    def setUp(self):
        with open(CFG, "w") as fh:
            fh.write("schema_version: 3\n# keep me\nfirst_login: true\ndomain: 10.0.0.5\n")
        if os.path.exists(TOKEN):
            os.unlink(TOKEN)
        auth.set_secret(auth._K_HASH, "")      # no credential from an earlier test
        auth.set_secret(auth._K_USER, "")
        users.ensure_table()
        users.get_connection().execute("DELETE FROM users")
        users.get_connection().commit()
        users.invalidate()
        auth.reset_lockout()
        auth.MIN_SECONDS_BETWEEN_ATTEMPTS = 0.0
        auth._resolve_nginx = lambda: frozenset({NGINX})
        auth._nginx.update(addrs=frozenset(), at=None)
        os.environ.pop("INTACT_ALLOW_WEAK_PASSWORDS", None)
        SESSION.clear()
        # These classes test other things; the MFA class below keeps the real rule.
        self._mfa_roles = users.MFA_REQUIRED_ROLES
        users.MFA_REQUIRED_ROLES = frozenset() if self.MFA_OFF else self._mfa_roles

    MFA_OFF = True

    def tearDown(self):
        users.MFA_REQUIRED_ROLES = self._mfa_roles

    def claim(self):
        tok = write_token()
        body, status = call(routes.auth_setup, setup_body(tok))
        self.assertEqual(status, 200, body)
        SESSION.clear()


class SetupToken(Base):
    def test_missing_and_wrong_token_refused_403(self):
        tok = write_token()
        for given in (None, "", "wrong", tok + "x"):
            body, status = call(routes.auth_setup, setup_body(given))
            self.assertEqual(status, 403, given)
            self.assertEqual(body["error"], "bad_setup_token")
            self.assertIn("reset-login.sh", body["message"])
        self.assertTrue(os.path.exists(TOKEN), "a wrong token must not spend the real one")
        self.assertEqual(auth.read_first_login(), auth.FIRST_LOGIN_TRUE)
        self.assertFalse(auth.has_credential())

    def test_no_token_file_refuses_and_names_the_script(self):
        body, status = call(routes.auth_setup, setup_body("anything"))
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "setup_token_missing")
        self.assertIn("sudo scripts/reset-login.sh", body["message"])

    def test_right_token_sets_up_spends_token_and_closes_setup(self):
        tok = write_token()
        ino = os.stat(CFG).st_ino
        body, status = call(routes.auth_setup, setup_body(" " + tok + " "))
        self.assertEqual(status, 200, body)
        self.assertFalse(os.path.exists(TOKEN), "token deleted after success")
        self.assertEqual(auth.read_first_login(), auth.FIRST_LOGIN_FALSE)
        self.assertEqual(os.stat(CFG).st_ino, ino)
        with open(CFG) as fh:
            self.assertIn("# keep me", fh.read())
        self.assertTrue(auth.verify_password("admin", GOOD))
        # Second setup: closed by the flag...
        body, status = call(routes.auth_setup, setup_body(tok))
        self.assertEqual((status, body["error"]), (403, "setup_closed"))
        # ...and still refused if someone hand-edits first_login back on.
        auth.write_first_login(True)
        body, status = call(routes.auth_setup, setup_body(tok))
        self.assertEqual((status, body["error"]), (403, "setup_token_missing"))

    def test_wrong_tokens_count_toward_the_client_lockout(self):
        write_token()
        for _ in range(auth.LOCKOUT_THRESHOLD):
            call(routes.auth_setup, setup_body("wrong"), ip="10.9.9.9")
        body, status = call(routes.auth_setup, setup_body("wrong"), ip="10.9.9.9")
        self.assertEqual((status, body["error"]), (429, "locked"))
        body, status = call(routes.auth_setup, setup_body("wrong"), ip="10.0.0.2")
        self.assertEqual(status, 403, "another address is not locked")

    def test_new_token_lifts_the_operators_own_lock(self):
        # The usual recovery: operator locked their own address, runs reset-login.
        write_token()
        for _ in range(auth.LOCKOUT_THRESHOLD):
            call(routes.auth_setup, setup_body("wrong"))
        self.assertGreater(auth.lock_remaining_seconds("10.0.0.1"), 0)
        tok = write_token("fresh-" + "B" * 40)
        os.utime(TOKEN, ns=(1, 1))     # a distinct stamp even on coarse-mtime filesystems
        body, status = call(routes.auth_setup, setup_body(tok))
        self.assertEqual(status, 200, body)


class PerClientLockout(Base):
    def test_locked_address_does_not_lock_another(self):
        self.claim()
        bad = {"username": "admin", "password": "nope"}
        for _ in range(auth.LOCKOUT_THRESHOLD - 1):
            _, status = call(routes.auth_login, bad, ip="10.6.6.6")
            self.assertEqual(status, 401)
        body, status = call(routes.auth_login, bad, ip="10.6.6.6")
        self.assertEqual((status, body["error"]), (429, "locked"))
        self.assertEqual(body["lock_remaining_seconds"], auth.LOCKOUT_BASE_MINUTES * 60)
        good = {"username": "admin", "password": GOOD}
        body, status = call(routes.auth_login, good, ip="10.6.6.6")
        self.assertEqual(status, 429, "locked address stays locked even with the right password")
        body, status = call(routes.auth_login, good, ip="10.0.0.7")
        self.assertEqual(status, 200, body)
        body, _ = call(routes.auth_status, ip="10.0.0.8")
        self.assertFalse(body["locked"])

    def test_x_real_ip_is_trusted_only_from_nginx(self):
        self.assertEqual(call(lambda: routes._client_ip(), ip="10.1.2.3")[0], "10.1.2.3")
        self.assertEqual(call(lambda: routes._client_ip(), ip=None)[0], NGINX)
        # A peer container or the host's 127.0.0.1:5001 is keyed by itself.
        for peer in ("172.18.0.50", "127.0.0.1"):
            self.assertEqual(call(lambda: routes._client_ip(), ip="10.1.2.3", peer=peer)[0], peer)

    def test_direct_caller_cannot_dodge_the_lockout_with_fresh_headers(self):
        self.claim()
        bad = {"username": "admin", "password": "nope"}
        for i in range(auth.LOCKOUT_THRESHOLD):
            call(routes.auth_login, bad, ip=f"10.50.0.{i}", peer="172.18.0.50")
        body, status = call(routes.auth_login, bad, ip="10.50.0.99", peer="172.18.0.50")
        self.assertEqual((status, body["error"]), (429, "locked"))
        body, status = call(routes.auth_login, bad, ip="10.50.0.99")
        self.assertEqual(status, 401, "the forged addresses were never locked")

    def test_nginx_address_is_re_resolved_after_a_miss(self):
        self.assertTrue(auth._is_nginx(NGINX))
        auth._resolve_nginx = lambda: frozenset({"172.18.0.77"})    # nginx recreated
        self.assertFalse(auth._is_nginx("172.18.0.77"), "a miss inside the retry window: no lookup")
        auth._nginx["at"] -= auth.NGINX_MISS_RETRY_SECONDS + 1
        self.assertTrue(auth._is_nginx("172.18.0.77"))
        self.assertFalse(auth._is_nginx(NGINX))
        auth._resolve_nginx = lambda: (_ for _ in ()).throw(AssertionError("looked up"))
        self.assertTrue(auth._is_nginx("172.18.0.77"), "a hit never resolves")

    def test_unresolvable_nginx_trusts_nobody(self):
        auth._resolve_nginx = _REAL_RESOLVE
        auth.NGINX_HOST, host = "nginx.invalid", auth.NGINX_HOST
        try:
            self.assertEqual(call(lambda: routes._client_ip(), ip="10.1.2.3")[0], NGINX)
        finally:
            auth.NGINX_HOST = host

    def test_global_brake_after_many_failures_from_many_addresses(self):
        for i in range(auth.GLOBAL_BRAKE_FAILURES):
            auth.register_failure(f"10.2.{i // 250}.{i % 250}")
        self.assertTrue(auth.throttle_ok("10.3.0.1"))
        self.assertTrue(auth.throttle_ok("10.3.0.2"), "not braked at exactly the limit")
        auth.register_failure("10.2.9.9")
        self.assertTrue(auth.throttle_ok("10.3.0.3"), "braked: one attempt per second still passes")
        self.assertFalse(auth.throttle_ok("10.3.0.4"))
        auth._last_braked_attempt -= auth.GLOBAL_BRAKE_INTERVAL
        self.assertTrue(auth.throttle_ok("10.3.0.4"))
        self.assertLessEqual(len(auth._recent_failures), auth.GLOBAL_BRAKE_FAILURES + 1)
        # Old failures fall out of the window.
        for k in range(len(auth._recent_failures)):
            auth._recent_failures[k] -= auth.GLOBAL_BRAKE_WINDOW + 1
        self.assertTrue(auth.throttle_ok("10.3.0.5"))
        self.assertTrue(auth.throttle_ok("10.3.0.6"))

    def test_throttle_is_per_client(self):
        auth.MIN_SECONDS_BETWEEN_ATTEMPTS = 60.0
        self.assertTrue(auth.throttle_ok("10.0.0.1"))
        self.assertFalse(auth.throttle_ok("10.0.0.1"))
        self.assertTrue(auth.throttle_ok("10.0.0.2"))

    def test_tracked_addresses_are_bounded(self):
        cap = auth.MAX_TRACKED_CLIENTS
        auth.MAX_TRACKED_CLIENTS = 50
        try:
            for i in range(500):
                auth.register_failure(f"10.1.{i // 250}.{i % 250}")
            self.assertLessEqual(len(auth._clients), 50)
        finally:
            auth.MAX_TRACKED_CLIENTS = cap

    def test_escalation_keeps_threshold_10(self):
        self.assertEqual(auth.LOCKOUT_THRESHOLD, 10)
        self.assertEqual([auth.lock_duration_minutes(s) for s in (1, 2, 3, 20)],
                         [15, 30, 60, 24 * 60])


class MustChange(Base):
    """A login with a publicly known password gets in, but its session can do
    nothing except change it."""
    API = "/api/cases"

    def gate(self, path):
        return auth.gate_decision(path, "GET", "172.18.0.9", SESSION)

    def default_box(self):
        auth.write_first_login(False)
        auth.set_credential("admin", "123123")
        body, status = call(routes.auth_login, {"username": "admin", "password": "123123"})
        self.assertEqual(status, 200, body)
        return body

    def test_default_password_session_only_changes_password(self):
        self.assertTrue(self.default_box()["must_change"])
        self.assertEqual(self.gate(self.API), auth.PASSWORD_CHANGE_REQUIRED)
        self.assertEqual(self.gate("/api/security/default-passwords"), auth.PASSWORD_CHANGE_REQUIRED)
        for path in ("/api/auth/change-password", "/api/auth/logout", "/api/auth/status"):
            self.assertIsNone(self.gate(path), path)
        REQUEST.args = {"tool": "uploads"}
        self.assertEqual(call(routes.auth_verify)[1], 401, "/velociraptor/ and uploads too")
        self.assertTrue(call(routes.auth_status)[0]["must_change"])

        new = "An0ther-Strong.Pass"
        body, status = call(routes.auth_change_password,
                            {"current_password": "123123", "new_password": new, "confirm": new})
        self.assertEqual(status, 200, body)
        self.assertIsNone(self.gate(self.API))
        self.assertEqual(call(routes.auth_verify)[1], 200)
        REQUEST.args = {}
        self.assertEqual(call(routes.auth_verify)[1], 403, "no ?tool= is refused, never defaulted")
        self.assertFalse(call(routes.auth_status)[0]["must_change"])
        # And a later login with the new password is not flagged.
        SESSION.clear()
        body, _ = call(routes.auth_login, {"username": "admin", "password": new})
        self.assertFalse(body["must_change"])
        self.assertIsNone(self.gate(self.API))

    def test_password_from_the_old_rule_is_not_flagged(self):
        # Decided 2026-11-25: the 15-character rule applies at the next change;
        # a password set under the old 12-character rule keeps signing in.
        auth.write_first_login(False)
        auth.set_credential("admin", OLD_RULE)
        body, _ = call(routes.auth_login, {"username": "admin", "password": OLD_RULE})
        self.assertFalse(body["must_change"])
        self.assertEqual(auth.password_problem(OLD_RULE), "it is shorter than 15 characters")

    def test_strong_password_session_is_not_gated(self):
        self.claim()
        body, _ = call(routes.auth_login, {"username": "admin", "password": GOOD})
        self.assertFalse(body["must_change"])
        self.assertIsNone(self.gate(self.API))

    def test_lab_switch_means_no_gate(self):
        with open(CFG, "a") as fh:
            fh.write("allow_weak_passwords: true\n")
        self.assertFalse(self.default_box()["must_change"])
        self.assertIsNone(self.gate(self.API))

    def test_lab_switch_lifts_an_existing_flag(self):
        self.default_box()
        self.assertEqual(self.gate(self.API), auth.PASSWORD_CHANGE_REQUIRED)
        os.environ["INTACT_ALLOW_WEAK_PASSWORDS"] = "1"
        self.assertIsNone(self.gate(self.API))

    def test_app_answers_403_password_change_required(self):
        with open(os.path.join(ROOT, "modules/backend/app.py")) as fh:
            src = fh.read()
        self.assertIn("if reason == auth_service.PASSWORD_CHANGE_REQUIRED:", src)
        self.assertIn("}), 403", src)


class PasswordRule(Base):
    def test_setup_refuses_weak_without_spending_the_token(self):
        tok = write_token()
        for weak in ("123123", "Short1Aa", "fourteen chars", "aaaaaaaaaaaaaaaaaaaa",
                     "password-but-long", "my-admin-passphrase"):
            body, status = call(routes.auth_setup, setup_body(tok, weak))
            self.assertEqual((status, body["error"]), (400, "weak_password"), weak)
            self.assertNotIn(weak, body["message"])
        self.assertTrue(os.path.exists(TOKEN))
        self.assertEqual(auth.read_first_login(), auth.FIRST_LOGIN_TRUE)

    def test_lab_switch_lets_123123_set_up_the_dashboard(self):
        # A dev box with allow_weak_passwords: true keeps 123123; the token is
        # still required (the switch weakens the password rule, not the claim).
        with open(CFG, "a") as fh:
            fh.write("allow_weak_passwords: true\n")
        self.assertTrue(auth.weak_passwords_allowed())
        body, status = call(routes.auth_setup, setup_body("wrong-token", "123123"))
        self.assertEqual(status, 403, body)
        tok = write_token()
        body, status = call(routes.auth_setup, setup_body(tok, "123123"))
        self.assertEqual(status, 200, body)

    def test_lab_switch_off_by_default_and_on_junk(self):
        self.assertFalse(auth.weak_passwords_allowed())
        with open(CFG, "a") as fh:
            fh.write("allow_weak_passwords: maybe\n")
        self.assertFalse(auth.weak_passwords_allowed())
        # YAML reads yes/on as True; the shell's secret_weak_allowed does not,
        # so neither may the backend.
        for word in ("yes", "on", "On"):
            with open(CFG, "w") as fh:
                fh.write("first_login: true\nallow_weak_passwords: %s\n" % word)
            self.assertFalse(auth.weak_passwords_allowed(), word)
        with open(CFG, "w") as fh:
            fh.write("first_login: true\nallow_weak_passwords: TRUE  # lab\n")
        self.assertTrue(auth.weak_passwords_allowed())
        with open(CFG, "w") as fh:
            fh.write("first_login: true\nallow_weak_passwords: false\n")
        self.assertEqual(auth.password_problem("123123"), "it is a publicly known default")

    def test_change_password_enforces_the_rule(self):
        self.claim()
        call(routes.auth_login, {"username": "admin", "password": GOOD})
        body, status = call(routes.auth_change_password,
                            {"current_password": GOOD, "new_password": "123123", "confirm": "123123"})
        self.assertEqual((status, body["error"]), (400, "weak_password"))
        new = "An0ther-Strong.Pass"
        body, status = call(routes.auth_change_password,
                            {"current_password": GOOD, "new_password": new, "confirm": new})
        self.assertEqual(status, 200, body)

    def test_login_never_applies_the_rule(self):
        # An old box set up with the shipped default before the rule existed.
        auth.write_first_login(False)
        auth.set_credential("admin", "123123")
        body, status = call(routes.auth_login, {"username": "admin", "password": "123123"})
        self.assertEqual(status, 200, body)

    def test_rule_is_length_not_composition(self):
        # NIST SP 800-63B-4: 15+ characters, any characters, no composition rules.
        for ok in ("correct horse battery", "all lowercase words here", "Héllo wörld, long one",
                   "quotes ' \" ` and $ are fine"):
            self.assertIsNone(auth.password_problem(ok), ok)
        self.assertEqual(auth.password_problem("x" * 257), "it is longer than 256 characters")
        self.assertEqual(auth.password_problem("tab\there and more"), "it has control characters")
        self.assertEqual(auth.password_problem("anna likes long walks", "anna"),
                         "it contains the user name")


_uspec = importlib.util.spec_from_file_location(
    "user_routes_under_test", os.path.join(ROOT, "modules/backend/routes/user_routes.py"))
uroutes = importlib.util.module_from_spec(_uspec)
_uspec.loader.exec_module(uroutes)

STRONG = "a long enough passphrase"


class Roles(Base):
    """Four roles, one rank rule, enforced on the server."""

    def setUp(self):
        super().setUp()
        auth.write_first_login(False)
        auth.set_credential("boss", GOOD)
        self.login("boss", GOOD)

    def login(self, name, password):
        SESSION.clear()
        body, status = call(routes.auth_login, {"username": name, "password": password})
        self.assertEqual(status, 200, body)
        return body

    def make(self, name, role, password=STRONG):
        """Create `name` as the current session's user, then give it a real password."""
        actor = dict(SESSION)
        body, status = call(uroutes.create_user, {"username": name, "role": role})
        self.assertEqual(status, 200, body)
        self.login(name, body["temporary_password"])
        body, status = call(routes.auth_change_password, {"current_password": body["temporary_password"],
                                                          "new_password": password, "confirm": password})
        self.assertEqual(status, 200, body)
        SESSION.clear()
        SESSION.update(actor)

    def gate(self, endpoint, method="GET", sess=None):
        return auth.gate_decision("/api/x", method, "172.18.0.9", SESSION if sess is None else sess,
                                  endpoint=endpoint, headers={})

    def test_existing_login_becomes_the_superadmin(self):
        users.get_connection().execute("DELETE FROM users")
        users.get_connection().commit()
        users.invalidate()
        auth.set_secret(auth._K_USER, "Tenroot")
        auth.set_secret(auth._K_HASH, auth.generate_password_hash("old-but-kept"))
        self.assertTrue(auth.migrate_legacy_credential())
        self.assertFalse(auth.migrate_legacy_credential(), "runs once")
        row = auth.authenticate("tenroot", "old-but-kept")
        self.assertEqual(row["role"], users.SUPERADMIN)

    def test_old_cookie_is_signed_out_once(self):
        SESSION.pop("uid")
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_CREDENTIALS_CHANGED)

    def test_rank_rule(self):
        self.make("adm", users.ADMIN)
        self.make("adm2", users.ADMIN)
        self.login("adm", STRONG)
        self.assertEqual(call(uroutes.create_user, {"username": "op", "role": users.OPERATOR})[1], 200)
        for role in (users.ADMIN, users.SUPERADMIN):
            self.assertEqual(call(uroutes.create_user, {"username": "x" + role, "role": role})[1], 403, role)
        for name in ("boss", "adm2", "adm"):     # above, equal, self
            self.assertEqual(call(lambda: uroutes.update_user(name), {"enabled": False})[1], 403, name)
            self.assertEqual(call(lambda: uroutes.reset_password(name))[1], 403, name)
        self.assertEqual(call(lambda: uroutes.update_user("op"), {"role": users.ADMIN})[1], 403)
        self.assertEqual(call(lambda: uroutes.update_user("op"), {"role": users.READONLY})[1], 200)
        self.assertEqual(call(uroutes.create_user, {"username": "op", "role": users.READONLY})[1], 409,
                         "names are never reused")

    def test_temporary_password_only_chooses_a_new_one(self):
        body, _ = call(uroutes.create_user, {"username": "anna", "role": users.OPERATOR})
        temp = body["temporary_password"]
        self.assertNotIn(temp, str(users.by_name("anna")), "only the hash is stored")
        self.assertTrue(self.login("anna", temp)["must_change"])
        self.assertEqual(self.gate("case.list_cases"), auth.PASSWORD_CHANGE_REQUIRED)
        users._write("UPDATE users SET temp_expires = 1 WHERE username = 'anna'", ())
        SESSION.clear()
        self.assertEqual(call(routes.auth_login, {"username": "anna", "password": temp})[1], 401,
                         "an expired one-time password is refused")

    def test_disable_and_demote_apply_on_the_next_request(self):
        self.make("op", users.OPERATOR)
        boss = dict(SESSION)
        self.login("op", STRONG)
        op = dict(SESSION)
        SESSION.clear(); SESSION.update(boss)
        auth.access_policy.POLICY["test.write"] = users.OPERATOR
        try:
            self.assertIsNone(self.gate("test.write", "POST", op))
            call(lambda: uroutes.update_user("op"), {"role": users.READONLY})
            self.assertEqual(self.gate("test.write", "POST", op), auth.SESSION_CREDENTIALS_CHANGED)
            self.login("op", STRONG)
            self.assertEqual(self.gate("test.write", "POST"), auth.FORBIDDEN)
            op = dict(SESSION)
            SESSION.clear(); SESSION.update(boss)
            call(lambda: uroutes.update_user("op"), {"enabled": False})
            self.assertEqual(auth.evaluate_session(op), auth.SESSION_DISABLED)
            SESSION.clear()
            self.assertEqual(call(routes.auth_login, {"username": "op", "password": STRONG})[1], 401)
        finally:
            auth.access_policy.POLICY.pop("test.write")

    def test_unlisted_route_is_superadmin_only(self):
        self.make("adm", users.ADMIN)
        self.assertIsNone(self.gate("no.such_route"))
        self.login("adm", STRONG)
        self.assertEqual(self.gate("no.such_route"), auth.FORBIDDEN)

    def test_user_management_needs_a_recent_password(self):
        SESSION["auth_at"] -= auth.REAUTH_SECONDS + 1
        self.assertEqual(self.gate("users.create_user", "POST"), auth.REAUTH_REQUIRED)
        self.assertIsNone(self.gate("users.list_users"), "listing is not a change")
        self.assertEqual(call(routes.auth_reauth, {"password": "wrong"})[1], 401)
        self.assertEqual(call(routes.auth_reauth, {"password": GOOD})[1], 200)
        self.assertIsNone(self.gate("users.create_user", "POST"))

    def test_tools_by_role(self):
        self.make("ro", users.READONLY)
        self.make("op", users.OPERATOR)
        expect = {"boss": {"portainer": 200, "kibana": 200, "nosuch": 403},
                  "op": {"portainer": 403, "kibana": 200, "velociraptor": 200, "iris": 200},
                  "ro": {"kibana": 403, "velociraptor": 403, "uploads": 403}}
        for name, tools in expect.items():
            self.login(name, GOOD if name == "boss" else STRONG)
            for tool, status in tools.items():
                REQUEST.args = {"tool": tool}
                self.assertEqual(call(routes.auth_verify)[1], status, (name, tool))
        REQUEST.args = {}
        SESSION.clear()
        self.assertEqual(call(routes.auth_verify)[1], 401)

    def test_tool_writes_from_another_origin_are_refused(self):
        self.make("op", users.OPERATOR)
        self.login("op", STRONG)
        REQUEST.args = {"tool": "volweb"}
        for hdrs, status in (({"X-Original-Method": "POST", "Sec-Fetch-Site": "same-site"}, 403),
                             ({"X-Original-Method": "POST", "Sec-Fetch-Site": "same-origin"}, 200),
                             ({"X-Original-Method": "GET", "Sec-Fetch-Site": "same-site"}, 200)):
            REQUEST.headers = hdrs
            REQUEST.remote_addr = NGINX
            self.assertEqual(routes.auth_verify()[1], status, hdrs)
        REQUEST.args = {}

    def test_csrf_from_another_origin_is_refused(self):
        refused = [{"Sec-Fetch-Site": "same-site"}, {"Sec-Fetch-Site": "cross-site"},
                   {"Origin": "https://box:5602", "Host": "box"}, {"Origin": "null"}]
        allowed = [{"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"}, {},
                   {"Origin": "https://box", "Host": "box"}]
        for h in refused:
            self.assertTrue(auth.csrf_problem("POST", h), h)
            self.assertFalse(auth.csrf_problem("GET", h), h)
        for h in allowed:
            self.assertFalse(auth.csrf_problem("POST", h), h)
        self.assertEqual(auth.gate_decision("/api/auth/login", "POST", NGINX, {},
                                            headers={"Sec-Fetch-Site": "same-site"}),
                         auth.CSRF_REJECTED, "login CSRF too")

    def test_setup_recovery_resets_only_the_superadmin(self):
        self.make("adm", users.ADMIN)
        auth.write_first_login(True)
        tok = write_token()
        body, status = call(routes.auth_setup, setup_body(tok, user="adm"))
        self.assertEqual((status, body["error"]), (400, "bad_username"), "cannot take over a user")
        body, status = call(routes.auth_setup, setup_body(tok, user="newboss"))
        self.assertEqual(status, 200, body)
        self.assertEqual(users.superadmin()["username"], "boss",
                         "recovery keeps the name: a freed name could be reused")
        self.assertIsNotNone(auth.authenticate("boss", GOOD))
        self.assertEqual(users.by_name("adm")["role"], users.ADMIN)
        self.assertIsNotNone(auth.authenticate("adm", STRONG))

    def test_transfer_superadmin(self):
        self.make("adm", users.ADMIN)
        self.assertEqual(call(uroutes.transfer_superadmin, {"to": "adm", "current_password": "no"})[1], 401)
        body, status = call(uroutes.transfer_superadmin, {"to": "adm", "current_password": GOOD})
        self.assertEqual(status, 200, body)
        self.assertEqual(users.superadmin()["username"], "adm")
        self.assertEqual(users.by_name("boss")["role"], users.ADMIN)
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_OK, "re-issued as an Admin")
        self.assertEqual(auth.get_secret(auth._K_USER), "adm", "a rollback signs in the new Super-admin")

    def test_role_checks_inside_a_route(self):
        # dashboard_routes: System runs (upgrade, purge) need Admin to read and
        # Super-admin to stop; a request with no session is the box itself.
        self.make("op", users.OPERATOR)
        self.assertTrue(users.caller_has(SESSION, users.SUPERADMIN))
        self.assertTrue(users.caller_has({}, users.SUPERADMIN), "loopback")
        self.login("op", STRONG)
        self.assertFalse(users.caller_has(SESSION, users.ADMIN))
        self.assertTrue(users.caller_has(SESSION, users.OPERATOR))
        self.assertEqual(users.caller_name(SESSION), "op")

    def test_rollback_cookie_never_matches_the_old_release(self):
        # The release before users accepts any cookie whose `gen` equals its
        # integer counter; a new user's generation starts at 1 too.
        self.make("ro", users.READONLY)
        self.login("ro", STRONG)
        self.assertIsInstance(SESSION["gen"], str)
        self.assertNotEqual(SESSION["gen"], int(auth.get_secret(auth._K_GENERATION) or 0))

    def test_password_changed_during_a_rollback_is_picked_up(self):
        # The older release ran meanwhile and the operator changed the password
        # there: it wrote only the legacy rows.
        auth.set_secret(auth._K_HASH, auth.generate_password_hash("set during rollback"))
        auth.set_secret(auth._K_GENERATION, str(auth.credential_generation() + 1))
        self.assertTrue(auth.migrate_legacy_credential())
        self.assertIsNotNone(auth.authenticate("boss", "set during rollback"))
        self.assertFalse(auth.migrate_legacy_credential(), "and only once")

    def test_one_time_password_session_ignores_the_lab_switch(self):
        body, _ = call(uroutes.create_user, {"username": "anna", "role": users.OPERATOR})
        self.login("anna", body["temporary_password"])
        os.environ["INTACT_ALLOW_WEAK_PASSWORDS"] = "1"
        self.assertEqual(self.gate("case.list_cases"), auth.PASSWORD_CHANGE_REQUIRED)

    def test_guessing_the_current_password_hits_the_lockout(self):
        bad = {"current_password": "nope", "new_password": STRONG, "confirm": STRONG}
        for _ in range(auth.LOCKOUT_THRESHOLD):
            self.assertEqual(call(routes.auth_change_password, bad)[1], 401)
        self.assertEqual(call(routes.auth_change_password, bad)[1], 429)
        self.assertEqual(call(uroutes.transfer_superadmin, {"to": "x", "current_password": "no"})[1], 429)

    def test_tool_only_activity_keeps_the_session(self):
        # Working only inside Kibana: nginx's per-tool check is the only request,
        # and its Set-Cookie is dropped, so the cookie's `seen` never moves.
        SESSION["seen"] -= auth.SESSION_IDLE_LIMIT_SECONDS - 60
        auth.note_activity(SESSION)
        SESSION["seen"] -= 120
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_OK)
        auth._last_active.clear()
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_EXPIRED)

    def test_backup_copy_has_no_password_hash(self):
        import sqlite3
        spec = importlib.util.spec_from_file_location(
            "db_routes_under_test", os.path.join(ROOT, "modules/backend/routes/db_routes.py"))
        db_routes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(db_routes)
        users.get_connection().execute("PRAGMA wal_checkpoint(FULL)")
        out = db_routes._make_redacted_backup_copy(os.path.join(_BASE, "intact.db"))
        try:
            rows = sqlite3.connect(out).execute("SELECT username, pw_hash FROM users").fetchall()
        finally:
            os.unlink(out)
        self.assertTrue(rows)
        self.assertEqual({h for _, h in rows}, {"[REDACTED]"})
        users._write("UPDATE users SET pw_hash = '[REDACTED]' WHERE username = 'boss'", ())
        self.assertIsNone(auth.authenticate("boss", GOOD), "a restored, redacted hash fails closed")

    def test_names_that_could_collide_in_a_tool_are_refused(self):
        self.assertEqual(users.name_problem("tenroot-intact"), "it may not end in -intact")
        self.assertIsNone(users.name_problem("intact-anna"))

    def test_absolute_session_limit(self):
        SESSION["iat"] -= auth.SESSION_ABSOLUTE_LIMIT_SECONDS + 1
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_EXPIRED)


class AuditChain(Base):
    def test_a_changed_or_removed_line_breaks_the_chain(self):
        for f in [auth.AUDIT_LOG] + [f"{auth.AUDIT_LOG}.{i}" for i in range(1, auth.AUDIT_KEEP + 1)]:
            if os.path.exists(f):
                os.unlink(f)
        auth._last_hash = None
        for i in range(5):
            auth.audit("action", username_value=f"u{i}")
        self.assertIsNone(auth.verify_audit_chain([auth.AUDIT_LOG]))
        auth._last_hash = None      # a restart: the chain continues from the file
        auth.audit("action", username_value="after-restart")
        self.assertIsNone(auth.verify_audit_chain([auth.AUDIT_LOG]))
        with open(auth.AUDIT_LOG) as fh:
            lines = fh.readlines()
        with open(auth.AUDIT_LOG, "w") as fh:
            fh.writelines(lines[:2] + lines[3:])
        self.assertEqual(auth.verify_audit_chain([auth.AUDIT_LOG]), 3)
        with open(auth.AUDIT_LOG, "w") as fh:
            fh.writelines(lines[:1] + [lines[1].replace("u1", "uX")] + lines[2:])
        self.assertEqual(auth.verify_audit_chain([auth.AUDIT_LOG]), 2)


import json  # noqa: E402
import time as _time  # noqa: E402
from services import mfa  # noqa: E402


class ClosedGets(unittest.TestCase):
    """/api/auth/status lists the GET routes closed to the caller's role, so the
    dashboard stops sending background loads the server would refuse."""

    def test_routes_split_by_the_real_policy(self):
        import re as _re
        rule = lambda path, ep, methods=("GET", "HEAD"): types.SimpleNamespace(rule=path, endpoint=ep, methods=set(methods))
        rules = [rule("/api/system/data-location", "system.data_location_get"),
                 rule("/api/cases", "case.list_cases"),
                 rule("/api/cases/<case_id>/files/<file_id>", "case.download_case_file"),
                 rule("/api/security/alerts/<int:alert_id>/ack", "security.ack_security_alert", ("POST",)),
                 rule("/static/<path:f>", "static"),
                 rule("/api/auth/status", "auth.auth_status"),
                 rule("/api/x/<string(length=2):c>/y", "nosuch.endpoint")]
        _flask.current_app = types.SimpleNamespace(url_map=types.SimpleNamespace(iter_rules=lambda: rules))
        routes._GET_RULES.clear()
        try:
            ro = routes._get_rules(users.READONLY)
            adm = routes._get_rules(users.ADMIN)
        finally:
            routes._GET_RULES.clear()
            del _flask.current_app
        hit = lambda srcs, path: any(_re.match(x, path) for x in srcs)
        self.assertTrue(hit(ro["closed"], "/api/system/data-location"))
        self.assertTrue(hit(ro["open"], "/api/cases"))
        self.assertTrue(hit(ro["open"], "/api/cases/c1/files/f1"), "pictures: the route decides")
        self.assertFalse(hit(ro["closed"] + ro["open"], "/api/security/alerts/1/ack"), "GET routes only")
        self.assertFalse(hit(ro["closed"] + ro["open"], "/static/x.js"), "/api only")
        self.assertTrue(hit(adm["closed"], "/api/system/data-location"), "Super-admin only")
        self.assertTrue(hit(ro["open"], "/api/auth/status"), "the gate's exempt paths are open")
        self.assertTrue(hit(ro["closed"], "/api/x/ab/y"), "a converter with arguments is a segment too")


class TwoStep(Base):
    """Two-step login (services/mfa.py), with the real rule: Admins and the
    Super-admin must set it up; codes work once; recovery codes once each."""
    MFA_OFF = False

    def setUp(self):
        super().setUp()
        auth.write_first_login(False)
        auth.set_credential("boss", GOOD)

    def login(self, name, password):
        SESSION.clear()
        return call(routes.auth_login, {"username": name, "password": password})

    def enroll(self, name, password=GOOD):
        """Set up two-step login the way the screens do; returns (secret, recovery codes)."""
        body, _ = call(routes.auth_mfa_setup)
        secret = body["secret"]
        self.assertTrue(body["otpauth_uri"].startswith("otpauth://totp/Intact.AI:" + name))
        body, status = call(routes.auth_mfa_confirm, {"code": mfa.code_at(secret, mfa.current_step()),
                                                      "password": password})
        self.assertEqual(status, 200, body)
        return secret, body["recovery_codes"]

    def gate(self, endpoint="case.list_cases", path="/api/x"):
        return auth.gate_decision(path, "GET", NGINX, SESSION, endpoint=endpoint, headers={})

    def test_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA1, T=59 s: 94287082 -> the last 6 digits.
        # Its published key is the ASCII "12345678901234567890", base32-encoded.
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(mfa.code_at(secret, 59 // 30), "287082")
        self.assertEqual(mfa.verify(secret, "287082", now=59), 1)
        self.assertIsNone(mfa.verify(secret, "287082", now=59 + 90), "outside the window")
        self.assertIsNone(mfa.verify(secret, "287082", last_step=1, now=59), "replay refused")

    def test_recovery_codes_from_the_unsalted_build_still_work_once(self):
        old = hashlib.sha256(b"intact-recovery:abcd2345xy").hexdigest()
        left = mfa.use_recovery("ABCD-2345-XY", [old, "other"], "7")
        self.assertEqual(left, ["other"])
        self.assertIsNone(mfa.use_recovery("abcd-2345-xy", left, "7"))

    def test_admin_must_enroll_before_anything_else(self):
        body, status = self.login("boss", GOOD)
        self.assertEqual(status, 200)
        self.assertFalse(body.get("mfa_required"), "not set up yet: the password signs in")
        self.assertEqual(self.gate(), auth.MFA_ENROLL_REQUIRED)
        self.assertIsNone(self.gate(path="/api/auth/mfa/setup"))
        st, _ = call(routes.auth_status)
        self.assertTrue(st["must_enroll"] and st["mfa_required"] and not st["mfa_enabled"])
        REQUEST.args = {"tool": "kibana"}
        self.assertEqual(call(routes.auth_verify)[1], 401, "no tool until it is set up")
        REQUEST.args = {}
        self.enroll("boss")
        self.assertIsNone(self.gate())
        self.assertNotIn(mfa.new_secret()[:4], json.dumps(users.by_name("boss").get("mfa_secret") or ""),
                         "stored encrypted")

    def test_login_with_code_then_recovery_code_once(self):
        self.login("boss", GOOD)
        secret, codes = self.enroll("boss")
        self.assertEqual(len(codes), 10)
        body, _ = self.login("boss", GOOD)
        self.assertTrue(body["mfa_required"])
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_NONE, "not signed in yet")
        self.assertEqual(call(routes.auth_mfa, {"code": "000000"})[1], 401)
        nxt = mfa.current_step() + 1         # the setup used this step: a fresh one
        body, status = call(routes.auth_mfa, {"code": mfa.code_at(secret, nxt)})
        self.assertEqual(status, 200, body)
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_OK)
        self.login("boss", GOOD)
        self.assertEqual(call(routes.auth_mfa, {"code": mfa.code_at(secret, nxt)})[1], 401, "a code works once")
        self.assertEqual(call(routes.auth_mfa, {"recovery_code": codes[0].upper()})[1], 200)
        self.login("boss", GOOD)
        self.assertEqual(call(routes.auth_mfa, {"recovery_code": codes[0]})[1], 401, "a recovery code works once")

    def test_pending_step_expires(self):
        self.login("boss", GOOD)
        secret, _ = self.enroll("boss")
        self.login("boss", GOOD)
        SESSION["mfa_pending"]["at"] -= auth.MFA_PENDING_SECONDS + 1
        body, status = call(routes.auth_mfa, {"code": mfa.code_at(secret, mfa.current_step() + 1)})
        self.assertEqual((status, body["error"]), (401, "mfa_expired"))

    def test_reauth_needs_the_code_too(self):
        self.login("boss", GOOD)
        secret, _ = self.enroll("boss")
        self.assertEqual(call(routes.auth_reauth, {"password": GOOD})[1], 401)
        body, status = call(routes.auth_reauth, {"password": GOOD, "code": mfa.code_at(secret, mfa.current_step() + 1)})
        self.assertEqual(status, 200, body)

    def test_disable_only_when_not_required_and_admin_reset(self):
        self.login("boss", GOOD)
        secret, _ = self.enroll("boss")
        self.assertEqual(call(routes.auth_mfa_disable, {"password": GOOD})[1], 403, "required for the role")
        body, _ = call(uroutes.create_user, {"username": "opx", "role": users.OPERATOR})
        boss = dict(SESSION)
        self.login("opx", body["temporary_password"])
        call(routes.auth_change_password, {"current_password": body["temporary_password"],
                                           "new_password": STRONG_PW, "confirm": STRONG_PW})
        self.assertIsNone(self.gate(), "optional for an Operator")
        osec, _ = self.enroll("opx", STRONG_PW)
        self.assertEqual(call(routes.auth_mfa_disable, {"password": STRONG_PW, "code": "000000"})[1], 401)
        body, status = call(routes.auth_mfa_disable, {"password": STRONG_PW,
                                                      "code": mfa.code_at(osec, mfa.current_step() + 1)})
        self.assertEqual(status, 200, body)
        self.assertEqual(auth.evaluate_session(SESSION), auth.SESSION_OK, "re-issued")
        self.enroll("opx", STRONG_PW)
        op = dict(SESSION)
        SESSION.clear(); SESSION.update(boss)
        self.assertEqual(call(lambda: uroutes.reset_mfa("opx"))[1], 200)
        self.assertFalse(users.by_name("opx")["mfa_enabled"])
        self.assertEqual(auth.evaluate_session(op), auth.SESSION_CREDENTIALS_CHANGED, "their sessions end")
        self.assertEqual(call(lambda: uroutes.reset_mfa("boss"))[1], 403, "not your own / above")

    def test_code_guessing_locks_the_user_even_with_the_right_password(self):
        # Review finding: a correct password reset the per-address count, so a
        # password-holder could keep guessing codes. Now the count is per user.
        self.login("boss", GOOD)
        secret, _ = self.enroll("boss")
        auth._mfa_fail.clear()
        # A fresh address per guess: the per-address lockout (which a correct
        # password no longer clears either) cannot be what stops it here.
        for i in range(auth.LOCKOUT_THRESHOLD):
            SESSION.clear()
            call(routes.auth_login, {"username": "boss", "password": GOOD}, ip=f"10.7.{i}.1")
            call(routes.auth_mfa, {"code": "000000"}, ip=f"10.7.{i}.1")
        SESSION.clear()
        call(routes.auth_login, {"username": "boss", "password": GOOD}, ip="10.7.99.1")
        body, status = call(routes.auth_mfa, {"code": mfa.code_at(secret, mfa.current_step() + 1)}, ip="10.7.99.1")
        self.assertEqual((status, body["error"]), (429, "locked"), "even the right code waits out the lock")
        auth._mfa_fail.clear()

    def test_setup_cannot_replace_an_active_factor_and_confirm_needs_the_password(self):
        self.login("boss", GOOD)
        body, _ = call(routes.auth_mfa_setup)
        bad, status = call(routes.auth_mfa_confirm, {"code": mfa.code_at(body["secret"], mfa.current_step())})
        self.assertEqual((status, bad["error"]), (401, "invalid_credentials"), "a stolen session alone cannot enrol")
        self.enroll("boss")
        body, status = call(routes.auth_mfa_setup)
        self.assertEqual((status, body["error"]), (409, "mfa_already_on"))

    def test_reauth_takes_a_recovery_code_and_unicode_digits_do_not_crash(self):
        self.login("boss", GOOD)
        _, codes = self.enroll("boss")
        self.assertEqual(call(routes.auth_reauth, {"password": GOOD, "code": "\u00b2" * 6})[1], 401)
        self.assertIsNone(mfa.verify(mfa.new_secret(), "\u00b2" * 6))
        self.assertEqual(call(routes.auth_reauth, {"password": GOOD, "recovery_code": codes[1]})[1], 200)
        auth._mfa_fail.clear()

    def test_reused_code_says_wait_for_the_next(self):
        self.login("boss", GOOD)
        secret, _ = self.enroll("boss")
        used = mfa.code_at(secret, users.by_name("boss")["mfa_last_step"])
        body, status = call(routes.auth_reauth, {"password": GOOD, "code": used})
        self.assertEqual(status, 401)
        self.assertIn("Wait for the next one", body["message"])
        auth._mfa_fail.clear()

    def test_reset_login_recovery_clears_the_superadmins_factor(self):
        self.login("boss", GOOD)
        self.enroll("boss")
        auth.write_first_login(True)
        tok = write_token()
        self.assertEqual(call(routes.auth_setup, setup_body(tok, user="boss"))[1], 200)
        self.assertFalse(users.by_name("boss")["mfa_enabled"], "lost phone: set it up again")


STRONG_PW = "another long passphrase"

if __name__ == "__main__":
    unittest.main()
