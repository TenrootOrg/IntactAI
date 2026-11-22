"""Dashboard login: one-time setup token, per-client lockout, password rule,
must-change gate for a publicly known password, global brake.

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


REQUEST = types.SimpleNamespace(headers={}, remote_addr="172.18.0.9", body=None)
REQUEST.get_json = lambda silent=False: REQUEST.body
SESSION = _Session()

_flask = types.ModuleType("flask")


class _Blueprint:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda fn: fn


_flask.Blueprint = _Blueprint
_flask.jsonify = lambda body=None, **k: body if body is not None else k
_flask.request = REQUEST
_flask.session = SESSION
sys.modules["flask"] = _flask

from services import auth_service as auth  # noqa: E402
_REAL_RESOLVE = auth._resolve_nginx

_spec = importlib.util.spec_from_file_location(
    "auth_routes_under_test", os.path.join(ROOT, "modules/backend/routes/auth_routes.py"))
routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(routes)

GOOD = "Str0ng-Pass.word9"
NO_SYMBOL = "Abcdefghijk1"   # strong before 2026-11-22; new passwords now need a symbol


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
        auth.reset_lockout()
        auth.MIN_SECONDS_BETWEEN_ATTEMPTS = 0.0
        auth._resolve_nginx = lambda: frozenset({NGINX})
        auth._nginx.update(addrs=frozenset(), at=None)
        os.environ.pop("INTACT_ALLOW_WEAK_PASSWORDS", None)
        SESSION.clear()

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
        self.assertEqual(call(routes.auth_verify)[1], 401, "/velociraptor/ and uploads too")
        self.assertTrue(call(routes.auth_status)[0]["must_change"])

        new = "An0ther-Strong.Pass"
        body, status = call(routes.auth_change_password,
                            {"current_password": "123123", "new_password": new, "confirm": new})
        self.assertEqual(status, 200, body)
        self.assertIsNone(self.gate(self.API))
        self.assertEqual(call(routes.auth_verify)[1], 200)
        self.assertFalse(call(routes.auth_status)[0]["must_change"])
        # And a later login with the new password is not flagged.
        SESSION.clear()
        body, _ = call(routes.auth_login, {"username": "admin", "password": new})
        self.assertFalse(body["must_change"])
        self.assertIsNone(self.gate(self.API))

    def test_rule_failing_old_password_is_flagged_too(self):
        auth.write_first_login(False)
        auth.set_credential("admin", "short-but-old")
        body, _ = call(routes.auth_login, {"username": "admin", "password": "short-but-old"})
        self.assertTrue(body["must_change"])

    def test_old_password_without_a_symbol_is_not_flagged(self):
        # 2026-11-22: a NEW password needs a symbol; one set before that keeps
        # working without being sent to change-password.
        auth.write_first_login(False)
        auth.set_credential("admin", NO_SYMBOL)
        body, _ = call(routes.auth_login, {"username": "admin", "password": NO_SYMBOL})
        self.assertFalse(body["must_change"])
        self.assertEqual(auth.password_problem(NO_SYMBOL),
                         "it needs a symbol (such as ! @ # % ^ & * + = ? ~)")

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
        for weak in ("123123", "Short1Aa", "alllowercase123", "-Leading1Dash12", "Has Space1Abcd"):
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

    def test_matches_lib_secrets_sh(self):
        samples = ["", "123123", "changeme", "Ch4nge-Me!Intact2026", "Short1Aa", "Str0ng-Pass.word9",
                   "alllowercase123", "ALLUPPERCASE123", "NoDigitsHereAtAll", "-Leading1Dash12",
                   ".Leading1Dotxx", "Has Space1Abcd", "Dollar$1Abcdefg", "Abcdefghijk1", "Abcdefghij1",
                   "Abcdefghij1!", "Abcdefgh1!@#%^&*()[]{}|;:,.<>/?~=+-_", "Back\\slash1Abc!",
                   "Back`tick1Abcd!", 'Dq"uote1Abcde!', "Sq'uote1Abcde!", "Héllo1Abcdefg!", "!Leading1Abcde"]
        script = 'source lib/secrets.sh; for v in "$@"; do secret_check "$v" >/dev/null && echo 1 || echo 0; done'
        out = subprocess.run(["bash", "-c", script, "_"] + samples, cwd=ROOT,
                             capture_output=True, text=True, timeout=30).stdout.split()
        self.assertEqual(out, ["1" if auth.password_problem(v) is None else "0" for v in samples])


if __name__ == "__main__":
    unittest.main()
