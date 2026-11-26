"""Security alerts (services/security_alerts.py) and the Settings -> Security
routes (routes/security_routes.py).

Each rule fires once per 10-minute window, bursts are deduplicated, alerts are
stored, acknowledged once, counted for the dashboard badge and handed to the
syslog forwarder. flask is a container dependency, so the routes run against
a minimal stand-in, as in test_dashboard_login_auth.py.
"""
import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-alerttest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_AUTH_DIR"] = os.path.join(_BASE, "auth")
os.environ["INTACT_CONFIG_PATH"] = os.path.join(_BASE, "config.yaml")
os.environ["INTACT_CLOUD_KEY_PATH"] = os.path.join(_BASE, "state", "cloud_secrets.key")
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

REQUEST = types.SimpleNamespace(body=None, args={})
REQUEST.get_json = lambda silent=False: REQUEST.body
SESSION = {}


class _Blueprint:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda fn: fn


_flask = types.ModuleType("flask")
_flask.Blueprint = _Blueprint
_flask.jsonify = lambda body=None, **k: body if body is not None else k
_flask.request = REQUEST
_flask.session = SESSION
sys.modules["flask"] = _flask

from services import audit_forward  # noqa: E402
from services import auth_service as auth  # noqa: E402
from services import security_alerts as sa  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "security_routes_under_test", os.path.join(ROOT, "modules/backend/routes/security_routes.py"))
routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(routes)

T0 = 1_000_000.0


def kinds(entry, now):
    return [a[0] for a in sa.evaluate(entry, now=now)]


def call(fn, *args, body=None, args_=None):
    REQUEST.body, REQUEST.args = body, args_ or {}
    out = fn(*args)
    return out if isinstance(out, tuple) else (out, 200)


class Base(unittest.TestCase):
    def setUp(self):
        sa._hits.clear()
        sa._fired.clear()
        conn = sa.get_connection()
        sa._ensure_table(conn)
        conn.execute("DELETE FROM security_alerts")
        conn.commit()


class BurstRules(Base):
    def fail(self, ip, now, user="admin", event="login_failed"):
        return kinds({"event": event, "ip": ip, "user": user}, now)

    def test_ip_burst_fires_once_per_window(self):
        fired = []
        for i in range(15):
            fired += self.fail("10.0.0.9", T0 + i)
        self.assertEqual(fired, ["failed_login_burst"])        # at the 10th, once
        self.assertEqual(self.fail("10.0.0.9", T0 + 300), [])  # same window: deduplicated
        # After the window, a burst still going on raises the next one.
        later = []
        for i in range(10):
            later += self.fail("10.0.0.9", T0 + 700 + i)
        self.assertEqual(later, ["failed_login_burst"])

    def test_ninth_failure_and_slow_failures_do_not_fire(self):
        out = []
        for i in range(9):
            out += self.fail("10.0.0.1", T0 + i)
        for i in range(12):                                    # one every 70 s: 10 take > 10 min
            out += self.fail("10.0.0.2", T0 + 70 * i)
        self.assertEqual(out, [])

    def test_failed_codes_count(self):
        out = []
        for i in range(10):
            out += self.fail("10.0.0.3", T0 + i, event="reauth_failed")
        self.assertEqual(out, ["failed_login_burst"])

    def test_box_wide_burst_across_ips(self):
        out = []
        for i in range(25):
            out += self.fail(f"10.1.0.{i}", T0 + i)
        self.assertEqual(out, ["failed_login_burst_box"])

    def test_forbidden_burst_per_user(self):
        out = []
        for i in range(12):
            out += kinds({"event": "denied", "reason": "forbidden", "user": "op", "ip": "x"}, T0 + i)
        for i in range(9):
            out += kinds({"event": "denied", "reason": "forbidden", "user": "ro", "ip": "x"}, T0 + i)
        self.assertEqual(out, ["forbidden_burst"])
        # A token probing routes it may never use counts like a forbidden burst.
        out = []
        for i in range(10):
            out += kinds({"event": "token_denied", "reason": "token_refused", "user": "tk", "ip": "y"}, T0 + i)
        self.assertEqual(out, ["forbidden_burst"])
        # Dead tokens from one address count like failed sign-ins.
        out = []
        for i in range(10):
            out += kinds({"event": "token_denied", "reason": "token_invalid", "ip": "z"}, T0 + i)
        self.assertEqual(out, ["failed_login_burst"])
        # reauth_required is the normal step-up prompt, not an attack.
        self.assertEqual(kinds({"event": "denied", "reason": "reauth_required", "user": "op"}, T0), [])


class SingleRules(Base):
    def test_each_event_rule(self):
        cases = [
            ({"event": "user_role_changed", "user": "sa", "target": "bob", "role": "admin",
              "old_role": "operator"}, ["admin_granted"]),
            ({"event": "user_role_changed", "user": "sa", "target": "bob", "role": "superadmin"},
             ["admin_granted"]),
            ({"event": "user_role_changed", "user": "sa", "target": "bob", "role": "operator"}, []),
            ({"event": "user_created", "user": "sa", "target": "carol", "role": "admin"}, ["admin_granted"]),
            ({"event": "user_created", "user": "sa", "target": "dave", "role": "readonly"}, []),
            ({"event": "superadmin_transferred", "user": "sa", "target": "bob"}, ["superadmin_transferred"]),
            ({"event": "setup", "user": "admin", "role": "superadmin"}, ["superadmin_setup"]),
            ({"event": "user_mfa_reset", "user": "sa", "target": "bob"}, ["mfa_removed"]),
            ({"event": "mfa_disabled", "user": "erin"}, ["mfa_removed"]),
            # once per target per window: toggling one's own two-step login cannot flood
            ({"event": "mfa_disabled", "user": "erin"}, []),
            ({"event": "audit_forward_changed", "user": "adm",
              "old": {"enabled": True, "host": "siem", "port": 514},
              "new": {"enabled": False, "host": "siem", "port": 514}}, ["audit_forward_changed"]),
            ({"event": "audit_forward_changed", "user": "adm",
              "old": {"enabled": True, "host": "siem", "port": 514},
              "new": {"enabled": True, "host": "evil", "port": 514}}, ["audit_forward_changed"]),
            ({"event": "audit_forward_changed", "user": "adm",
              "old": {"enabled": False, "host": "", "port": 514},
              "new": {"enabled": True, "host": "siem", "port": 514}}, []),
            ({"event": "login_ok", "user": "bob"}, []),
            ({"event": "action", "user": "bob"}, []),
        ]
        for entry, want in cases:
            self.assertEqual(kinds(entry, T0), want, entry)

    def test_locked_and_csrf_dedup_per_window(self):
        lock = {"event": "locked", "user": "admin", "ip": "10.0.0.5", "locked_for_seconds": 300}
        self.assertEqual(kinds(lock, T0), ["account_locked"])
        self.assertEqual(kinds(lock, T0 + 60), [])
        self.assertEqual(kinds(dict(lock, ip="10.0.0.6"), T0 + 60), ["account_locked"])
        self.assertEqual(kinds(lock, T0 + 601), ["account_locked"])
        csrf = {"event": "denied", "reason": "csrf_rejected", "user": "bob", "ip": "1.2.3.4",
                "endpoint": "tool:kibana"}
        self.assertEqual(kinds(csrf, T0), ["csrf_rejected"])
        self.assertEqual(kinds(csrf, T0 + 1), [])

    def test_every_kind_reads_as_plain_words(self):
        for kind in ("failed_login_burst", "failed_login_burst_box", "account_locked", "admin_granted",
                     "superadmin_transferred", "superadmin_setup", "mfa_removed", "csrf_rejected",
                     "forbidden_burst"):
            text = sa.describe(kind, "bob", {"ip": "1.2.3.4", "count": 10, "target": "eve", "role": "admin"})
            self.assertNotEqual(text, kind)
            self.assertNotIn("None", text)


class StoreAndAck(Base):
    @classmethod
    def setUpClass(cls):
        sa.install()
        sa.install()

    def setUp(self):
        super().setUp()
        self.forwarded = []
        self._orig = audit_forward.forward_alert
        audit_forward.forward_alert = self.forwarded.append

    def tearDown(self):
        audit_forward.forward_alert = self._orig

    def test_through_audit_store_forward_ack(self):
        self.assertEqual(auth.AUDIT_SINKS.count(sa.sink), 1)
        auth.audit("superadmin_transferred", username_value="sa", target="bob")
        auth.audit("login_ok", username_value="bob")
        self.assertEqual(sa.unacked_count(), 1)
        [alert] = sa.list_alerts()
        self.assertEqual((alert["kind"], alert["severity"], alert["user"]),
                         ("superadmin_transferred", "high", "sa"))
        self.assertEqual(alert["detail"]["target"], "bob")
        self.assertIn("bob", alert["text"])
        self.assertEqual([a["id"] for a in self.forwarded], [alert["id"]])

        acked = sa.acknowledge(alert["id"], "admin1")
        self.assertEqual(acked["acknowledged_by"], "admin1")
        self.assertTrue(acked["acknowledged_at"])
        self.assertEqual(sa.acknowledge(alert["id"], "admin2")["acknowledged_by"], "admin1")
        self.assertEqual(sa.unacked_count(), 0)
        self.assertEqual(sa.list_alerts(unacked=True), [])
        self.assertEqual(len(sa.list_alerts()), 1)
        self.assertIsNone(sa.acknowledge(99999, "admin1"))

    def test_newest_first(self):
        auth.audit("setup", username_value="admin", role="superadmin")
        auth.audit("mfa_disabled", username_value="bob")
        self.assertEqual([a["kind"] for a in sa.list_alerts()], ["mfa_removed", "superadmin_setup"])

    def test_sink_never_raises(self):
        orig = sa._store
        sa._store = lambda *a: 1 / 0
        try:
            self.assertIsNone(sa.sink({"event": "setup", "user": "x"}))
        finally:
            sa._store = orig
        self.assertIsNone(sa.sink(None))


class Routes(Base):
    def setUp(self):
        super().setUp()
        SESSION.clear()
        SESSION["user"] = "admin1"

    def test_alert_routes(self):
        sa.sink({"event": "setup", "user": "admin", "role": "superadmin"})
        body, code = call(routes.security_alert_count)
        self.assertEqual((code, body["unacknowledged"]), (200, 1))
        [a] = call(routes.list_security_alerts, args_={"unacked": "1"})[0]["alerts"]
        body, code = call(routes.ack_security_alert, a["id"])
        self.assertEqual((code, body["alert"]["acknowledged_by"]), (200, "admin1"))
        self.assertEqual(call(routes.list_security_alerts, args_={"unacked": "1"})[0]["alerts"], [])
        self.assertEqual(len(call(routes.list_security_alerts)[0]["alerts"]), 1)
        self.assertEqual(call(routes.ack_security_alert, 424242)[1], 404)

    def test_forward_routes(self):
        body, code = call(routes.save_audit_forward, body={"enabled": True, "host": ""})
        self.assertEqual(code, 400)
        self.assertTrue(body["message"])
        body, code = call(routes.save_audit_forward, body=None)
        self.assertEqual(code, 400)
        body, code = call(routes.save_audit_forward,
                          body={"enabled": False, "protocol": "tcp", "host": "10.9.9.9", "port": 6514})
        self.assertEqual((code, body["config"]["port"]), (200, 6514))
        body, _ = call(routes.get_audit_forward)
        self.assertEqual(body["config"]["host"], "10.9.9.9")
        self.assertIn("dropped", body["status"])
        body, code = call(routes.test_audit_forward, body={"host": "bad host"})
        self.assertEqual((code, body["success"]), (400, False))


if __name__ == "__main__":
    unittest.main()
