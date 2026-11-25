"""services/tool_accounts/kibana.py: the Kibana / Elasticsearch provider.

A fake Elasticsearch stands in for requests.request; the admin credentials come
from the env, so no real ones are read.
"""
import atexit
import base64
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-toolacct-kib-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
atexit.register(shutil.rmtree, _BASE, True)
# Set in the env so config resolves them there and never reads the box's elk .env.
_ADMIN_PW = "admin-secret-XYZ"
os.environ.update(ELASTICSEARCH_USER="svc_backend", ELASTIC_PASSWORD=_ADMIN_PW,
                  ELASTICSEARCH_HOST="elasticsearch", ELASTICSEARCH_PORT="9200")

import _optional_deps  # noqa: F401,E402
from services.tool_accounts import kibana  # noqa: E402

FORBIDDEN_CLUSTER = {"all", "manage", "manage_security", "manage_api_key", "manage_own_api_key",
                     "grant_api_key", "read_security", "manage_service_account", "manage_token",
                     "manage_user_profile", "manage_saml", "manage_oidc", "delegate_pki"}


class FakeES:
    def __init__(self, down=False):
        self.users, self.roles, self.calls, self.down = {}, {}, [], down

    def __call__(self, method, url, json=None, auth=None, timeout=None):
        self.calls.append((method, url, json, auth, timeout))
        path = url.split(":9200", 1)[1]
        if self.down:
            return self._r(503, {"error": "unavailable"})
        parts = path.strip("/").split("/")
        if parts[:2] == ["_security", "role"] and method == "PUT":
            self.roles[parts[2]] = json
            return self._r(200, {"role": {"created": True}})
        if parts[:2] == ["_security", "user"]:
            name = parts[2]
            if len(parts) == 4 and parts[3] == "_disable":
                if name not in self.users:      # what ES 9.5 really answers
                    return self._r(400, {"error": "only existing users can be disabled"})
                self.users[name]["enabled"] = False
                return self._r(200, {})
            if method == "GET":
                return self._r(200, {name: self.users[name]}) if name in self.users else self._r(404, {})
            if method == "PUT":
                self.users[name] = dict(json)
                return self._r(200, {"created": True})
        if parts == ["_security", "api_key"] and method == "DELETE":
            self.revoked = getattr(self, "revoked", []) + [json["username"]]
            return self._r(200, {"invalidated_api_keys": []})
        return self._r(400, {"error": "unexpected " + path})

    @staticmethod
    def _r(code, body):
        return types.SimpleNamespace(status_code=code, text=json.dumps(body), json=lambda: body)


class KibanaProvider(unittest.TestCase):
    def setUp(self):
        self.es = FakeES()
        p = mock.patch.object(kibana.requests, "request", self.es)
        p.start()
        self.addCleanup(p.stop)

    def test_roles_have_no_security_privilege(self):
        for name, body in kibana.ROLES.items():
            self.assertFalse(set(body["cluster"]) & FORBIDDEN_CLUSTER, name)
            for ip in body["indices"]:
                self.assertFalse(ip.get("allow_restricted_indices"), name)
                self.assertNotIn("all", ip["privileges"], name)
            self.assertNotIn("run_as", body, name)
            self.assertEqual(body["applications"], [{"application": "kibana-.kibana",
                                                     "privileges": ["all"], "resources": ["*"]}])
        self.assertEqual(kibana.ROLES["intact_member"]["cluster"], [])

    def test_role_mapping(self):
        self.assertEqual(kibana.tool_role("superadmin"), "intact_superadmin")
        self.assertEqual(kibana.tool_role("admin"), "intact_member")
        self.assertEqual(kibana.tool_role("operator"), "intact_member")
        self.assertIsNone(kibana.tool_role("readonly"))

    def test_reserved_has_builtins_and_configured_user(self):
        self.assertTrue({"elastic", "kibana_system", "remote_monitoring_user"} <= kibana.RESERVED)
        self.assertIn("svc_backend", kibana.RESERVED)

    def test_ensure_creates_roles_and_user(self):
        kibana.ensure("anna", "pw-anna-1", "intact_member")
        self.assertEqual(set(self.es.roles), {"intact_member", "intact_superadmin"})
        u = self.es.users["anna"]
        self.assertEqual((u["roles"], u["enabled"], u["password"], u["metadata"]),
                         (["intact_member"], True, "pw-anna-1", {"intact": True}))
        self.assertTrue(all(c[4] == 10 for c in self.es.calls), "every call has a timeout")
        self.assertTrue(all(c[3] == ("svc_backend", _ADMIN_PW) for c in self.es.calls))
        # Again, after a hand edit: idempotent and drift is reverted.
        self.es.users["anna"].update(roles=["superuser"], enabled=False)
        kibana.ensure("anna", "pw-anna-1", "intact_member")
        self.assertEqual((self.es.users["anna"]["roles"], self.es.users["anna"]["enabled"]),
                         (["intact_member"], True))

    def test_ensure_refuses_a_hand_made_user(self):
        self.es.users["bob"] = {"roles": ["viewer"], "metadata": {}, "enabled": True}
        with self.assertRaises(RuntimeError):
            kibana.ensure("bob", "pw", "intact_member")
        self.assertEqual(self.es.users["bob"]["roles"], ["viewer"])

    def test_ensure_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            kibana.ensure("anna", "pw", "superuser")

    def test_routine_pass_keeps_the_password_and_demotion_drops_api_keys(self):
        kibana.ensure("anna", "pw-anna-1", "intact_superadmin")
        kibana.ensure("anna", "pw-anna-1", "intact_superadmin", set_password=False)
        self.assertNotIn("password", self.es.calls[-1][2], "an existing user keeps its own")
        self.assertEqual(getattr(self.es, "revoked", []), [])
        kibana.ensure("anna", "pw-anna-1", "intact_member", set_password=False)
        self.assertEqual(self.es.revoked, ["anna"], "old-role API keys go with the demotion")

    def test_disable_revokes_the_users_api_keys(self):
        kibana.ensure("anna", "pw-anna-1", "intact_member")
        kibana.disable("anna")
        self.assertEqual(self.es.revoked, ["anna"], "alerting rules' keys stop with the person")

    def test_disable_is_idempotent(self):
        kibana.ensure("anna", "pw", "intact_member")
        kibana.disable("anna")
        kibana.disable("anna")
        self.assertFalse(self.es.users["anna"]["enabled"])
        kibana.disable("ghost")             # missing user: no error

    def test_failure_raises_without_password(self):
        self.es.down = True
        with self.assertRaises(RuntimeError) as cm:
            kibana.ensure("anna", "pw-hidden-77", "intact_member")
        self.assertIn("503", str(cm.exception))
        self.assertNotIn("pw-hidden-77", str(cm.exception))
        self.assertNotIn(_ADMIN_PW, str(cm.exception))

    def test_auth_value(self):
        v = kibana.auth_value("anna", "p:w")
        self.assertTrue(v.startswith("Basic "))
        self.assertEqual(base64.b64decode(v[6:]).decode(), "anna:p:w")
        self.assertIsNone(kibana.auth_value("anna", None))

    def test_password_never_printed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), \
                self.assertLogs(level="DEBUG") as logs:
            import logging
            logging.getLogger("probe").debug("x")   # assertLogs needs one record
            kibana.ensure("anna", "pw-secret-42", "intact_superadmin")
            kibana.disable("anna")
            kibana.auth_value("anna", "pw-secret-42")
            self.es.down = True
            with contextlib.suppress(RuntimeError):
                kibana.ensure("anna", "pw-secret-42", "intact_member")
        text = out.getvalue() + "\n".join(logs.output)
        for secret in ("pw-secret-42", _ADMIN_PW):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
