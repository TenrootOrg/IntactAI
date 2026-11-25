"""services/tool_accounts/velociraptor.py against a fake Velociraptor.

The fake `_query` keeps {user: {"pw": ..., "orgs": {org: roles}}} and answers
the three VQL calls the provider makes (user, user_create, user_grant), with
the semantics checked on 0.77.4: user_create replaces roles in the orgs it
lists, user_grant(policy=dict()) drops the user from them.
"""
import ast
import atexit
import base64
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
# velociraptor_clients' imports open the storage layer: keep it off the box's DB.
_BASE = tempfile.mkdtemp(prefix="intact-velo-acct-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
from services.tool_accounts import velociraptor as velo  # noqa: E402

PW = "A" * 20 + "b_-9" * 5
ORGS = ["root", "O2JS0", "OK1TQ"]


def _arg(vql, name):
    m = re.search(rf"\b{name}=('[^']*'|\[[^\]]*\])", vql)
    return ast.literal_eval(m.group(1)) if m else None


class FakeVelo:
    def __init__(self):
        self.users, self.vql = {}, []

    def query(self, vql, timeout=120):
        self.vql.append(vql)
        user = _arg(vql, "user")
        if "user_create(" in vql:
            u = self.users.setdefault(user, {"orgs": {}})
            u["pw"] = _arg(vql, "password")
            for o in _arg(vql, "orgs"):
                u["orgs"][o] = list(_arg(vql, "roles"))
        elif "user_grant(" in vql:
            # 0.77.4: roles= replaces the roles in those orgs; policy=dict() drops them.
            for o in _arg(vql, "orgs"):
                if "roles=" in vql:
                    self.users[user]["orgs"][o] = list(_arg(vql, "roles"))
                else:
                    self.users[user]["orgs"].pop(o, None)
        elif "user(" in vql:
            return [{"u": {"name": user} if user in self.users else None}]
        return [{"r": user}]


class Provider(unittest.TestCase):
    def setUp(self):
        self.fake = FakeVelo()
        self._saved = velo._query, velo.org_list
        velo._query = self.fake.query
        velo.org_list = lambda: [(o, o) for o in ORGS]

    def tearDown(self):
        velo._query, velo.org_list = self._saved

    def test_roles(self):
        self.assertEqual(velo.tool_role("superadmin"), ["administrator"])
        for r in ("admin", "operator"):
            self.assertNotIn("administrator", velo.tool_role(r))
            self.assertEqual(velo.tool_role(r), ["investigator", "artifact_writer"])
        self.assertIsNone(velo.tool_role("readonly"))
        self.assertIsNone(velo.tool_role("nosuch"))

    def test_ensure_grants_in_every_org_and_reverts_drift(self):
        velo.ensure("anna", PW, velo.tool_role("operator"))
        u = self.fake.users["anna"]
        self.assertEqual(set(u["orgs"]), set(ORGS))
        self.assertTrue(all(r == ["investigator", "artifact_writer"] for r in u["orgs"].values()))
        self.assertEqual(u["pw"], PW)
        u["orgs"]["O2JS0"] = ["administrator"]          # raised by hand
        u["pw"] = "changed-by-hand"
        velo.ensure("anna", PW, velo.tool_role("operator"))
        self.assertEqual(u["orgs"]["O2JS0"], ["investigator", "artifact_writer"])
        self.assertEqual(u["pw"], PW)

    def test_disable_strips_every_org_and_changes_password(self):
        velo.ensure("anna", PW, velo.tool_role("admin"))
        velo.disable("anna")
        u = self.fake.users["anna"]
        self.assertEqual(u["orgs"], {})
        self.assertNotEqual(u["pw"], PW)
        self.assertNotIn("user_delete", " ".join(self.fake.vql))

    def test_disable_missing_user_is_fine_and_creates_nothing(self):
        velo.disable("ghost")
        self.assertNotIn("ghost", self.fake.users)

    def test_injection_rejected(self):
        bad_users = ["a'b", "x') AS r FROM scope() --", "Anna", "a b", "", "a\nb", None]
        for u in bad_users:
            with self.assertRaises(ValueError, msg=repr(u)):
                velo.ensure(u, PW, ["investigator"])
            with self.assertRaises(ValueError, msg=repr(u)):
                velo.disable(u)
        for pw in ["short", PW + "'", PW + "\\", PW + " ", None]:
            with self.assertRaises(ValueError):
                velo.ensure("anna", pw, ["investigator"])
        for roles in (["investigator'"], ["nosuchrole"], [], None):
            with self.assertRaises(ValueError):
                velo.ensure("anna", PW, roles)
        velo.org_list = lambda: [("root", "root"), ("O1']", "evil")]
        with self.assertRaises(ValueError):
            velo.ensure("anna", PW, ["investigator"])
        self.assertEqual(self.fake.vql, [], "nothing reached Velociraptor")

    def test_password_never_printed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            velo.ensure("anna", PW, ["investigator"])
            velo.disable("anna")
            try:
                velo.ensure("anna", PW + "'", ["investigator"])
            except ValueError as e:
                print(e)
        self.assertNotIn(PW, out.getvalue())

    def test_password_is_sent_only_when_new(self):
        # Velociraptor logs every API query in full: a routine pass must not
        # carry the password, only the first creation (or re-enable) does.
        velo.ensure("anna", PW, ["investigator", "artifact_writer"])
        self.fake.vql.clear()
        velo.ensure("anna", PW, ["administrator"], set_password=False)
        self.assertFalse(any(PW in q for q in self.fake.vql))
        self.assertEqual(set(map(tuple, self.fake.users["anna"]["orgs"].values())), {("administrator",)})
        self.fake.users.clear()               # deleted by hand inside Velociraptor
        velo.ensure("anna", PW, ["investigator"], set_password=False)
        self.assertIn("anna", self.fake.users, "a vanished account is made again")

    def test_reserved_and_auth_value(self):
        self.assertTrue({"api", "admin"} <= velo.RESERVED)
        self.assertEqual(len(velo.RESERVED), 3)
        v = velo.auth_value("anna", PW)
        self.assertEqual(base64.b64decode(v[len("Basic "):]).decode(), f"anna:{PW}")
        self.assertIsNone(velo.auth_value("anna", None))


if __name__ == "__main__":
    unittest.main()
