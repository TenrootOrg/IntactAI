"""services/tool_accounts: the reconciler that keeps one account per Intact user
inside every bundled tool, and the encrypted vault of generated passwords.

Runs the real reconciler and vault against a throwaway SQLite DB and key file,
with a fake provider standing in for a tool (the real providers are tested in
tests/test_tool_accounts_<tool>.py).
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
_BASE = tempfile.mkdtemp(prefix="intact-toolacct-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_CLOUD_KEY_PATH"] = os.path.join(_BASE, "state", "backend", "cloud_secrets.key")
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
from services import users  # noqa: E402
import services.tool_accounts as ta  # noqa: E402
from services.tool_accounts import vault  # noqa: E402


class FakeTool(types.SimpleNamespace):
    """Records calls; `accounts` is the tool's own user list."""


def fake(fail=False):
    t = FakeTool(TOOL="fake", NEEDS_PASSWORD=True, RESERVED={"tenroot"}, accounts={}, calls=[])
    t.tool_role = lambda r: {"superadmin": "boss", "admin": "member", "operator": "member"}.get(r)

    def ensure(u, pw, role, set_password=True):
        t.calls.append(("ensure", u, role, set_password))
        if fail:
            raise RuntimeError("tool down")
        t.accounts[u] = {"pw": pw, "role": role, "enabled": True}

    def disable(u):
        t.calls.append(("disable", u))
        if u in t.accounts:
            t.accounts[u]["enabled"] = False

    t.ensure, t.disable = ensure, disable
    t.auth_value = lambda u, pw: f"Basic {u}:{pw}"
    return t


class Reconciler(unittest.TestCase):
    def setUp(self):
        users.ensure_table()
        vault.ensure_table()
        c = users.get_connection()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM tool_accounts")
        c.commit()
        users.invalidate()
        vault._invalidate()
        self.tool = fake()
        ta._providers = {"fake": self.tool}
        self.boss = users.create("tenroot", "h", users.SUPERADMIN, "t", False)
        self.op = users.create("anna", "h", users.OPERATOR, "t", False)
        self.ro = users.create("rita", "h", users.READONLY, "t", False)

    def test_accounts_follow_the_users_table(self):
        ta.reconcile_all()
        self.assertEqual(set(self.tool.accounts), {"tenroot-intact", "anna"},
                         "reserved name mapped; Read-only gets no account")
        self.assertEqual(self.tool.accounts["tenroot-intact"]["role"], "boss")
        pw = self.tool.accounts["anna"]["pw"]
        self.assertGreaterEqual(len(pw), 40)
        ta.reconcile_all()
        self.assertEqual(self.tool.accounts["anna"]["pw"], pw, "stable across passes")

    def test_password_is_sent_only_when_new(self):
        ta.reconcile_all()
        ta.reconcile_all()
        sets = [c[3] for c in self.tool.calls if c[0] == "ensure" and c[1] == "anna"]
        self.assertEqual(sets, [True, False])

    def test_a_failing_recheck_keeps_a_working_account(self):
        # A tool still starting after an upgrade must not cost people their sign-in.
        ta.reconcile_all()
        ta._providers = {"fake": fake(fail=True)}
        ta.reconcile_all()
        row = vault.get("anna", "fake")
        self.assertEqual(row["state"], "ok")
        self.assertIn("tool down", row["error"])
        self.assertIsNotNone(ta.auth_value(users.get(self.op), "fake"))

    def test_drift_is_reverted(self):
        ta.reconcile_all()
        self.tool.accounts["anna"]["role"] = "boss"      # raised by hand inside the tool
        ta.reconcile_all()
        self.assertEqual(self.tool.accounts["anna"]["role"], "member")

    def test_disable_demote_and_reenable(self):
        ta.reconcile_all()
        old = self.tool.accounts["anna"]["pw"]
        users.set_role(self.op, users.READONLY)
        ta.reconcile_all()
        self.assertFalse(self.tool.accounts["anna"]["enabled"])
        self.assertIsNone(vault.get("anna", "fake"), "the old password is forgotten")
        users.set_role(self.op, users.OPERATOR)
        ta.reconcile_all()
        self.assertTrue(self.tool.accounts["anna"]["enabled"])
        self.assertNotEqual(self.tool.accounts["anna"]["pw"], old, "fresh password on re-enable")
        users.set_enabled(self.op, False)
        ta.reconcile_all()
        self.assertFalse(self.tool.accounts["anna"]["enabled"])

    def test_removed_user_loses_the_tool_account(self):
        ta.reconcile_all()
        users._write("DELETE FROM users WHERE id = ?", (self.op,))
        ta.reconcile_all()
        self.assertFalse(self.tool.accounts["anna"]["enabled"])
        self.assertIsNone(vault.get("anna", "fake"))

    def test_auth_value_only_for_a_working_account(self):
        row = users.get(self.op)
        self.assertIsNone(ta.auth_value(row, "fake"), "not made yet")
        ta.reconcile_all()
        self.assertTrue(ta.auth_value(row, "fake").startswith("Basic anna:"))
        self.assertIsNone(ta.auth_value(row, "nosuch"))

    def test_a_failing_tool_is_recorded_not_fatal(self):
        ta._providers = {"fake": fake(fail=True)}
        out = ta.reconcile_all()
        self.assertTrue(out["anna"]["fake"].startswith("error"))
        self.assertEqual(vault.get("anna", "fake")["state"], "error")
        self.assertIsNone(ta.auth_value(users.get(self.op), "fake"))
        self.assertEqual(ta.status()["last_run"]["errors"], 2)

    def test_passwords_are_encrypted_at_rest(self):
        ta.reconcile_all()
        pw = self.tool.accounts["anna"]["pw"]
        raw = sqlite3.connect(os.path.join(_BASE, "intact.db")).execute(
            "SELECT secret FROM tool_accounts WHERE username='anna'").fetchone()[0]
        self.assertNotIn(pw, raw)
        self.assertNotIn(pw, str(ta.status()), "status never carries a secret")

    def test_user_changes_wake_the_reconciler_but_logins_do_not(self):
        hits = []
        users.on_change.append(lambda: hits.append(1))
        try:
            users.touch_login(self.op)
            self.assertEqual(hits, [])
            users.set_role(self.op, users.ADMIN)
            self.assertEqual(hits, [1])
        finally:
            users.on_change.pop()


if __name__ == "__main__":
    unittest.main()
