"""services/tool_accounts/volweb.py: the VolWeb provider.

docker exec and VolWeb's HTTP API are faked; the live check is done by hand on
a box (see the provider's docstring).
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Keeps _volweb_base() off the box's frontend config (the real DB).
os.environ["VOLWEB_BASE_URL"] = "http://volweb.test:8000"

import _optional_deps  # noqa: F401,E402
from services.tool_accounts import volweb  # noqa: E402

SECRET = "s3cr3t-'\"$(x)-pw"


class FakeRun:
    def __init__(self, rc=0, out="VW_OK\n"):
        self.calls, self.rc, self.out = [], rc, out

    def __call__(self, cmd, input=None, env=None, **kw):
        self.calls.append({"cmd": cmd, "input": input, "env": env})
        return mock.Mock(returncode=self.rc, stdout=self.out, stderr="")


def resp(status=200, access="tok1"):
    return mock.Mock(status_code=status, json=lambda: {"access": access, "refresh": "r"})


class VolwebProvider(unittest.TestCase):
    def setUp(self):
        volweb._cache.clear()
        self.run = FakeRun()
        p = mock.patch.object(volweb.subprocess, "run", self.run)
        p.start()
        self.addCleanup(p.stop)

    def test_roles(self):
        for r in ("superadmin", "admin", "operator"):
            self.assertEqual(volweb.tool_role(r), "superuser")
        self.assertIsNone(volweb.tool_role("readonly"))
        self.assertTrue({"admin", "user"} <= volweb.RESERVED)

    def test_secrets_never_in_argv_or_script(self):
        volweb.ensure("anna", SECRET, "superuser")
        c = self.run.calls[0]
        self.assertNotIn(SECRET, " ".join(c["cmd"]))
        self.assertNotIn("anna", " ".join(c["cmd"]))
        self.assertNotIn(SECRET, c["input"])
        self.assertEqual(c["env"]["_VW_PASSWORD"], SECRET)
        self.assertEqual(c["env"]["_VW_USER"], "anna")
        self.assertIn("_VW_PASSWORD", c["cmd"])      # passed by name: -e _VW_PASSWORD

    def test_failed_shell_raises(self):
        self.run.out = "Traceback ..."
        with self.assertRaises(RuntimeError):
            volweb.ensure("anna", SECRET, "superuser")

    def test_token_cached_8_minutes_then_refetched(self):
        post = mock.Mock(side_effect=[resp(access="tok1"), resp(access="tok2")])
        clock = [1000.0]
        with mock.patch.object(volweb.requests, "post", post), \
                mock.patch.object(volweb.time, "monotonic", lambda: clock[0]):
            self.assertEqual(volweb.auth_value("anna", SECRET), "Bearer tok1")
            clock[0] += 7 * 60
            self.assertEqual(volweb.auth_value("anna", SECRET), "Bearer tok1")
            self.assertEqual(post.call_count, 1)
            clock[0] += 2 * 60
            self.assertEqual(volweb.auth_value("anna", SECRET), "Bearer tok2")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args.kwargs["timeout"], 3)
        self.assertTrue(post.call_args.args[0].endswith("/core/token/"))

    def test_new_password_refetches(self):
        post = mock.Mock(side_effect=[resp(access="a"), resp(access="b")])
        with mock.patch.object(volweb.requests, "post", post):
            volweb.auth_value("anna", "pw1")
            self.assertEqual(volweb.auth_value("anna", "pw2"), "Bearer b")

    def test_failure_is_remembered_briefly(self):
        # VolWeb down: one failed login per FAIL_TTL, not one 3 s wait per request.
        down = mock.Mock(side_effect=OSError("down"))
        with mock.patch.object(volweb.requests, "post", down):
            self.assertIsNone(volweb.auth_value("anna", SECRET))
            self.assertIsNone(volweb.auth_value("anna", SECRET))
        self.assertEqual(down.call_count, 1)
        volweb._cache["anna"] = (SECRET, None, 0)            # FAIL_TTL passed
        with mock.patch.object(volweb.requests, "post", mock.Mock(return_value=resp(401))):
            self.assertIsNone(volweb.auth_value("anna", SECRET))
        with mock.patch.object(volweb.requests, "post", mock.Mock(return_value=resp())):
            self.assertIsNone(volweb.auth_value("anna", SECRET), "still inside the new FAIL_TTL")
            self.assertTrue(volweb.auth_value("anna", "new-pw").startswith("Bearer"),
                            "a new password is tried at once")

    def test_disable_blacklists_and_forgets(self):
        with mock.patch.object(volweb.requests, "post", mock.Mock(return_value=resp())):
            volweb.auth_value("anna", SECRET)
        self.assertIn("anna", volweb._cache)
        volweb.disable("anna")
        self.assertNotIn("anna", volweb._cache)
        script = self.run.calls[-1]["input"]
        self.assertIn("BlacklistedToken", script)
        self.assertIn("is_active = False", script)
        self.assertIn("set_unusable_password", script)
        self.assertNotIn("delete", script)


if __name__ == "__main__":
    unittest.main()
