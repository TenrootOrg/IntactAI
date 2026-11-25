"""services/tool_accounts/timesketch.py: the Timesketch provider (header SSO).

The docker-exec layer is faked: what is checked is the role mapping, the
reserved names, that a user name reaches the container only as an argv entry
(validated, never through a shell), and how the in-container result is read.
The in-container script itself was run against the live box (see the
provider's docstring for the timing).
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-toolacct-ts-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
# config.load_main_config reads the box's real config.yaml; a stand-in, set
# before the provider computes RESERVED at import.
import config as _config  # noqa: E402
_config.load_main_config = lambda: {"modules": {"timesketch": {"id": "Boss"}}}
_config.TIMESKETCH_CONFIG = dict(_config.TIMESKETCH_CONFIG, username="apiuser")

from services.tool_accounts import timesketch as ts  # noqa: E402
import services.tool_accounts as ta  # noqa: E402


def _done(out=None, rc=0, stderr=""):
    stdout = "noise from create_app\n"
    if out is not None:
        stdout += "INTACT-RESULT " + json.dumps(out) + "\n"
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class Provider(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.reply = _done({"created": True, "granted": 4, "sketches": 2,
                            "exists": True, "admin": False, "in_group": True})

        def fake_run(argv, **kw):
            self.calls.append((argv, kw))
            return self.reply

        p = mock.patch.object(ts.subprocess, "run", side_effect=fake_run)
        p.start()
        self.addCleanup(p.stop)

    def test_contract(self):
        self.assertEqual(ts.TOOL, "timesketch")
        self.assertFalse(ts.NEEDS_PASSWORD)
        self.assertEqual(ts.auth_value("anna", None), "anna", "nginx puts the name into the header")

    def test_role_mapping(self):
        self.assertEqual(ts.tool_role("superadmin"), "admin")
        self.assertEqual(ts.tool_role("admin"), "admin")
        self.assertEqual(ts.tool_role("operator"), "user")
        self.assertIsNone(ts.tool_role("readonly"))

    def test_reserved_names_are_the_install_admin_and_the_api_user(self):
        self.assertEqual(ts.RESERVED, {"boss", "apiuser"})
        self.assertEqual(ta.tool_user_for(ts, "boss"), "boss-intact")
        self.assertEqual(ta.tool_user_for(ts, "anna"), "anna")

    def test_reserved_falls_back_to_tenroot(self):
        with mock.patch.object(_config, "load_main_config", side_effect=OSError("gone")):
            self.assertIn("tenroot", ts._reserved())
        with mock.patch.object(_config, "load_main_config", return_value={}):
            self.assertIn("tenroot", ts._reserved())

    def test_ensure_is_one_exec_with_argv_only(self):
        out = ts.ensure("anna", None, "user")
        self.assertEqual(out["granted"], 4)
        self.assertEqual(len(self.calls), 1, "one docker exec per ensure")
        argv, kw = self.calls[0]
        self.assertEqual(argv, ["docker", "exec", "-i", "intact_timesketch_web", "python3", "-",
                                "ensure", "anna", "user", "intact-team"])
        self.assertNotIn("shell", kw)
        self.assertIn("create_app", kw["input"], "the script goes on stdin")
        self.assertTrue(kw.get("timeout"))

    def test_disable(self):
        ts.disable("anna")
        self.assertEqual(self.calls[0][0][6:8], ["disable", "anna"])

    def test_bad_names_never_reach_docker(self):
        for bad in ("", "Anna", "a b", "a;rm -rf /", "$(id)", "a'b", "-rf", "x" * 65, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ts.ensure(bad, None, "user")
            with self.assertRaises(ValueError):
                ts.disable(bad)
        self.assertEqual(self.calls, [])

    def test_unknown_role_refused(self):
        with self.assertRaises(ValueError):
            ts.ensure("anna", None, "superuser")
        self.assertEqual(self.calls, [])

    def test_no_result_line_is_an_error_with_the_last_stderr_line(self):
        self.reply = _done(None, rc=1, stderr="Traceback\nOperationalError: db down\n")
        with self.assertRaises(RuntimeError) as cm:
            ts.ensure("anna", None, "admin")
        self.assertIn("OperationalError: db down", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
