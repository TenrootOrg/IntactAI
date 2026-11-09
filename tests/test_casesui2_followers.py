"""Wrapper so tests/test_casesui2_followers.js runs with the suite.

The code under test is browser JavaScript inside cases.html; the harness
evaluates the shipped function bodies (no live appliance needed).
"""
import os
import shutil
import subprocess
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HARNESS = os.path.join(_ROOT, "tests", "test_casesui2_followers.js")


class CasesUiFollowers(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_followers_retry_and_pause_when_hidden(self):
        r = subprocess.run(["node", _HARNESS, _ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0,
                         f"casesui2 harness failed:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
