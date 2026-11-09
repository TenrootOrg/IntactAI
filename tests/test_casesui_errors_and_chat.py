"""Wrapper so tests/test_casesui_errors_and_chat.js runs with the suite.

The code under test is browser JavaScript inside cases.html; the harness
evaluates the shipped function bodies (no live appliance needed).
"""
import os
import shutil
import subprocess
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HARNESS = os.path.join(_ROOT, "tests", "test_casesui_errors_and_chat.js")


class CasesUiErrorsAndChat(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_error_replies_and_cross_case_chat(self):
        r = subprocess.run(["node", _HARNESS, _ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0,
                         f"casesui harness failed:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
