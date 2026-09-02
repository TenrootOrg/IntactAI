"""Pytest wrapper for the chat in-flight-turn regression harness.

The assertions live in tests/chat_inflight_turn.js because the code under test
is browser JavaScript inside cases.html, and the harness evaluates the SHIPPED
function bodies rather than a Python re-description of them. This wrapper just
makes it run with the rest of the suite.
"""
import os
import shutil
import subprocess
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HARNESS = os.path.join(_ROOT, "tests", "chat_inflight_turn.js")


class ChatInFlightTurn(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_an_in_flight_question_survives_a_tab_switch(self):
        r = subprocess.run(["node", _HARNESS, _ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0,
                         f"chat harness failed:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
