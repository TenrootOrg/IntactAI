"""Timesketch "Start" sends the picker's selection (fleet-scale audit F30).

It read the ticked boxes on screen, so a client hidden by a filter was silently
dropped, and its confirm listed every hostname (~15 KB at 1,000 hosts), pushing
the settings off-screen. tests/timesketch_start_selection.js drives the real
partial and scripts in jsdom.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TimesketchStartSelection(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_start_sends_hidden_selected_clients(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "timesketch_start_selection.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
