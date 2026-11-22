"""Case Analysis: the "further windows" card under the phases.

It used to say "Accounting row -- the windows not analysed individually. Not a
scope." with nothing to click. Drives the REAL _ztRest from cases.html
(tests/zoom_rest_card.js): it says what the windows are and lists them on
demand, each with its own "Analyze"; a capped list says so; a card without a
list (an older backend) promises none.
"""
import os
import shutil
import subprocess
import unittest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zoom_rest_card.js")


class ZoomRestCard(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_card_explains_and_lists_its_windows(self):
        r = subprocess.run(["node", HARNESS], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
        self.assertIn("ok", r.stdout)


if __name__ == "__main__":
    unittest.main()
