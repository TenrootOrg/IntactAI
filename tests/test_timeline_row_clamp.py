"""A timeline row is one line, with "⌄ more" on click like the evidence under it.

QA: a recurring detection's span, count and host list wrapped one entry onto two
lines. Drives the page's own mdToHtml — see tests/timeline_row_clamp.js.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class TimelineRowsClampToOneLine(unittest.TestCase):
    def test_harness(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "timeline_row_clamp.js"),
                            os.path.join(ROOT, "modules/nginx/html/cases.html")],
                           capture_output=True, text=True)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
