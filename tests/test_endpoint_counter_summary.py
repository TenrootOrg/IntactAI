"""Dashboard endpoint counter uses /api/clients/summary (fleet-scale audit F36).

Every open tab pulled the whole fleet every 10 s to show two numbers.
tests/endpoint_counter_summary.js runs the real services store and Alpine in
jsdom: summary first, the full list only when the route 404s (older backend).
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class EndpointCounterSummary(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_counter_reads_the_summary(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "endpoint_counter_summary.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
