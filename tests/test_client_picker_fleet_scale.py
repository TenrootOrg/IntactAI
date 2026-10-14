"""The shared client picker at 1,000 endpoints (fleet-scale audit F31).

It pre-ticked every online client and rebuilt the whole list (~700 KB of HTML)
on every keystroke. tests/client_picker_fleet_scale.js drives the real
Forensics partial and component in jsdom with 1,000 clients.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ClientPickerFleetScale(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_real_picker_at_1000_clients(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "client_picker_fleet_scale.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
