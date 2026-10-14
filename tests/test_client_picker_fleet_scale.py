"""The shared client picker at 1,000 endpoints (fleet-scale audit F31).

It pre-ticked every online client and rebuilt the whole list (~700 KB of HTML)
on every keystroke. tests/client_picker_fleet_scale.js drives the real
Forensics partial and component in jsdom with 1,000 clients.
"""

import os
import re
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

    def test_the_forensics_box_is_taller_and_the_class_exists(self):
        """max-h-48 showed ~6 of 1,000 hosts (F35). Tailwind is prebuilt: a class
        missing from css/tailwind.css silently does nothing."""
        html = os.path.join(ROOT, "modules", "nginx", "html")
        with open(os.path.join(html, "partials", "velociraptor.html"), encoding="utf-8") as f:
            box = re.search(r'id="forensics-client-list" class="([^"]*)"', f.read()).group(1)
        size = re.search(r"\bmax-h-(\d+)\b", box)
        self.assertIsNotNone(size, box)
        self.assertGreater(int(size.group(1)), 48)
        with open(os.path.join(html, "css", "tailwind.css"), encoding="utf-8") as f:
            self.assertIn(".max-h-%s{" % size.group(1), f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
