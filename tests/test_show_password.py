"""Setup and login let the operator see what they typed.

Setup asks for a 12+ character password twice and refuses a mismatch it does not
show. js/show-password.js gives every password field on setup.html and login.html
its own Show/Hide toggle; tests/show_password_page.js runs the real pages in jsdom.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ShowPassword(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_every_password_field_can_be_shown(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "show_password_page.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
