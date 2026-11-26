"""Two-step login (TOTP) screens: login.html's code step and setup screen, the
user menu, the re-auth prompt and the fetch hook.

tests/mfa_page.js runs the real login.html (with the vendored QR library) and
the index.html user menu with js/active-case.js, js/access.js and Alpine in
jsdom against a mocked backend: password -> code -> signed in, a wrong code
stays, mfa_expired goes back, must_enroll opens setup with a local QR, the
secret and the recovery codes once, the clock warning at 120 s skew only, and
the re-auth prompt asks for the code when two-step login is on.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MfaPage(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_mfa_page(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "mfa_page.js"), ROOT],
                           capture_output=True, text=True, timeout=90)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_qr_library_is_vendored_not_fetched(self):
        # Air-gapped boxes: the QR is drawn by a file in the repo, never a CDN.
        html = os.path.join(ROOT, "modules", "nginx", "html")
        with open(os.path.join(html, "js", "vendor", "qrcode.js"), encoding="utf-8") as f:
            lib = f.read()
        self.assertIn("qrcode-generator@1.4.4", lib)
        self.assertIn("Licensed under the MIT license", lib)
        with open(os.path.join(html, "login.html"), encoding="utf-8") as f:
            page = f.read()
        self.assertIn('<script src="js/vendor/qrcode.js?v=', page)
        self.assertNotRegex(page, r'(src|href)="(https?:)?//')


if __name__ == "__main__":
    unittest.main()
