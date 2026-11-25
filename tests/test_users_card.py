"""Settings -> Users, the role-based hiding and the re-auth prompt.

tests/users_card_page.js runs the real Users panel from partials/settings.html
with js/active-case.js, js/access.js, js/components/users-card.js and Alpine in
jsdom against a mocked backend: hidden for an Operator, no actions on your own
or the Super-admin's row, the one-time password shown once after a 403
reauth_required -> password -> retry, a 403 forbidden as a toast.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UsersCard(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_users_card(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "users_card_page.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
