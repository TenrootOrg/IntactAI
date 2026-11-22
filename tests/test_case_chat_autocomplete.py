"""Case Analysis chat autocomplete: the names it offers and how it completes.

Drives the REAL _acTerms/_acMatch from cases.html (tests/case_chat_autocomplete.js):
names come only from the case's own hosts and identities (hidden and excluded
hosts never), and the last word typed is completed case-insensitively, after
DOMAIN\\ too.
"""
import os
import shutil
import subprocess
import unittest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "case_chat_autocomplete.js")


class CaseChatAutocomplete(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_names_and_completion(self):
        r = subprocess.run(["node", HARNESS], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
        self.assertIn("ok", r.stdout)


if __name__ == "__main__":
    unittest.main()
