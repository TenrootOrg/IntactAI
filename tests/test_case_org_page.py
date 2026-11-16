"""The Velociraptor org belongs to the case, not to a page.

A case is attached to one org when it is opened (editable later); the top bar
shows it next to the case and every module page uses it, with no org dropdown
anywhere. tests/case_org_page.js runs the real js/active-case.js and
client-manager.js in jsdom.
"""

import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules", "nginx", "html")


class CaseOrgPage(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_org_follows_the_active_case(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "case_org_page.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_no_page_has_an_org_dropdown(self):
        for dirpath, _dirs, files in os.walk(HTML):
            for name in files:
                if name.endswith((".html", ".js")) and name != "alpine.min.js":
                    with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                        src = f.read()
                    self.assertNotIn("velo-org-select", src, name)
                    self.assertNotIn("VeloOrg.set(", src, name)
                    self.assertIsNone(re.search(r"X-Velo-Org", src), name)


if __name__ == "__main__":
    unittest.main()
