"""Text an endpoint or an operator controls must stay data.

1. The client picker put endpoint-reported OS/label text into the page raw, and
   escapeHtml left quotes alone, so a hostname could close an attribute and add an
   event handler. tests/client_picker_endpoint_text.js renders the real picker in
   jsdom with a booby-trapped host (it created an <img onerror> before the fix).
"""
import os
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: E402



class ClientPickerShowsEndpointTextAsText(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_booby_trapped_host_os_and_label(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "client_picker_endpoint_text.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
