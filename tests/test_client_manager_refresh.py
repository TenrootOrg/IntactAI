"""Every module's client list can be refreshed in place.

The Velociraptor collection, Timesketch, Memory and Scheduler pickers all use
one component, js/utils/client-manager.js, and none could reload the fleet: a
client enrolled or brought online after the page opened was invisible until a
full page reload. tests/client_manager_refresh.js runs the real component
against a fake page and checks that a refresh keeps facets, search and
selection, drops clients that no longer exist, never wipes the list on a
failure, and ignores repeat clicks.
"""

import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules", "nginx", "html")


class ClientListRefresh(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_real_component_refreshes_safely(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "client_manager_refresh.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_every_client_picker_uses_the_shared_component(self):
        """A picker built another way would not get the button."""
        js = os.path.join(HTML, "js")
        users = set()
        for dirpath, _dirs, files in os.walk(js):
            for name in files:
                if name.endswith(".js") and "client-manager" not in name:
                    with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                        if "new ClientManager(" in f.read():
                            users.add(name)
        for expected in ("blueprints-forensics.js", "timesketch.js", "memory.js", "scheduler.js"):
            self.assertIn(expected, users)

    def test_refresh_sits_beside_select_all_in_every_multi_select_picker(self):
        """Reported: the button was in the component's own bar, which only appears
        once the list has loaded, so nobody saw it while "Loading clients..." was up."""
        pickers = {
            os.path.join(HTML, "partials", "velociraptor.html"): "forensicsClientManager.refresh(this)",
            os.path.join(HTML, "partials", "timesketch.html"): "timesketchClientManager.refresh(this)",
            os.path.join(HTML, "index.html"): "schedulerClientManager.refresh(this)",
        }
        for path, call in pickers.items():
            with open(path, encoding="utf-8") as f:
                src = f.read()
            self.assertIn(call, src, path)
            around = src[src.index(call):src.index(call) + 600]
            self.assertIn("Select All", around, f"{path}: Refresh is not beside Select All")

    def test_the_velociraptor_page_does_not_wait_for_blueprints_before_clients(self):
        with open(os.path.join(HTML, "js", "blueprints-forensics.js"), encoding="utf-8") as f:
            src = f.read()
        body = src[src.index("async function initForensicsTab"):src.index("async function loadForensicsHuntLabels")]
        self.assertLess(body.index("forensicsClientManager.load()"), body.index("await loadBlueprints('forensics')"))

    def test_the_browser_loads_the_new_version(self):
        with open(os.path.join(HTML, "index.html"), encoding="utf-8") as f:
            m = re.search(r"js/utils/client-manager\.js\?v=(\d+)", f.read())
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(1)), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
