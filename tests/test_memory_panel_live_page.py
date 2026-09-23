"""The Memory panel, driven in a real DOM against a live appliance.

Written after a layered run (plugins + YARA -- the box the UI ships ticked)
failed on the operator's FIRST click while every test here was green. The
reason it was green: every run I had dispatched by hand was plugins-only, and
the page is what turns "blueprint + Include YARA" into a mode. The request the
page builds was the one thing nothing covered.

tests/memory_panel_live_page.js boots index.html with the real partial loader,
the real Alpine store and the real partials, clicks each of the four tabs, and
presses each button:

  * every blueprint/checkbox combination produces the expected mode
  * Acquire sends client_id + mode + keep_dump and no dump_path
  * Analyze-this-image sends dump_path and NO client_id (the server refuses both)
  * the keep checkbox is hidden where the server forces the keep, and the whole
    settings card is hidden on the tab that runs nothing
  * a refusal from the server is surfaced on the page, in red
  * nothing the panel binds to is undefined at runtime

The two calls that would start real work are intercepted, not relayed: this
test is about what the page sends. What the backend does with it is
tests/test_memory_*.py.

Needs a live appliance and jsdom, so it skips everywhere else -- run it on the
box before shipping a change to the panel.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "memory_panel_live_page.js")
PAGE = os.path.join(ROOT, "modules", "nginx", "html", "index.html")
CONTAINER = os.environ.get("INTACT_BACKEND", "intact_backend")


def _backend_is_up():
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _has_jsdom():
    r = subprocess.run(["node", "-e", "require.resolve('jsdom')"],
                       capture_output=True, text=True, cwd=ROOT)
    return r.returncode == 0


class TheOperatorsClicksOnALiveAppliance(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_every_tab_and_button_does_what_it_says(self):
        if not _backend_is_up():
            self.skipTest(f"{CONTAINER} is not running — this one needs a live appliance")
        if not _has_jsdom():
            self.skipTest("jsdom is not installed (npm i jsdom)")
        r = subprocess.run(["node", HARNESS, PAGE], capture_output=True, text=True,
                           timeout=600, cwd=ROOT)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
