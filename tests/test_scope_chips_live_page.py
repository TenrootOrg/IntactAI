"""The Scope row above the report, driven the way the operator drives it.

QA TASK-12679: entering a timeframe used to be a one-way door. The way back is a
row of chips built inside renderReport's innerHTML and clicked through the page's
own fetch + redraw — neither of which a fake-DOM harness can see.

tests/scope_chips_live_page.js runs the REAL page in jsdom against a REAL backend
on a throwaway case it creates and deletes. Needs a live appliance, so it skips
everywhere else.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "scope_chips_live_page.js")
PAGE = os.path.join(ROOT, "modules", "nginx", "html", "cases.html")
CONTAINER = os.environ.get("INTACT_BACKEND", "intact_backend")


def _backend_is_up():
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _has_jsdom():
    return subprocess.run(["node", "-e", "require.resolve('jsdom')"],
                          capture_output=True, text=True, cwd=ROOT).returncode == 0


class TheWayBackIsOnScreen(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_chips_render_and_a_click_switches_the_case(self):
        if not _backend_is_up():
            self.skipTest(f"{CONTAINER} is not running — this one needs a live appliance")
        if not _has_jsdom():
            self.skipTest("jsdom is not installed (npm i jsdom@24)")
        r = subprocess.run(["node", HARNESS, PAGE], capture_output=True, text=True,
                           timeout=600, cwd=ROOT)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
