"""AWS + Azure scan pages: the time window an operator picks is what the scan request carries.

Runs tests/cloud_time_window_live_page.js -- the real partials, flatpickr, the shared
cloud-datepickers.js and Alpine, reads relayed to the live backend, "Start scan"
intercepted -- and checks the defaults, a calendar pick, a typed time, an open end
and the three refusals (no start, not a date, end before start).

Needs a live appliance and jsdom (NODE_PATH to a jsdom@24 install), so it skips
everywhere else -- run it on the box before shipping a change to either page.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "cloud_time_window_live_page.js")
HTML = os.path.join(ROOT, "modules", "nginx", "html")
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


class TheOperatorsTimeWindowReachesTheScan(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_both_pages_send_what_was_picked(self):
        if not _backend_is_up():
            self.skipTest(f"{CONTAINER} is not running — this one needs a live appliance")
        if not _has_jsdom():
            self.skipTest("jsdom is not installed (npm i jsdom, or set NODE_PATH)")
        r = subprocess.run(["node", HARNESS, HTML], capture_output=True, text=True,
                           timeout=300, cwd=ROOT)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
