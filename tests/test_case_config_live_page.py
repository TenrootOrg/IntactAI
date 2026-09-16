"""The Case Analysis config rail, driven the way the operator drives it.

"Change the time window, run a Fusion, go to the Log or refresh -- the window is
back to what it was." Three fixes passed tests/case_config_persist.js and still
failed on the appliance, because that harness fakes the DOM: no flatpickr, no
innerHTML re-parse, no 5s report poll, no sessionStorage view memo, no
active-case re-open. Everything the failure actually ran through.

tests/case_config_live_page.js runs the REAL page in jsdom against a REAL
backend and repeats the operator's sequence on a throwaway case it creates and
deletes: open -> pick a date in the calendar -> two background refreshes ->
Refusion -> follow the page to the Log and back -> reload the page.

It needs a live appliance, so it skips everywhere else -- run it on the box
before shipping a change to the rail.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "case_config_live_page.js")
PAGE = os.path.join(ROOT, "modules", "nginx", "html", "cases.html")
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


class TheOperatorsSequenceOnALiveAppliance(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_window_survives_the_whole_round_trip(self):
        if not _backend_is_up():
            self.skipTest(f"{CONTAINER} is not running — this one needs a live appliance")
        if not _has_jsdom():
            self.skipTest("jsdom is not installed (npm i jsdom@24)")
        r = subprocess.run(["node", HARNESS, PAGE], capture_output=True, text=True,
                           timeout=600, cwd=ROOT)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
