"""A finished fuse must reach the open case with no reload and no click.

"Every time the fusion finishes the report must update automatically, no matter
what." It did not. The page polled ONLY while a report was generating, and only
once the Analysis tab had been drawn during it -- so the single case that
refreshed itself was a report this browser had started, which made it look like
the rule. A fuse from anywhere else (another operator's Refusion, the automatic
re-fuse after new data lands, a disposition or timeline edit in a second tab)
left the case showing the PREVIOUS report until somebody reloaded.

tests/case_auto_refresh.js drives the REAL page in a real DOM against a REAL
backend and starts a fuse from OUTSIDE the browser -- the case the old poll could
not see -- then checks the view catches up on its own. It also checks the other
half, which making the poll always-on created: a background redraw must never
land on top of someone typing, and must deliver once they stop.

Needs a live appliance, so it skips everywhere else. Works on a throwaway case it
creates and deletes.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "case_auto_refresh.js")
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


class AFinishedFuseReachesTheScreenByItself(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_it(self):
        if not _backend_is_up():
            self.skipTest(f"{CONTAINER} is not running — this one needs a live appliance")
        if not _has_jsdom():
            self.skipTest("jsdom is not installed (npm i jsdom@24)")
        r = subprocess.run(["node", HARNESS, PAGE], capture_output=True, text=True,
                           timeout=900, cwd=ROOT)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


class ThePollIsNotConditionalOnAReportGenerating(unittest.TestCase):
    """Static guard: the whole defect was the poll only existing during
    generation. If it ever goes back to that, this fails without an appliance."""

    def setUp(self):
        with open(PAGE, encoding="utf-8") as fh:
            self.page = fh.read()

    def test_render_starts_the_poll_for_every_case(self):
        start = self.page.index("function render(info,md,g){")
        body = self.page[start:start + 1200]
        self.assertIn("pollReportGen(info.case_id)", body,
                      "render() must start the poll for any case on screen, whatever "
                      "tab — not only when the Analysis tab sees a generating report")

    def test_the_poll_compares_the_fuse_stamp(self):
        start = self.page.index("function pollReportGen(id){")
        body = self.page[start:self.page.index("function _reportBody", start)
                         if "function _reportBody" in self.page[start:] else start + 4000]
        self.assertIn("fused_at", body,
                      "the poll must compare fused_at, or a re-fuse that reuses the "
                      "existing narrative goes unnoticed")

    def test_every_automatic_refresh_goes_through_the_typing_guard(self):
        start = self.page.index("function pollReportGen(id){")
        body = self.page[start:start + 4000]
        self.assertNotIn("openCase(id);", body,
                         "the poll must refresh via backgroundRefresh(), which holds "
                         "off while the operator is typing — a bare openCase() here "
                         "throws away a half-typed field")
        self.assertIn("backgroundRefresh(id", body)

    def test_the_backend_stamps_every_fuse(self):
        with open(os.path.join(ROOT, "modules/backend/services/fusion/store.py"),
                  encoding="utf-8") as fh:
            store = fh.read()
        self.assertIn('"fused_at": _now_iso()', store)
        with open(os.path.join(ROOT, "modules/backend/routes/case_routes.py"),
                  encoding="utf-8") as fh:
            routes = fh.read()
        self.assertIn('"fused_at": d.get("fused_at")', routes,
                      "the case payload must carry it or the page cannot compare it")


if __name__ == "__main__":
    unittest.main(verbosity=2)
