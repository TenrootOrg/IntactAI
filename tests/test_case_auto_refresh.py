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


class OpeningACaseRedrawsOnce(unittest.TestCase):
    """A second redraw a fraction of a second after the first can swallow a click.

    openCase shows the remembered view immediately, then compares the payload
    that arrives against it and skips the redraw when nothing changed. That
    comparison was dead: the snapshot was taken AFTER showCase, which mutates
    `info` by folding in five report-meta keys the case payload never carries.
    So `same` was never true and every re-open replaced #main twice — the second
    landing where the operator was already clicking. A node replaced between
    mousedown and mouseup fires no click at all, which is how a tab "does
    nothing until the second try".
    """

    def setUp(self):
        with open(PAGE, encoding="utf-8") as fh:
            self.page = fh.read()
        self.open_case = self.page[self.page.index("function openCase(id){"):
                                   self.page.index("function showCase(id,info,rep){")]

    def test_the_snapshot_is_taken_before_showCase_mutates_it(self):
        self.assertLess(self.open_case.index("shown=JSON.stringify"),
                        self.open_case.index("showCase(id,v.info"),
                        "snapshot the remembered view BEFORE showing it — showCase "
                        "mutates `info`, and a snapshot taken afterwards can never "
                        "equal the raw payload the network returns")

    def test_the_keys_showCase_adds_are_still_absent_from_the_payload(self):
        """If the backend ever starts serving these, the ordering above stops
        mattering — and this test should be the thing that says so."""
        import re
        show = self.page[self.page.index("function showCase(id,info,rep){"):
                         self.page.index("function render(info,md,g){")]
        added = set(re.findall(r"info\.([a-z_]+)\s*=", show))
        with open(os.path.join(ROOT, "modules/backend/routes/case_routes.py"),
                  encoding="utf-8") as fh:
            routes = fh.read()
        d0 = routes.index("def get_case(case_id):")
        served = set(re.findall(r'"([a-z_]+)":', routes[d0:routes.index("@case_bp.route", d0)]))
        self.assertTrue(added - served,
                        "showCase no longer adds anything the payload lacks — the "
                        "snapshot ordering is no longer load-bearing, so simplify it "
                        "rather than leaving a comment that describes a dead hazard")


class TheContentAlwaysMatchesTheUnderline(unittest.TestCase):
    """Reported: "I'm on the Analysis page but it shows the log."

    setTab moves the underline synchronously and then draws. Timeline, Chat,
    Identities and Risk all FETCH first and write #tabc in a .then(), and none of
    them checked whether their tab was still the one on screen — so clicking a
    slow tab and then another painted the first one's content under the second
    one's underline. A renderer that threw did the same thing by leaving the
    previous tab's content in place. Either way the only way out was clicking
    again, which is also what "the tabs don't move on the first click" looks like.
    """

    def setUp(self):
        with open(PAGE, encoding="utf-8") as fh:
            self.page = fh.read()

    def test_every_deferred_write_checks_the_tab_is_still_its_own(self):
        import re
        for fn, tab in (("renderTimeline", "timeline"), ("renderIdentities", "identities"),
                        ("renderRisk", "risk")):
            body = self.page[self.page.index(f"function {fn}("):][:1500]
            self.assertIn(f"tabIsStill('{tab}')", body,
                          f"{fn} writes #tabc after a fetch — it must not paint over "
                          "a tab the operator has since switched to")
            self.assertLess(body.index("tabIsStill("), body.index("$('#tabc')", body.index(".then(")),
                            f"{fn} must check BEFORE it writes")

    def test_a_renderer_that_throws_does_not_leave_the_previous_tab(self):
        draw = self.page[self.page.index("function drawTab(md){"):]
        draw = draw[:draw.index("\n}") + 2]
        self.assertIn("catch(e){", draw)
        self.assertIn("could not be drawn", draw)

    def test_tabc_records_which_tab_it_is_showing(self):
        draw = self.page[self.page.index("function drawTab(md){"):]
        draw = draw[:draw.index("\n}") + 2]
        self.assertIn("box.dataset.tab=_t", draw,
                      "stamp what is on screen, or a mismatch cannot be detected")

    def test_the_poll_corrects_a_mismatch(self):
        poll = self.page[self.page.index("function pollReportGen(id){"):][:4000]
        self.assertIn("dataset.tab!==tab", poll,
                      "the 5s tick should heal a tab that ended up out of step with "
                      "its underline, whatever caused it")


if __name__ == "__main__":
    unittest.main(verbosity=2)
