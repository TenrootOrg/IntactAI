"""A case that has never been fused must say so.

Reported from the box: a new case 'twe' was created, an offline collector was
imported into it, and nothing happened -- no banner, no prompt -- until the
operator knew to click Refusion themselves.

The poll was working. It was polling a signal that answered "nothing new" for the
one case where everything is new. stale_member_runs began:

    fused = d.get("fused_run_ids")
    if fused is None:
        return []

An absent key meant two different things and the guard treated both as silence:

    never fused   no graph exists at all      -> EVERY member run is unreflected
    legacy        a graph exists, but predates fused_run_ids tracking, so we
                  genuinely cannot say which runs built it -> stay quiet

Only the second deserves silence, and it is the rarer one. The first is a brand
new case -- the exact moment the prompt matters most.

The REAL functions are lifted out of store.py and executed against stubbed
collaborators, so this cannot drift from what ships. store.py itself cannot be
imported (it pulls the whole backend, and this suite is stdlib-only), but the
three functions under test touch nothing but their stubs.
"""

import ast
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")

WANTED = ("_ever_fused", "stale_member_runs", "report_stale_runs")


def _load():
    """Execute the real functions with every collaborator stubbed."""
    with open(STORE, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    picked = {n.name: ast.get_source_segment(src, n)
              for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in WANTED}
    missing = [w for w in WANTED if w not in picked]
    if missing:
        raise AssertionError("not found in store.py: %s" % ", ".join(missing))

    ns = {"os": os}
    ns["_state"] = {"runs": [], "sidecar": False, "case": {}}
    ns["get_case"] = lambda cid: ns["_state"]["case"]
    # A real file on disk, so os.path.exists() is genuinely exercised rather than
    # being told the answer by a stub that never touches the filesystem.
    fd, present = tempfile.mkstemp(prefix="fusion_sidecar_", suffix=".json")
    os.close(fd)
    ns["_present_path"] = present
    ns["_graph_path"] = lambda cid: (present if ns["_state"]["sidecar"]
                                     else os.path.join(present + ".absent"))
    ns["_run_passes_gate"] = lambda r, d: r.get("gated", True)

    class _WS:
        def get_automation_runs_by_case(self, cid):
            return ns["_state"]["runs"]
    ns["_ws"] = lambda: _WS()

    for name in WANTED:
        exec(compile(picked[name], STORE, "exec"), ns)
    return ns


NS = _load()
STATE = NS["_state"]


def _run(rid, status="completed", gated=True):
    return {"run_id": rid, "status": status, "gated": gated}


class _Base(unittest.TestCase):
    def setUp(self):
        STATE["runs"] = [_run("velociraptor_upload_1")]
        STATE["sidecar"] = False
        STATE["case"] = {}

    def stale(self, d):
        return NS["stale_member_runs"]("case_x", d)

    def report_stale(self, d):
        return NS["report_stale_runs"]("case_x", d)


class TestNeverFusedIsReported(_Base):
    """The reported bug."""

    def test_a_fresh_case_with_an_import_is_stale(self):
        d = {}                                   # no fused_run_ids, no graph
        self.assertEqual(self.stale(d), ["velociraptor_upload_1"],
                         "a never-fused case must report its member runs as new")

    def test_the_banner_would_show(self):
        d = {}
        is_stale = bool(self.stale(d) or self.report_stale(d) or d.get("report_dirty"))
        self.assertTrue(is_stale, "is_stale drives the banner — it must be True here")

    def test_a_fresh_case_with_no_runs_is_not_stale(self):
        """An empty new case must not nag about nothing."""
        STATE["runs"] = []
        self.assertEqual(self.stale({}), [])


class TestLegacyStaysSilent(_Base):
    """The original guard's purpose, which must survive the fix."""

    def test_precomputed_counts_mean_a_graph_exists(self):
        d = {"graph_counts": {"entities": 18749}}
        self.assertEqual(self.stale(d), [],
                         "a legacy graph cannot say which runs built it — stay quiet")

    def test_an_inline_graph_means_a_graph_exists(self):
        """Cases fused before the sidecar split carry it inline."""
        d = {"fusion_graph": {"entities": {"a": 1}}}
        self.assertEqual(self.stale(d), [])

    def test_a_sidecar_on_disk_means_a_graph_exists(self):
        """Counts were not always precomputed; the file is the last word."""
        STATE["sidecar"] = True
        self.assertEqual(self.stale({}), [])

    def test_an_empty_counts_dict_does_not_count_as_fused(self):
        """`fusion_graph: {}` is written to CLEAR a legacy inline graph."""
        self.assertEqual(self.stale({"fusion_graph": {}, "graph_counts": {}}),
                         ["velociraptor_upload_1"])


class TestNormalTracking(_Base):
    """Everything the fix must not change."""

    def test_a_fused_run_is_not_stale(self):
        d = {"fused_run_ids": ["velociraptor_upload_1"], "graph_counts": {"entities": 1}}
        self.assertEqual(self.stale(d), [])

    def test_a_run_added_since_the_fuse_is_stale(self):
        STATE["runs"] = [_run("old"), _run("new")]
        d = {"fused_run_ids": ["old"], "graph_counts": {"entities": 1}}
        self.assertEqual(self.stale(d), ["new"])

    def test_an_unfinished_run_is_not_stale(self):
        STATE["runs"] = [_run("running", status="running")]
        self.assertEqual(self.stale({"fused_run_ids": []}), [])

    def test_a_disabled_modules_run_is_not_stale(self):
        """Flagging it would prompt a Refusion that does nothing."""
        STATE["runs"] = [_run("cloud", gated=False)]
        self.assertEqual(self.stale({"fused_run_ids": []}), [])

    def test_success_counts_as_terminal_too(self):
        STATE["runs"] = [_run("ok", status="success")]
        self.assertEqual(self.stale({"fused_run_ids": []}), ["ok"])


class TestReportStaleness(_Base):
    """Same conflation, one door along."""

    def test_no_report_yet_means_every_run_is_unreflected(self):
        self.assertEqual(self.report_stale({}), ["velociraptor_upload_1"])

    def test_a_legacy_report_stays_silent(self):
        d = {"report_md": "# Incident Case Report"}
        self.assertEqual(self.report_stale(d), [])

    def test_a_current_report_is_not_stale(self):
        d = {"report_run_ids": ["velociraptor_upload_1"], "report_md": "x"}
        self.assertEqual(self.report_stale(d), [])

    def test_a_run_added_since_the_report_is_stale(self):
        STATE["runs"] = [_run("old"), _run("new")]
        d = {"report_run_ids": ["old"], "report_md": "x"}
        self.assertEqual(self.report_stale(d), ["new"])


class TestEverFusedIsCheap(unittest.TestCase):
    """It runs on every case GET, which the UI now polls every 20s. A graph
    reaching 39 MB must never be deserialized to answer this."""

    def test_it_does_not_load_the_graph(self):
        with open(STORE, encoding="utf-8") as f:
            src = f.read()
        node = next(n for n in ast.parse(src).body
                    if isinstance(n, ast.FunctionDef) and n.name == "_ever_fused")
        body = ast.get_source_segment(src, node) or ""
        code = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
        for forbidden in ("load_graph", "_read_graph_sidecar", "json.load", "open("):
            self.assertNotIn(forbidden, code,
                             "_ever_fused must stay a metadata/stat check")


def tearDownModule():
    try:
        os.unlink(NS["_present_path"])
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
