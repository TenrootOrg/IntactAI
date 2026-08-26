"""Fetching what Velociraptor already has, without touching an endpoint.

WHY THIS EXISTS. Three ordinary situations leave collected data on the
Velociraptor server that the appliance never picked up, and only one of them is
a bug:

  * the collection budget expired while the flow was still running. Measured
    2026-08-26 on a live 10-minute BestPractice run, which ended with "Some
    flows had not finished yet — they keep running in Velociraptor and finish
    there". The operator asked for 10 minutes and the work needed longer;
    nothing is broken and no automatic behaviour can fix it.
  * a hunt is marked completed as soon as Velociraptor HOLDS it — seconds after
    dispatch — while its clients report over the following hours.
  * runs collected before errored flows stopped being abandoned are short.

Before this, the only offer was "increase the time and Rerun", which starts a
whole new collection on the customer's endpoint. Re-collect asks the SERVER for
rows it already has. That difference — free vs another hour of somebody's
machine — is invisible from a button, which is why the two are worded
differently and tested apart.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes/dashboard_routes.py")
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
JS = os.path.join(ROOT, "modules/nginx/html/js/stores/workflows.js")
HTML = os.path.join(ROOT, "modules/nginx/html/partials/workflows.html")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def load_route_helpers():
    """Exec just the pure helper out of dashboard_routes — importing the module
    would drag the whole backend in for one function."""
    tree = ast.parse(read(ROUTES))
    ns = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_recollect_locator":
            exec(compile(ast.Module([node], []), ROUTES, "exec"), ns)
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "_RECOLLECTABLE":
            exec(compile(ast.Module([node], []), ROUTES, "exec"), ns)
    return ns


class TestItFindsWhateverTheRunRecorded(unittest.TestCase):
    """Each run type stores its locator differently, and a collection stores a
    LIST when several clients were selected. Getting this wrong means the button
    reports "nothing to re-fetch" on a run that plainly has data."""

    def setUp(self):
        self.ns = load_route_helpers()
        self.locate = self.ns["_recollect_locator"]

    def test_a_single_client_collection(self):
        flow, hunt, cids = self.locate({"flow_id": "F.ABC"})
        self.assertEqual((flow, hunt), ("F.ABC", None))

    def test_a_multi_client_collection_keeps_every_flow(self):
        flow, hunt, _ = self.locate({"flow_id": ["F.A", "F.B", "F.C"]})
        self.assertEqual(flow, ["F.A", "F.B", "F.C"],
                         "dropping the other clients' flows loses their data")

    def test_a_one_element_list_is_unwrapped(self):
        flow, _h, _c = self.locate({"flow_id": ["F.ONLY"]})
        self.assertEqual(flow, "F.ONLY")

    def test_a_hunt(self):
        flow, hunt, _ = self.locate({"hunt_id": "H.XYZ"})
        self.assertEqual((flow, hunt), (None, "H.XYZ"))

    def test_a_hunt_wins_over_a_stray_flow_id(self):
        # An offline import can carry both; the hunt is the complete picture.
        _f, hunt, _c = self.locate({"hunt_id": "H.XYZ", "flow_id": "F.ABC"})
        self.assertEqual(hunt, "H.XYZ")

    def test_an_offline_import_scopes_to_its_client(self):
        _f, _h, cids = self.locate({"flow_id": "F.ABC", "client_id": "C.1"})
        self.assertEqual(cids, ["C.1"])

    def test_a_run_with_no_locator(self):
        self.assertEqual(self.locate({}), (None, None, None))


class TestItRefusesWhatItCannotDo(unittest.TestCase):
    def setUp(self):
        self.src = read(ROUTES)

    def test_only_velociraptor_backed_runs_are_offered(self):
        ns = load_route_helpers()
        self.assertEqual(set(ns["_RECOLLECTABLE"]),
                         {"velociraptor_collection", "velociraptor_upload",
                          "velociraptor_hunt", "velociraptor_offline_import"})
        # A memory or timesketch run holds no Velociraptor flow to re-read.
        self.assertNotIn("memory", ns["_RECOLLECTABLE"])

    def test_a_still_running_run_is_refused(self):
        # Re-fetching mid-collection would race the collector writing the same
        # snapshot file.
        self.assertIn("still collecting", self.src)

    def test_a_second_request_is_refused_while_one_is_in_flight(self):
        self.assertIn("_recollecting", self.src)
        self.assertIn('"busy": True', self.src)

    def test_an_empty_result_says_why_rather_than_looking_successful(self):
        # Velociraptor expires flow data. Returning zero rows silently makes a
        # run look like it collected nothing.
        self.assertIn("may have expired on the server", self.src)

    def test_it_starts_no_collection(self):
        # The guarantee that separates this from Rerun. Nothing in the route may
        # reach a launch path.
        code = "\n".join(l.split("#", 1)[0] for l in self.src.splitlines())
        seg = code[code.index("def _recollect_worker"):code.index("def recollect(")]
        for forbidden in ("collect_client", "create_collections", "/api/agentic/run",
                          "create_velociraptor_hunt"):
            self.assertNotIn(forbidden, seg, f"re-collect reaches {forbidden}")


class TestTheCaseIsToldThereIsNewData(unittest.TestCase):
    """Re-fetched rows land in raw_results.json — and would sit there unseen.

    stale_member_runs only counts members NOT in fused_run_ids, so a run that
    has been fused once is never stale again however much its data grows. The
    re-collect has to drop it from that list or the graph never learns.
    """

    def test_the_run_is_removed_from_fused_run_ids(self):
        src = read(ROUTES)
        self.assertIn("fused_run_ids", src)
        self.assertIn("autofuse.schedule", src)

    def test_a_failure_to_re_arm_still_keeps_the_rows(self):
        src = read(ROUTES)
        self.assertIn("Press Refusion on the case", src)


class TestAManualRefusionRereadsFromVelociraptor(unittest.TestCase):
    """A collection fuses from the snapshot written when it ended, so a manual
    Refusion used to rebuild from data that was already stale. It now re-reads —
    but only when a PERSON asked, because it is a full result fetch per member
    run and the automatic fuse after every landing run has to stay quick."""

    def setUp(self):
        self.src = read(STORE)

    def test_manual_triggers_refetch(self):
        seg = self.src[self.src.index("if refetch is None:"):]
        seg = seg[:seg.index("\n    #", 5)]
        for t in ("TRIGGER_MANUAL_REFUSION", "TRIGGER_MANUAL_RESCAN", "TRIGGER_API_FUSE"):
            self.assertIn(t, seg)

    def test_automatic_triggers_do_not(self):
        seg = self.src[self.src.index("if refetch is None:"):]
        seg = seg[:seg.index("\n    #", 5)]
        for t in ("TRIGGER_AUTOMATIC_RUN_LANDED", "TRIGGER_DISPOSITION",
                  "TRIGGER_TIMELINE", "TRIGGER_IDENTITY", "TRIGGER_CHECKLIST"):
            self.assertNotIn(t, seg,
                             f"{t} would make every automatic fuse re-read every run")

    def test_a_failed_refetch_falls_back_to_the_snapshot(self):
        # Velociraptor being down must degrade to the stored rows, never fuse an
        # empty case over a good snapshot.
        seg = self.src[self.src.index("def _refetch_agentic_rows"):
                       self.src.index("def _contribution_for_run")]
        self.assertIn("return None", seg)
        self.assertIn("using the stored snapshot", seg)
        caller = self.src[self.src.index("def _contribution_for_run"):]
        caller = caller[:caller.index("if atype in (\"velociraptor_hunt\"")]
        self.assertIn("if rows is None:", caller)
        self.assertIn("_agentic_collected_data(rid, det)", caller)

    def test_the_refetch_is_re_snapshotted(self):
        # Otherwise the next automatic fuse drops straight back to the old rows.
        seg = self.src[self.src.index("def _refetch_agentic_rows"):
                       self.src.index("def _contribution_for_run")]
        self.assertIn("persist_pipeline_artifacts", seg)

    def test_the_operator_is_told_why_it_is_slower(self):
        self.assertIn("re-reading each one from Velociraptor", self.src)


class TestTheButtonSaysWhatItDoes(unittest.TestCase):
    """Rerun costs the customer's endpoint another collection; this costs
    nothing. That difference has to be legible from the button."""

    def test_it_is_not_worded_like_a_rerun(self):
        html = read(HTML)
        self.assertIn("Fetch results", html)
        self.assertIn("recollect(run.id)", html)

    def test_it_says_the_endpoint_is_not_touched(self):
        html = read(HTML)
        seg = html[html.index("recollect(run.id)") - 1200:html.index("recollect(run.id)") + 900]
        self.assertIn("endpoint is not touched", seg)

    def test_it_is_only_offered_on_velociraptor_runs(self):
        html = read(HTML)
        seg = html[html.index("recollect(run.id)") - 1200:html.index("recollect(run.id)")]
        for t in ("velociraptor_collection", "velociraptor_hunt"):
            self.assertIn(t, seg)

    def test_it_is_only_offered_on_finished_runs(self):
        html = read(HTML)
        seg = html[html.index("recollect(run.id)") - 1200:html.index("recollect(run.id)")]
        self.assertIn("completed", seg)

    def test_one_at_a_time(self):
        js = read(JS)
        self.assertIn("if (this.recollecting) return;", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
