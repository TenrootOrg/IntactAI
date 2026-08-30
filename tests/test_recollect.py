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
                          "velociraptor_hunt", "velociraptor_offline_import",
                          # An ADOPTED hunt keeps collecting on the server just
                          # like one Intact dispatched — the operator adopting it
                          # early must be able to come back for the rest.
                          "velociraptor_adopt"})
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
        # Match the CALL, not its exact argument list — the loader has since
        # grown a `log=` kwarg so a refusal (payload too big to parse without
        # exhausting the host) reaches the case log. Pinning the literal text
        # made an unrelated, additive change look like a regression.
        self.assertRegex(caller, r"_agentic_collected_data\(rid, det[,)]",
                         "the snapshot fallback must still be the path taken "
                         "when a refetch returns None")

    def test_the_refetch_is_re_snapshotted(self):
        # Otherwise the next automatic fuse drops straight back to the old rows.
        seg = self.src[self.src.index("def _refetch_agentic_rows"):
                       self.src.index("def _contribution_for_run")]
        self.assertIn("_resnapshot_without_losing_rows", seg)


class TestFusionAsksOnlyForWhatItUses(unittest.TestCase):
    """Fusion was fetching everything and keeping almost none of it.

    Measured on a real BestPractice collection (DESKTOP-566AT85, 2026-08-26):

        collected   38 sources   713,520 rows
        fused        8 sources       322 rows      <- 99.95% discarded

    Two artifacts are almost all of it — Windows.NTFS.MFT (354,831) and
    Windows.Forensics.Usn (353,367) — and fusion supports neither. Every manual
    Refusion pulled all of that over gRPC, per member run, to throw it away.

    This is a FETCH filter, not a policy change: those artifacts are still
    collected, still stored, still downloadable. Fusion just stops asking.
    """

    def setUp(self):
        self.store = read(STORE)
        self.base = read(os.path.join(
            ROOT, "modules/backend/services/agentic/collectors/_base.py"))

    def test_the_fetch_can_be_scoped(self):
        self.assertIn("only_artifacts", self.base)
        self.assertIn("def _wanted_source(", self.base)

    def test_sub_sources_and_export_prefixes_normalize(self):
        # "Generic.Forensic.SQLiteHunter/AllFiles" and "All Windows.NTFS.MFT"
        # must resolve to their base name, exactly as the fusion allowlist does.
        ns = {}
        seg = self.base[self.base.index("def _wanted_source("):
                        self.base.index("def get_existing_collection_results(")]
        exec(compile(seg, "base", "exec"), ns)
        w = ns["_wanted_source"]
        allow = {"windows.ntfs.mft"}
        self.assertTrue(w("Windows.NTFS.MFT", allow))
        self.assertTrue(w("All Windows.NTFS.MFT", allow))
        self.assertTrue(w("Windows.NTFS.MFT/Sub", allow))
        self.assertFalse(w("Windows.Forensics.Usn", allow))

    def test_an_empty_allowlist_fetches_everything(self):
        # Re-collect and any other consumer must be unaffected.
        ns = {}
        seg = self.base[self.base.index("def _wanted_source("):
                        self.base.index("def get_existing_collection_results(")]
        exec(compile(seg, "base", "exec"), ns)
        self.assertTrue(ns["_wanted_source"]("Anything.At.All", None))
        self.assertTrue(ns["_wanted_source"]("Anything.At.All", set()))

    def test_both_fusion_fetches_pass_the_allowlist(self):
        for fn in ("def _refetch_agentic_rows", "def _velo_hunt_contribution"):
            seg = self.store[self.store.index(fn):]
            seg = seg[:seg.index("\ndef ", 10)]
            self.assertIn("only_artifacts=SUPPORTED_ARTIFACTS", seg,
                          f"{fn} still fetches artifacts fusion discards")

    def test_re_collect_still_fetches_everything(self):
        # The operator's own action restores the RUN's data, not fusion's subset.
        routes = read(ROUTES)
        seg = routes[routes.index("def _recollect_worker"):routes.index("def recollect(")]
        self.assertNotIn("only_artifacts", seg,
                         "re-collect would silently drop artifacts the operator "
                         "collected on purpose")


class TestAScopedFetchNeverShrinksTheSnapshot(unittest.TestCase):
    """THE TRAP IN THIS FIX.

    raw_results.json is the RUN's data — downloadable, exportable, not fusion's
    private cache. A fusion-scoped fetch returns 322 of 713,520 rows, so writing
    it straight over the snapshot would delete 708,198 rows the operator
    collected on purpose. The refreshed sources are merged OVER the existing
    ones instead.
    """

    def setUp(self):
        self.src = read(STORE)

    def test_the_merge_helper_reads_the_existing_snapshot_first(self):
        seg = self.src[self.src.index("def _resnapshot_without_losing_rows"):]
        seg = seg[:seg.index("\ndef ", 10)]
        self.assertIn("_agentic_collected_data(rid, det)", seg)
        self.assertIn("merged.update(fetched", seg)

    def test_no_scoped_fetch_persists_directly(self):
        for fn in ("def _refetch_agentic_rows", "def _velo_hunt_contribution"):
            seg = self.src[self.src.index(fn):]
            seg = seg[:seg.index("\ndef ", 10)]
            code = "\n".join(l.split("#", 1)[0] for l in seg.splitlines())
            self.assertNotIn("persist_pipeline_artifacts(rid,", code,
                             f"{fn} overwrites the run's snapshot with a subset")

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


class TestAFetchAfterACancelIsAudible(unittest.TestCase):
    """A Fetch is very often pressed on a run the operator just STOPPED — that
    is the whole point of the button when a collection budget ran out.

    add_log_to_run drops logs on a cancelled run, to keep subprocess wrap-up
    from writing "success" lines after "[Pipeline] Stop requested by user".
    That guard swallowed this worker's entire narrative. Measured on case
    'test2': the fetch ran, re-read 481,253 rows and updated the run's details,
    and wrote not one log line — so the button looked dead and the operator
    reported it as broken.

    The worker owns a deliberate post-cancel operation, so it must force its
    logs. This pins the wiring; test_post_cancel_logging.py pins the guard
    itself.
    """

    def setUp(self):
        self.src = read(ROUTES)
        tree = ast.parse(self.src)
        self.worker = next(
            ast.get_source_segment(self.src, n) for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "_recollect_worker")

    def test_the_worker_logs_through_a_forcing_wrapper(self):
        """Executed, not grepped: run the worker's own body far enough to bind
        its logger, then check what that logger does to a cancelled run."""
        seen = []

        def fake_add_log(rid, msg, level="info", force=False):
            seen.append({"msg": msg, "force": force})

        ns = {}
        # The worker imports its collaborators inside the function body, so a
        # stub module is what it will bind.
        import sys
        import types
        mod = types.ModuleType("services.workflow_service")
        mod.add_log_to_run = fake_add_log
        mod.mutate_run_details = lambda *a, **k: None
        col = types.ModuleType("services.agentic.collectors")
        col.get_existing_collection_results = lambda *a, **k: ({}, None, None)
        col.persist_pipeline_artifacts = lambda *a, **k: None
        saved = {k: sys.modules.get(k) for k in
                 ("services", "services.workflow_service", "services.agentic",
                  "services.agentic.collectors")}
        try:
            pkg = types.ModuleType("services"); pkg.__path__ = []
            ag = types.ModuleType("services.agentic"); ag.__path__ = []
            sys.modules.update({"services": pkg, "services.workflow_service": mod,
                                "services.agentic": ag,
                                "services.agentic.collectors": col})
            ns.update(load_route_helpers())
            ns["_recollect_lock"] = __import__("threading").Lock()
            ns["_recollecting"] = set()
            exec(compile(self.worker, ROUTES, "exec"), ns)
            ns["_recollect_worker"]("r1", {"details": {"flow_id": "F.ABC"},
                                           "case_id": None})
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

        self.assertTrue(seen, "the worker must say something when it starts")
        self.assertTrue(all(e["force"] for e in seen),
                        "every Fetch log must be forced, or a cancelled run "
                        "silently swallows the whole narrative")
        self.assertTrue(any("Fetch" in e["msg"] for e in seen))

    def test_the_empty_result_warning_is_forced_too(self):
        """'Velociraptor returned nothing' is the ONE line that explains a
        no-op fetch. Dropped on a cancelled run, the button looks broken
        instead of informative — which is exactly how this was reported."""
        self.assertIn("returned nothing", self.src,
                      "the empty-result explanation must still exist")


class TestALongFetchKeepsSaying(unittest.TestCase):
    """"It needs to write that it is still working, not say it is done and then
    show nothing."

    The fetch blocks while it re-reads every source from the Velociraptor server
    — minutes on a large cold collection — and its per-source progress goes to
    the RUN log only. The case's Log tab got one line at the start and then
    nothing, which is indistinguishable from a stalled job. A daemon ticker
    reports elapsed time to the CASE until the fetch returns.
    """

    def _run_worker(self, fetch_seconds, heartbeat_seconds, linger=0.0):
        """Execute the real worker with a deliberately slow fetch."""
        import sys
        import threading
        import time
        import types

        src = read(ROUTES)
        worker = next(ast.get_source_segment(src, n) for n in ast.parse(src).body
                      if isinstance(n, ast.FunctionDef) and n.name == "_recollect_worker")

        case_events = []
        mod = types.ModuleType("services.workflow_service")
        mod.add_log_to_run = lambda *a, **k: None
        mod.mutate_run_details = lambda *a, **k: None
        col = types.ModuleType("services.agentic.collectors")

        def slow_fetch(*a, **k):
            time.sleep(fetch_seconds)
            return ({"Some.Artifact": [{"x": 1}]}, None, None)
        col.get_existing_collection_results = slow_fetch
        col.persist_pipeline_artifacts = lambda *a, **k: None

        fusion = types.ModuleType("services.fusion")
        store_mod = types.ModuleType("services.fusion.store")
        store_mod.log_case_event = lambda cid, action, status="ok", detail="": \
            case_events.append(action)
        store_mod.get_case = lambda cid: {}
        store_mod._merge_case_details = lambda *a, **k: None
        af = types.ModuleType("services.fusion.autofuse")
        af.schedule = lambda *a, **k: True
        af.QUIET_SECONDS = 60.0
        fusion.store = store_mod
        fusion.autofuse = af

        saved = {k: sys.modules.get(k) for k in
                 ("services", "services.workflow_service", "services.agentic",
                  "services.agentic.collectors", "services.fusion",
                  "services.fusion.store", "services.fusion.autofuse")}
        try:
            pkg = types.ModuleType("services"); pkg.__path__ = []
            ag = types.ModuleType("services.agentic"); ag.__path__ = []
            sys.modules.update({
                "services": pkg, "services.workflow_service": mod,
                "services.agentic": ag, "services.agentic.collectors": col,
                "services.fusion": fusion, "services.fusion.store": store_mod,
                "services.fusion.autofuse": af})
            ns = dict(load_route_helpers())
            ns.update({"threading": threading, "_recollect_lock": threading.Lock(),
                       "_recollecting": set(), "_HEARTBEAT_SECONDS": heartbeat_seconds})
            exec(compile(worker, ROUTES, "exec"), ns)
            ns["_recollect_worker"]("r1", {"details": {"flow_id": "F.ABC"},
                                           "case_id": "case_1"})
            # Linger with the stubs STILL INSTALLED. Restoring sys.modules first
            # would kill the ticker thread on its next import, and the test would
            # pass whether or not _hb_stop was ever set.
            if linger:
                # A tick already inside log_case_event when the worker returned
                # will still append once — that is the ticker stopping, not the
                # ticker running. Let any in-flight tick land BEFORE taking the
                # baseline, then assert nothing further arrives. Sampling the
                # baseline immediately made this flaky under parallel test load.
                time.sleep(linger / 4.0)
                self._settled = len(case_events)
                time.sleep(linger)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return case_events

    def test_a_slow_fetch_reports_that_it_is_still_working(self):
        events = self._run_worker(fetch_seconds=0.35, heartbeat_seconds=0.1)
        self.assertGreaterEqual(events.count("Still fetching"), 2,
                                "a long fetch must keep telling the case it is alive")

    def test_the_case_hears_about_the_fetch_before_it_finishes(self):
        events = self._run_worker(fetch_seconds=0.2, heartbeat_seconds=0.05)
        self.assertEqual(events[0], "Fetching from Velociraptor",
                         "the very first case entry must land when the fetch STARTS")

    def test_a_fast_fetch_does_not_spam_the_log(self):
        """The ticker must not fire at all when the work is quick."""
        events = self._run_worker(fetch_seconds=0.01, heartbeat_seconds=5.0)
        self.assertEqual(events.count("Still fetching"), 0)
        self.assertIn("New data fetched", events)

    def test_the_ticker_stops_when_the_fetch_returns(self):
        """A daemon thread that outlives its work would log into a finished case
        forever. Measured with the stubs still live, so only _hb_stop can end it."""
        self._settled = None
        events = self._run_worker(fetch_seconds=0.1, heartbeat_seconds=0.05,
                                  linger=0.4)
        self.assertIsNotNone(self._settled)
        self.assertEqual(len(events), self._settled,
                         "the heartbeat kept ticking after the fetch returned")
