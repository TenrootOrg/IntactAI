"""QA C2 / C5 / C11: fusion state that must not disagree with itself.

C2  A failed graph sidecar write, or a case-row write update_run_status refused,
    used to log "Refusion complete — saved" and stamp fused_at / fused_run_ids over
    the OLD graph, so the next automatic fuse skipped those runs. Now the fuse
    fails and the previous graph + row stay as they were.
C5  The Timeline read only timeline_validations, so a chat/checklist disposition
    showed Pending; the report counted re-opened (stale-watermark) benign verdicts
    as dismissed while the Timeline showed them re-opened.
C11 Toggling "use in analysis" wrote the status back from an unlocked read with
    force=True, so a toggle racing the parse finishing left the run "running".
"""
import datetime as _dt
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("/app", os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion import render, schema, store  # noqa: E402

_T0 = _dt.datetime(2026, 6, 16, 8, 0, 0, tzinfo=_dt.timezone.utc)
CASE = "case_c2"


def _ts(h=0):
    return (_T0 + _dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _WS:
    AGENTIC_TYPES = {"velociraptor_collection", "memory"}

    def __init__(self, row_ok=True):
        self.row_ok, self.completed = row_ok, []

    def get_automation_run(self, rid, with_logs=True):
        return {"run_id": rid, "name": f"run {rid}", "status": "completed",
                "automation_type": "velociraptor_collection", "details": {}}

    def get_all_automation_runs(self):
        return []

    def get_automation_runs_by_case(self, _cid):
        return []

    def update_run_status(self, rid, status, **kw):
        if status == "completed":
            self.completed.append(kw.get("details") or {})
            return self.row_ok
        return True

    def mutate_run_details(self, rid, fn):
        fn({})
        return True


class FuseFailsInsteadOfLying(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.old = {"entities": {"asset:old": {"id": "asset:old", "type": "asset"}}}
        self.addCleanup(setattr, store, "_FUSION_GRAPH_DIR", store._FUSION_GRAPH_DIR)
        store._FUSION_GRAPH_DIR = self.tmp
        self.events = []

    def _fuse(self, ws, sidecar_ok=True, had_graph=True):
        if had_graph:
            import json
            with open(store._graph_path(CASE), "w") as f:
                json.dump(self.old, f)
        case = {"name": "c2", "min_severity": "informational", "time_window": None}

        def contribution(run, log=None, refetch=False):
            return ([schema.Entity(id=f"asset:{run['run_id']}", type="asset",
                                   label=run["run_id"], first_seen=_ts(0))], [])
        real_write = store._write_graph_sidecar
        with mock.patch.object(store, "_ws", lambda: ws), \
             mock.patch.object(store, "get_case", lambda _cid: dict(case)), \
             mock.patch.object(store, "_members_for_case", lambda _cid, _d=None: ["r1"]), \
             mock.patch.object(store, "_run_passes_gate", lambda _run, _d: True), \
             mock.patch.object(store, "load_baseline", lambda _key: None), \
             mock.patch.object(store, "_contribution_for_run", contribution), \
             mock.patch.object(store, "log_case_event",
                               lambda cid, ev, lvl="info", msg="", **k: self.events.append((ev, msg))), \
             mock.patch.object(store, "_mutate_list_field", lambda *a, **k: None), \
             mock.patch.object(store, "_merge_case_details", lambda *a, **k: True), \
             mock.patch.object(store._rh, "archive", lambda *a, **k: None), \
             mock.patch.object(store, "_write_graph_sidecar",
                               real_write if sidecar_ok else (lambda *a: False)):
            with self.assertRaises(RuntimeError) as cm:
                store.fuse_case(CASE, trigger=store.TRIGGER_AUTOMATIC_RUN_LANDED, allow_llm=False)
        return str(cm.exception)

    def _graph_on_disk(self):
        import json
        if not os.path.exists(store._graph_path(CASE)):
            return None
        with open(store._graph_path(CASE)) as f:
            return json.load(f)

    def _assert_failed_not_complete(self):
        names = [e for e, _ in self.events]
        self.assertIn("Refusion failed", names)
        self.assertNotIn("Refusion complete", names)

    def test_a_failed_sidecar_write_stamps_nothing(self):
        ws = _WS()
        msg = self._fuse(ws, sidecar_ok=False)
        self.assertIn("sidecar", msg)
        self.assertEqual([], ws.completed, "no fused_at / fused_run_ids over the old graph")
        self._assert_failed_not_complete()
        self.assertEqual(self.old, self._graph_on_disk())
        self.assertFalse(os.path.exists(store._graph_path(CASE) + ".prev"))

    def test_a_refused_row_write_puts_the_old_graph_back(self):
        ws = _WS(row_ok=False)
        self.assertIn("refused", self._fuse(ws))
        self.assertEqual(1, len(ws.completed))
        self._assert_failed_not_complete()
        self.assertEqual(self.old, self._graph_on_disk(), "graph and row must still agree")
        self.assertFalse(os.path.exists(store._graph_path(CASE) + ".prev"))

    def test_a_refused_first_fuse_leaves_no_graph(self):
        self._fuse(_WS(row_ok=False), had_graph=False)
        self.assertIsNone(self._graph_on_disk())


def _finding(fid, occ=1, latest=None):
    return schema.Finding(id=fid, kind="sigma", title=f"Rule {fid}", severity="high",
                          confidence="medium", summary="",
                          ts=_ts(0), occ_count=occ, occ_latest=latest or _ts(0))


class VerdictsAgree(unittest.TestCase):
    def test_timeline_shows_a_chat_disposition(self):
        g = schema.FusionGraph(case_id=CASE)
        g.findings = [_finding("f1"), _finding("f2")]
        d = {"dispositions": [{"target": "f1", "verdict": "benign", "attribution": "it_admin"},
                              {"target": "f2", "verdict": "malicious"}],
             "timeline_validations": []}
        with mock.patch.object(store, "get_case", lambda _cid: d), \
             mock.patch.object(store, "view_graph", lambda _cid, _d=None: g), \
             mock.patch.object(store, "view_window", lambda _d: None):
            rows = store.get_timeline(CASE)
        got = {r["finding_id"]: r["validation"] for r in rows if not r.get("manual")}
        self.assertEqual("known", got.get("f1"))
        self.assertEqual("true_positive", got.get("f2"))

    def test_a_chat_disposition_replaces_an_older_timeline_verdict(self):
        det = {"dispositions": [], "timeline_validations": [
            {"finding_id": "f1", "status": "true_positive"}, {"finding_id": "f9", "status": "known"}]}
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda _cid, fn: fn(det) or True
        with mock.patch.object(store, "_ws", lambda: ws), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "fuse_case"):
            store.set_disposition(CASE, "f1", verdict="benign", attribution="customer")
        self.assertEqual(["f9"], [v["finding_id"] for v in det["timeline_validations"]])
        self.assertEqual("false_positive", render.analyst_verdict_map(
            det["dispositions"], det["timeline_validations"])["f1"])

    def test_the_report_drops_a_reopened_benign_verdict(self):
        g = schema.FusionGraph(case_id=CASE)
        g.findings = [_finding("f1", occ=5, latest=_ts(3)), _finding("f2")]
        vals = [{"finding_id": "f1", "status": "false_positive", "watermark": f"1|{_ts(0)}"},
                {"finding_id": "f2", "status": "known", "watermark": f"1|{_ts(0)}"}]
        self.assertEqual({"f2": "known"}, render.analyst_verdict_map(None, vals, g))
        self.assertEqual({"f1": "false_positive", "f2": "known"},
                         render.analyst_verdict_map(None, vals), "no graph: old behaviour")
        md = render._analyst_validations_md(g, [], vals)
        self.assertIn("Rule f2", md)
        self.assertNotIn("Rule f1", md, "re-opened in the Timeline, so not 'dismissed' here")

    def test_the_report_lists_a_chat_malicious_as_true_positive(self):
        g = schema.FusionGraph(case_id=CASE)
        g.findings = [_finding("f1")]
        md = render._analyst_validations_md(g, [{"target": "f1", "verdict": "malicious"}], [])
        self.assertIn(render._STATE_LABEL["true_positive"], md)
        self.assertNotIn(render._STATE_LABEL["false_positive"], md)


class UseInAnalysisNeverTouchesStatus(unittest.TestCase):
    def test_toggle_writes_details_only(self):
        from services.fusion import case_files
        import services.workflow_service as ws
        det, armed = {"rows": 3}, []
        with mock.patch.object(ws, "mutate_run_details",
                               side_effect=lambda rid, fn: fn(det) or True) as mut, \
             mock.patch.object(ws, "update_run_status") as upd, \
             mock.patch.object(ws, "get_automation_run",
                               lambda rid, with_logs=True: {"status": "completed"}), \
             mock.patch.object(case_files, "_forget_fused"), \
             mock.patch("services.fusion.autofuse.schedule",
                        lambda cid, reason="": armed.append(cid)):
            case_files._use_in_analysis(CASE, "external_log_9", False)
        mut.assert_called_once()
        upd.assert_not_called()
        self.assertEqual({"rows": 3, "use_in_analysis": False}, det)
        self.assertEqual([CASE], armed, "a finished run still re-arms the auto-fuse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
