"""A row that bundles several detections — a "+N related" row (rules on one event)
or a burst — is judged PART BY PART: QA asked "what if only some of them was
confirmed". A verdict on one rule is that rule's; the row leaves risk only when
every part is judged benign.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402

TS = "2026-06-21T13:30:08Z"
TWO = ["Malicious PowerShell Commandlets", "Mimikatz Execution via PowerShell"]


def _row(title):
    return {"Timestamp": TS, "Title": title, "Level": "high", "Computer": "HOSTA",
            "Channel": "Microsoft-Windows-PowerShell/Operational", "EID": 4104, "RecordID": 4242,
            "Details": "ScriptBlockID: 1234abcd ¦ MessageNumber: 1", "_hostname": "HOSTA",
            "_client_id": "C.HOSTA"}


def _fuse(dispositions=None):
    ents, rels = map_agentic({"Windows.Hayabusa.Rules": [_row(t) for t in TWO]}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"], dispositions=dispositions)
    return next(f for f in g.findings if "related" in f.title)


def _benign(target, wm=None):
    d = {"target": target, "verdict": "benign", "attribution": "operator"}
    if wm:
        d["watermark"] = wm
    return d


class RelatedRowParts(unittest.TestCase):
    def test_each_rule_is_a_part_not_an_alias(self):
        row = _fuse()
        self.assertEqual(sorted(p["title"] for p in row.parts),
                         sorted("SIGMA: " + t for t in TWO))
        for p in row.parts:
            self.assertNotIn(p["id"], row.ids())

    def test_one_rule_false_positive_keeps_the_row(self):
        row = _fuse()
        kept = _fuse([_benign(row.parts[0]["id"])])
        self.assertEqual(kept.severity, "high")
        self.assertNotEqual(kept.kind, "dispositioned")
        self.assertIn("1 of 2 parts judged benign", kept.summary)

    def test_every_rule_benign_suppresses_the_row(self):
        row = _fuse()
        gone = _fuse([_benign(p["id"]) for p in row.parts])
        self.assertEqual((gone.severity, gone.kind), ("informational", "dispositioned"))

    def test_new_activity_on_a_part_reopens_it(self):
        row = _fuse()
        ds = [_benign(row.parts[0]["id"]), _benign(row.parts[1]["id"], wm="1|2020-01-01T00:00:00Z")]
        self.assertNotEqual(_fuse(ds).kind, "dispositioned")

    def test_a_verdict_on_the_whole_row_still_covers_it(self):
        row = _fuse()
        self.assertEqual(_fuse([_benign(row.id)]).kind, "dispositioned")


class BurstParts(unittest.TestCase):
    def _graph(self):
        g = correlate.FusionGraph(case_id="c")
        f = Finding(id="burst1", title="Burst of 2 detections", severity="high", confidence="high",
                    summary="s", entity_ids=["e1", "e2"], kind="derived",
                    parts=[correlate._part("e1", "A", TS, None, 1, "1|" + TS, ["e1"], "medium"),
                           correlate._part("e2", "B", TS, None, 1, "1|" + TS, ["e2"], "medium")])
        g.findings.append(f)
        return g, f

    def test_one_detection_benign_does_not_clear_the_burst(self):
        # its part id is also a cited entity: it must not match the whole row that way
        g, f = self._graph()
        correlate._apply_dispositions(g, [_benign("e1")])
        self.assertEqual(f.severity, "high")

    def test_all_detections_benign_clears_it(self):
        g, f = self._graph()
        correlate._apply_dispositions(g, [_benign("e1"), _benign("e2")])
        self.assertEqual(f.kind, "dispositioned")

    def test_parts_survive_save_and_load(self):
        _, f = self._graph()
        self.assertEqual(Finding.from_dict(f.to_dict()).parts, f.parts)


class Store(unittest.TestCase):
    """Verdicts on parts: what the Timeline shows, and what a part verdict does to
    one given earlier on the whole row."""

    def _row(self):
        return Finding(id="row", title="SIGMA: A (+1 related) on H", severity="high", confidence="high",
                       summary="", occ_count=2, occ_latest=TS, ts=TS,
                       parts=[correlate._part("p1", "SIGMA: A", TS, None, 1, "1|" + TS, [], "high"),
                              correlate._part("p2", "SIGMA: B", TS, None, 1, "1|" + TS, [], "high")])

    def _validate(self, ids, status, state):
        import types
        from unittest import mock
        from services.fusion import store
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: fn(state)

        def mut(cid, field, fn):
            state[field] = fn(list(state.get(field) or []))
        g = types.SimpleNamespace(findings=[self._row()])
        with mock.patch.object(store, "get_case", side_effect=lambda cid: dict(state)), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_mutate_list_field", side_effect=mut), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(store, "_report_behind"), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "ack_rows"), \
             mock.patch.object(store, "fuse_case") as fuse:
            store.validate_timeline_many("c1", ids, status)
        return state, fuse.call_count

    def test_a_part_verdict_snapshots_the_parts_own_watermark(self):
        state, fuses = self._validate(["p1"], "false_positive", {"timeline_validations": [], "dispositions": []})
        self.assertEqual(state["timeline_validations"][0]["watermark"], "1|" + TS)
        self.assertEqual([d["target"] for d in state["dispositions"]], ["p1"])
        self.assertEqual(fuses, 1)

    def test_a_whole_row_verdict_moves_down_to_the_other_parts(self):
        # the row was marked False positive before parts existed; now one rule is real
        state = {"timeline_validations": [{"finding_id": "row", "status": "false_positive"}],
                 "dispositions": [{"target": "row", "verdict": "benign", "attribution": "operator"}]}
        state, _ = self._validate(["p1"], "true_positive", state)
        self.assertEqual({v["finding_id"]: v["status"] for v in state["timeline_validations"]},
                         {"p1": "true_positive", "p2": "false_positive"})
        self.assertEqual([d["target"] for d in state["dispositions"]], ["p2"])   # the row no longer suppressed

    def test_timeline_rows_carry_parts_and_read_as_them(self):
        from unittest import mock
        from services.fusion import jev, store
        g = correlate.FusionGraph(case_id="c")
        g.findings.append(self._row())
        vals = [{"finding_id": "p1", "status": "true_positive"}, {"finding_id": "p2", "status": "known",
                                                                   "watermark": "1|" + TS}]
        with mock.patch.object(store, "get_case", return_value={"timeline_validations": vals}), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch.object(store, "view_window", return_value=None), \
             mock.patch.object(jev, "enabled", return_value=False):
            row = store.get_timeline("c1")[0]
        self.assertEqual({p["finding_id"]: p["validation"] for p in row["parts"]},
                         {"p1": "true_positive", "p2": "known"})
        self.assertEqual(row["validation"], "pending")          # mixed: the row itself is not judged
        vals[0]["status"] = "known"
        vals[0]["watermark"] = "1|" + TS
        with mock.patch.object(store, "get_case", return_value={"timeline_validations": vals}), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch.object(store, "view_window", return_value=None), \
             mock.patch.object(jev, "enabled", return_value=False):
            self.assertEqual(store.get_timeline("c1")[0]["validation"], "known")

    def test_the_report_names_a_judged_part(self):
        from services.fusion import render
        g = correlate.FusionGraph(case_id="c")
        g.findings.append(self._row())
        self.assertEqual(render.row_verdict(g.findings[0], {"p1": "true_positive"}), "true_positive")
        self.assertIsNone(render.row_verdict(g.findings[0], {"p1": "known"}))
        self.assertEqual(render.row_verdict(g.findings[0], {"p1": "known", "p2": "false_positive"}),
                         "false_positive")
        md = render._analyst_validations_md(g, [], [{"finding_id": "p2", "status": "known"}])
        self.assertIn("SIGMA: B (part of SIGMA: A (+1 related) on H)", md)


class RowDisplay(unittest.TestCase):
    """The real _tlRow from cases.html, run in node."""

    def test_row_opens_into_parts_with_their_own_buttons(self):
        import json, re, shutil, subprocess, tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = []
        fns.append(re.search(r"const _TL_SEVS=\[.*?\];", src).group(0))
        for name in ("_tlUntil", "_tlJev", "_tlParts", "_tlPartsToggle", "_tlRow", "_tlRowHtml",
                     "_tlTitle", "_tlLoggedAs", "_tlSevChip"):
            m = re.search(r"function %s\(.*?\n\}" % re.escape(name), src, re.S)
            self.assertTrue(m, name + " missing from cases.html")
            fns.append(m.group(0))
        js = ("const esc=s=>String(s); const TL_STATES=[['pending','Pending'],['true_positive','True Positive'],"
              "['false_positive','False Positive'],['known','Known']]; window={};\n" + "\n".join(fns) + """
const row={finding_id:'grp1', title:'SIGMA: A (+1 related) on H', host:'H', ts:'t', severity:'high',
  parts:[{finding_id:'p1', title:'SIGMA: A', ts:'t', severity:'high', validation:'true_positive'},
         {finding_id:'p2', title:'SIGMA: B', ts:'t', severity:'high', validation:'false_positive'}]};
const closed=_tlRow(row,false);
window._tlOpen={'p:grp1':true};
const open=_tlRow(row,false);
const files=_tlRow({finding_id:'f', title:'MFT: Erasing Tools (2 files: a.exe, b.exe) on H', host:'H', ts:'t', severity:'medium',
  parts:[{finding_id:'e1', title:'C:/a.exe', kind:'file'}, {finding_id:'e2', title:'C:/b.exe', kind:'file'}]}, false);
const burst=_tlRow({finding_id:'b', title:'Burst of 2 detections in 5 min — A, B on H', host:'H', ts:'t', severity:'high',
  parts:[{finding_id:'e1', title:'A', severity:'medium'}, {finding_id:'e2', title:'B', severity:'medium'}]}, false);
const single=_tlRow({finding_id:'s', title:'SIGMA: X on H', host:'H', ts:'t', severity:'high'}, false);
console.log(JSON.stringify([closed, open, files, burst, single]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            closed, opened, files, burst, single = json.loads(subprocess.run([node, t.name], capture_output=True, text=True,
                                                       check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("2 rules · 2 of 2 reviewed", closed)
        self.assertIn("tlValidateMany([&quot;p1&quot;,&quot;p2&quot;],'known')", closed)   # the row sets every part
        self.assertNotIn(" on\"", closed.split('class="seg"')[1])                          # mixed: nothing lit
        self.assertNotIn("tlgkids", closed)
        self.assertIn("tlValidate('p2','true_positive')", opened)                             # each part on its own
        self.assertIn("openFindingDetail('p1')", opened)
        self.assertIn("2 files · 0 of 2 reviewed", files)                                   # files found on disk
        # a bundled row's severity says what it is: its worst part, or rated as a whole
        self.assertIn('class="chip agg c-high"', closed)
        self.assertIn("high<small>max</small>", closed)
        self.assertIn("high<small>combined</small>", burst)
        self.assertIn('<span class="chip c-high">high</span>', single)


if __name__ == "__main__":
    unittest.main()
