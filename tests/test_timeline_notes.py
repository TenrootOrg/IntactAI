"""A note on a verdict — why it is a false positive, who confirmed it is known —
reaches the Timeline, the report and the chat (plan step 2).

The backend saved `notes` with each verdict since the start; nothing showed or
edited them. Editing a note is text only: no re-fuse, suppression untouched.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, jev, render, store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402

TS = "2026-06-01T10:00:00Z"


class _Case:
    def __init__(self, vals, disps=()):
        self.state = {"timeline_validations": list(vals), "dispositions": list(disps)}

    def patches(self, graph):
        def mut(cid, field, fn):
            self.state[field] = fn(list(self.state.get(field) or []))
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: fn(self.state)
        self.fuse = mock.patch.object(store, "fuse_case").start()
        for t, a, v in ((store, "get_case", lambda cid: dict(self.state)), (store, "load_graph", lambda cid: graph),
                        (store, "_mutate_list_field", mut), (store, "_ws", lambda: ws),
                        (store, "_report_behind", mock.Mock()), (store, "log_case_event", mock.Mock()),
                        (store, "ack_rows", mock.Mock()), (jev, "after_fuse", mock.Mock())):
            mock.patch.object(t, a, v).start()


def _row(parts=False):
    return Finding(id="row", title="SIGMA: A on H", severity="high", confidence="high", summary="",
                   occ_count=1, occ_latest=TS, ts=TS,
                   parts=[correlate._part("p1", "SIGMA: A", TS, None, 1, "1|" + TS, [], "high"),
                          correlate._part("p2", "SIGMA: B", TS, None, 1, "1|" + TS, [], "high")] if parts else [])


class Store(unittest.TestCase):
    def tearDown(self):
        mock.patch.stopall()

    def test_a_note_is_saved_on_its_verdict_without_a_refuse(self):
        c = _Case([{"finding_id": "row", "status": "false_positive"}])
        c.patches(types.SimpleNamespace(findings=[_row()]))
        res = store.note_timeline("c1", "row", "  Chef deploys sdelete on every image  ")
        self.assertEqual(res["notes"], "Chef deploys sdelete on every image")
        self.assertEqual(c.state["timeline_validations"][0]["notes"], "Chef deploys sdelete on every image")
        c.fuse.assert_not_called()                                  # text only
        self.assertEqual(c.state["dispositions"], [])               # suppression untouched

    def test_no_verdict_no_note(self):
        c = _Case([])
        c.patches(types.SimpleNamespace(findings=[_row()]))
        self.assertIn("error", store.note_timeline("c1", "row", "x"))
        self.assertEqual(c.state["timeline_validations"], [])

    def test_changing_the_verdict_keeps_the_note_pending_drops_it(self):
        c = _Case([{"finding_id": "row", "status": "false_positive", "notes": "IT's Chef"}])
        c.patches(types.SimpleNamespace(findings=[_row()]))
        store.validate_timeline_many("c1", ["row"], "known")
        self.assertEqual(c.state["timeline_validations"][0]["notes"], "IT's Chef")
        store.validate_timeline_many("c1", ["row"], "pending")
        self.assertEqual(c.state["timeline_validations"], [])

    def test_the_timeline_shows_notes_on_rows_and_parts(self):
        g = correlate.FusionGraph(case_id="c")
        g.findings += [_row(), Finding(id="grp", title="SIGMA: G (+1 related) on H", severity="high",
                                       confidence="high", summary="", occ_count=2, occ_latest=TS, ts=TS,
                                       parts=_row(parts=True).parts)]
        vals = [{"finding_id": "row", "status": "known", "notes": "admin task"},
                {"finding_id": "p2", "status": "false_positive", "notes": "test box"}]
        with mock.patch.object(store, "get_case", return_value={"timeline_validations": vals}), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch.object(store, "view_window", return_value=None), \
             mock.patch.object(jev, "enabled", return_value=False):
            rows = {r["finding_id"]: r for r in store.get_timeline("c1")}
        self.assertEqual(rows["row"]["notes"], "admin task")
        self.assertEqual({p["finding_id"]: p.get("notes") for p in rows["grp"]["parts"]},
                         {"p1": None, "p2": "test box"})

    def test_the_report_carries_the_note(self):
        g = correlate.FusionGraph(case_id="c")
        g.findings.append(_row())
        md = render._analyst_validations_md(g, [], [{"finding_id": "row", "status": "known",
                                                     "notes": "scheduled backup"}])
        self.assertIn("- SIGMA: A on H — _scheduled backup_", md)


class Page(unittest.TestCase):
    def test_the_note_link_shows_only_on_a_judged_row_without_parts(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0) for n in ("_tlNote", "_tlParts")]
        js = "const esc=s=>String(s);\n" + "\n".join(fns) + """
console.log(JSON.stringify([
  _tlNote({finding_id:'a', validation:'pending'}),
  _tlNote({finding_id:'a', validation:'false_positive'}),
  _tlNote({finding_id:'a', validation:'known', notes:'IT'}),
  _tlNote({finding_id:'g', validation:'known', parts:[{},{}]}),
  _tlNote({finding_id:'m', manual:true, notes:'GPO push'})]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertEqual(out[0], "")                                  # no verdict, nothing to note
        self.assertIn("✎ note", out[1])
        self.assertIn("tlNote('a')", out[1])
        self.assertIn("— IT ✎", out[2])                               # shown, click to edit
        self.assertEqual(out[3], "")                                  # a row with parts: notes go on the parts
        self.assertIn("— GPO push", out[4])                           # manual events keep their own


if __name__ == "__main__":
    unittest.main()
