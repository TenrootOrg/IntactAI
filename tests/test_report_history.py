"""Report history — every report written is kept (view, download, delete) — and the
case / host containment status the model is told, so a report cannot claim a
containment nobody recorded. Report stages and types were tried and removed; the
reports kept while they existed keep their label.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim, report_history as rh, store  # noqa: E402
from services.fusion.schema import FusionGraph  # noqa: E402

TEMPLATE = "# Incident Case Report — qa\n\n## Executive Summary\nsum\n\n---\n_Deterministic report — no model_\n"
AI = "# Incident Case Report — qa\n\n## Executive Summary\nb\n\n---\n_Narrative by live LLM; fact tables deterministic._\n"


class ContainmentReachesTheModel(unittest.TestCase):
    def test_host_statuses_reach_the_model(self):
        g = FusionGraph(case_id="c")
        g.host_status = {"DESKTOP-16OJFO6": "quarantined"}
        self.assertEqual(llm_sim.analyst_context(graph=g)["analyst_host_status"], {"DESKTOP-16OJFO6": "quarantined"})

    def test_the_model_is_told_when_nothing_is_contained(self):
        # qa test: an Open case with no host status got "the case has been contained".
        g = FusionGraph(case_id="c")
        g.host_status, g.case_status = {}, "open"
        ctx = llm_sim.analyst_context(graph=g)
        self.assertEqual(ctx["analyst_case_status"], "open")
        self.assertIn("none recorded", ctx["analyst_host_status"])
        self.assertNotIn("analyst_case_status", llm_sim.analyst_context(graph=FusionGraph(case_id="c")))
        src = open(os.path.join(_ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        self.assertEqual(src.count('g.case_status = case_info(d)["case_status"]'), 2)   # fuse + view graph
        self.assertEqual(src.count('gv.case_status = getattr(g, "case_status", None)'), 2)

    def test_no_report_type_is_left(self):
        for f in ("services/fusion/llm_sim.py", "services/fusion/store.py", "routes/case_routes.py"):
            src = open(os.path.join(_ROOT, "modules/backend", f), encoding="utf-8").read()
            self.assertNotIn("report_type", src, f)
            self.assertNotIn("report_basis", src, f)
        self.assertFalse(os.path.exists(os.path.join(_ROOT, "modules/backend/services/fusion/report_types.py")))


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}
        self.t = iter(f"2026-09-29T10:{m:02d}:00" for m in range(60))

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((rh, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock()),
                        (store, "_now_iso", lambda: next(self.t))):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def test_each_report_is_kept_once_newest_first(self):
        a = rh.archive("c1", TEMPLATE)
        self.assertIsNone(rh.archive("c1", TEMPLATE))              # reused by a Refusion: not twice
        b = rh.archive("c1", AI)
        self.assertEqual([(x["id"], x["label"], x["kind"]) for x in rh.history(self.d)],
                         [(b["id"], "Report", "ai"), (a["id"], "Report", "template")])
        self.assertEqual(rh.read("c1", b["id"]), AI)
        self.assertIsNone(rh.read("c1", "../../etc/passwd"))
        self.assertNotIn("type", self.d["report_history"][0])

    def test_one_entry_per_timeframe_a_newer_report_replaces_it(self):
        # "why there are 2 when i just enter data once": the first scan's template
        # report and the AI report written over it were two entries.
        a = rh.archive("c1", TEMPLATE, "full", "2016-09-24 → 2026-09-24")
        b = rh.archive("c1", AI, "full", "2016-09-24 → 2026-09-24")
        self.assertEqual(b["id"], a["id"])                          # the same entry, updated
        h = rh.history(self.d)
        self.assertEqual([(x["id"], x["kind"], x["scope_label"]) for x in h], [(a["id"], "ai", "2016-09-24 → 2026-09-24")])
        self.assertEqual(rh.read("c1", a["id"]), AI)
        self.assertIsNone(rh.archive("c1", AI, "full", "x"))        # the same text again: nothing
        c = rh.archive("c1", TEMPLATE, "s1", "2025-10-05 → 2025-10-22")   # another timeframe: its own
        self.assertNotEqual(c["id"], a["id"])
        d = rh.archive("c1", AI.replace("b", "full again"), "full", "2016-09-24 → 2026-09-24")
        self.assertEqual([x["id"] for x in rh.history(self.d)], [a["id"], c["id"]])   # updated one is newest
        self.assertEqual(d["id"], a["id"])
        self.assertEqual(len(self.d["report_history"]), 2)

    def test_reports_kept_while_stages_and_types_existed_keep_their_label(self):
        old = {"report_history": [
            {"id": "0123456789ab", "stage": "final", "at": "2026-09-29T09:00:00"},
            {"id": "0123456789cd", "type": "customer", "at": "2026-09-29T11:25:00", "kind": "ai"},
            {"id": "0123456789ef", "type": "directors", "at": "2026-09-29T11:26:00", "kind": "ai"},
            {"id": "0123456789aa", "type": "technical", "at": "2026-09-29T11:23:00", "kind": "ai"},
            {"id": "not-an-id", "at": "2026-09-29T12:00:00"}]}
        self.assertEqual([x["label"] for x in rh.history(old)],
                         ["Directors", "Technical customers", "Technical", "Final"])
        self.assertEqual(rh.history({"report_history": "junk"}), [])
        self.assertEqual(rh.history(None), [])

    def test_same_second_the_later_is_current_and_delete(self):
        with mock.patch.object(store, "_now_iso", lambda: "2026-09-29T10:00:00"):
            a = rh.archive("c1", TEMPLATE)
            b = rh.archive("c1", AI)
        self.assertEqual([x["id"] for x in rh.history(self.d)], [b["id"], a["id"]])
        self.assertEqual(rh.delete("c1", a["id"]), {"deleted": a["id"]})
        self.assertEqual(rh.delete("c1", a["id"]), {"error": "no such report"})
        rh.delete_case_reports("c1")
        self.assertFalse(os.path.exists(rh._dir("c1")))


class Page(unittest.TestCase):
    def test_no_type_choice_and_history_labels(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        src = open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        self.assertNotIn('id="rp-type"', src)
        self.assertNotIn("report_type", src)
        self.assertIn("body:JSON.stringify({use_llm:true})", src)
        js = ("const esc=s=>String(s); const window={};\n" + re.search(r"const _rpLab=.*?;\n", src).group(0)
              + re.search(r"function reportHistoryHtml\(.*?\n\}", src, re.S).group(0) + """
const H=[{id:'0123456789ab',label:'Report',at:'2026-09-30T10:12:00',kind:'ai',scope_label:'2016-09-24 → 2026-09-24'},
         {id:'0123456789cd',label:'Final',at:'2026-09-28T08:00:00',kind:'ai'}];
console.log(JSON.stringify([reportHistoryHtml({case_id:'c1', report_history:H}, null),
  reportHistoryHtml({case_id:'c1', report_history:H}, {id:'0123456789ab', label:'Report', at:'2026-09-30T10:12:00'}),
  reportHistoryHtml({case_id:'c1', report_history:H}, {id:'0123456789cd', label:'Final', at:'2026-09-28T08:00:00'})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertNotIn(">Report</span>", out[0])                       # a new report needs no label
        self.assertIn(">2016-09-24 → 2026-09-24</span>", out[0])          # its timeframe
        self.assertIn(">Final</span>", out[0])                            # an old stage report keeps it
        self.assertIn("Viewing the report of 2026-09-30 10:12 UTC — the current report", out[1])
        self.assertIn("● Viewing", out[1])
        self.assertIn(">View</button>", out[1])
        self.assertIn("Viewing the <b>Final</b> report of 2026-09-28 08:00 UTC — not the current one", out[2])


if __name__ == "__main__":
    unittest.main()
