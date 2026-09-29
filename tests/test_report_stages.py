"""Report stages and history (plan step 9): Flash / Interim / Final change how the
next report is written; every report written is kept with its stage and date, so
an Interim never overwrites the Final. Old cases: Interim, no history.
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
from services.fusion import llm_sim, report_stages as rs, store  # noqa: E402
from services.fusion.schema import FusionGraph  # noqa: E402

TEMPLATE = ("# Incident Case Report — qa\n\n## Executive Summary\nsum\n\n## Timeline of Events\n- t\n\n"
            "## Host Risk — who to focus on first\n- h\n\n## MITRE ATT&CK Mapping\n- m\n\n"
            "## Recommendations\n- r\n\n---\n_Deterministic report — no model_\n")
AI = TEMPLATE.replace("_Deterministic report — no model_", "_Narrative by live LLM; fact tables deterministic._")


class Stage(unittest.TestCase):
    def test_the_default_follows_the_case_status_and_a_choice_wins(self):
        self.assertEqual(rs.stage_of({"name": "old"}), "interim")                 # old case
        self.assertEqual(rs.stage_of({"case_status": "contained"}), "interim")
        self.assertEqual(rs.stage_of({"case_status": "closed"}), "final")
        self.assertEqual(rs.stage_of({"case_status": "closed", "report_stage": "flash"}), "flash")
        self.assertEqual(rs.stage_of({"report_stage": "bogus", "case_status": 5}), "interim")   # damaged
        self.assertEqual(rs.stage_of(None), "interim")

    def test_each_stage_tells_the_model_what_to_write(self):
        self.assertIn("## Next Update", rs.directive("flash"))
        self.assertIn("Do NOT write the per-finding catalogue", rs.directive("flash"))
        self.assertIn("## Status", rs.directive("interim"))
        self.assertIn("analyst_host_status", rs.directive("interim"))
        self.assertIn("## Lessons Learned", rs.directive("final"))
        self.assertEqual(rs.directive("bogus"), "")
        with open(os.path.join(_ROOT, "modules/backend/services/fusion/llm_sim.py"), encoding="utf-8") as fh:
            self.assertIn("system = system + \"\\n\\n\" + _d", fh.read())      # appended like the audience directive

    def test_the_banner_sits_under_the_title_and_is_never_repeated(self):
        once = rs.apply(AI, "interim")
        self.assertIn("# Incident Case Report — qa\n\n_Report stage: **Interim** — investigation ongoing._", once)
        again = rs.apply(once, "final")
        self.assertEqual(again.count("_Report stage:"), 1)
        self.assertIn("**Final** — case closed", again)

    def test_a_template_flash_keeps_only_its_short_sections(self):
        flash = rs.apply(TEMPLATE, "flash")
        for keep in ("## Executive Summary", "## Host Risk", "## Recommendations", "_Deterministic report — no model_"):
            self.assertIn(keep, flash)
        for drop in ("## Timeline of Events", "## MITRE ATT&CK Mapping"):
            self.assertNotIn(drop, flash)
        self.assertIn("## Timeline of Events", rs.apply(AI, "flash"))         # the model wrote its own Flash

    def test_host_statuses_reach_the_model(self):
        g = FusionGraph(case_id="c")
        g.host_status = {"DESKTOP-16OJFO6": "quarantined"}
        self.assertEqual(llm_sim.analyst_context(graph=g)["analyst_host_status"], {"DESKTOP-16OJFO6": "quarantined"})
        self.assertNotIn("analyst_host_status", llm_sim.analyst_context(graph=FusionGraph(case_id="c")))


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}
        self.t = iter(f"2026-09-29T10:{m:02d}:00" for m in range(60))

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((rs, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock()),
                        (store, "_now_iso", lambda: next(self.t))):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def test_each_report_is_kept_once_newest_first(self):
        a = rs.archive("c1", rs.apply(TEMPLATE, "flash"), "flash")
        self.assertIsNone(rs.archive("c1", rs.apply(TEMPLATE, "flash"), "flash"))     # a reused report: not twice
        b = rs.archive("c1", rs.apply(AI, "final"), "final")
        h = rs.history(self.d)
        self.assertEqual([x["id"] for x in h], [b["id"], a["id"]])
        self.assertEqual([(x["stage"], x["kind"]) for x in h], [("final", "ai"), ("flash", "template")])
        self.assertIn("**Flash**", rs.read("c1", a["id"]))
        self.assertIsNone(rs.read("c1", "../../etc/passwd"))

    def test_delete_one_and_a_whole_case(self):
        a = rs.archive("c1", AI, "interim")
        self.assertEqual(rs.delete("c1", a["id"]), {"deleted": a["id"]})
        self.assertEqual(rs.history(self.d), [])
        self.assertIsNone(rs.read("c1", a["id"]))
        self.assertIn("error", rs.delete("c1", a["id"]))
        rs.archive("c1", TEMPLATE, "interim")
        rs.delete_case_reports("c1")
        self.assertFalse(os.path.exists(rs._dir("c1")))

    def test_old_and_damaged_history(self):
        self.assertEqual(rs.history({"name": "old"}), [])
        self.assertEqual(rs.history({"report_history": "junk"}), [])
        h = rs.history({"report_history": [5, {"id": "../x"}, {"id": "0123456789ab", "stage": "??", "kind": "x"}]})
        self.assertEqual([(x["stage"], x["kind"]) for x in h], [("interim", "template")])


class Page(unittest.TestCase):
    def test_the_history_list_and_the_viewing_banner(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        js = ("const esc=s=>String(s); const window={};\n" + re.search(r"const RP_STAGE=\{.*?\};", src).group(0)
              + "\n" + re.search(r"function reportHistoryHtml\(.*?\n\}", src, re.S).group(0) + """
const H=[{id:'0123456789ab',stage:'final',at:'2026-09-29T10:12:00',kind:'ai'},{id:'0123456789cd',stage:'flash',at:'2026-09-28T08:00:00',kind:'template'}];
console.log(JSON.stringify([
  reportHistoryHtml({case_id:'c1'}, null),
  reportHistoryHtml({case_id:'c1', report_history:'junk'}, null),
  reportHistoryHtml({case_id:'c1', report_history:H}, null),
  reportHistoryHtml({case_id:'c1', report_history:H}, {id:'0123456789cd', stage:'flash', at:'2026-09-28T08:00:00'})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("none yet", out[0])
        self.assertIn("none yet", out[1])                                  # damaged: nothing, no crash
        self.assertIn("2 kept", out[2])
        self.assertIn("AI report · current", out[2])                       # the newest is the current one
        self.assertIn("/api/cases/c1/reports/0123456789cd/download?fmt=pdf", out[2])
        self.assertIn("Viewing the <b>Flash</b> report of 2026-09-28 08:00 UTC", out[3])
        self.assertIn("Back to the current report", out[3])
        self.assertIn('<select id="rp-stage"', src)


if __name__ == "__main__":
    unittest.main()
