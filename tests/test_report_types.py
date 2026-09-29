"""Report types — who the report is for: Technical (us), Technical customers,
Directors — three different documents, and the history of every report written.
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
from services.fusion import case_files, llm_sim, report_types as rt, store  # noqa: E402
from services.fusion.schema import FusionGraph  # noqa: E402

TEMPLATE = ("# Incident Case Report — qa\n\n## Executive Summary\nsum\n\n## Attack Assessment\na\n\n"
            "## Timeline of Events\n- t\n\n## Host Risk — who to focus on first\n- h\n\n"
            "## Indicators of Compromise (IOCs)\n- i\n\n## MITRE ATT&CK Mapping\n- m\n\n"
            "## Analyst Validations\n- v\n\n## Recommendations\n- r\n\n---\n_Deterministic report — no model_\n")
AI = ("# Incident Case Report — qa\n\n## Bottom Line\nb\n\n## Decisions Needed\nd\n\n"
      "## Analyst Validations\n- v\n\n## Timeline of Events\n- t\n\n## MITRE ATT&CK Mapping\n- m\n\n"
      "## Indicators of Compromise (IOCs)\n- i\n\n## Host Risk — who to focus on first\n- h\n\n"
      "## Limitations & Assumptions\n- l\n\n---\n_Narrative by live LLM; fact tables deterministic._\n")


def heads(md):
    return [h[3:] for h in re.findall(r"^## .*", md, re.M)]


class Types(unittest.TestCase):
    def test_default_is_technical_and_a_choice_is_kept(self):
        for d in ({"name": "old"}, {"report_type": "bogus"}, {"report_stage": "final"}, None):
            self.assertEqual(rt.type_of(d), "technical")
        self.assertEqual(rt.type_of({"report_type": "directors"}), "directors")

    def test_each_reader_gets_its_own_instructions(self):
        self.assertEqual(rt.directive("technical"), "")                        # the full report as it was
        c, d = rt.directive("customer"), rt.directive("directors")
        for h in ("## Summary", "## What Happened", "## Affected Assets", "## Indicators to Block and Hunt",
                  "## Remediation Steps", "## Detection & Monitoring"):
            self.assertIn(h, c)
        for h in ("## Bottom Line", "## Business Impact", "## What We Have Done", "## Decisions Needed",
                  "## Next Steps"):
            self.assertIn(h, d)
        self.assertIn("NO technical language", d)
        self.assertIn("No tables", d)
        for x in (c, d):
            self.assertIn("marked False Positive is NOT part of the incident", x)
            self.assertIn("no product or feature names", x)
        src = open(os.path.join(_ROOT, "modules/backend/services/fusion/llm_sim.py"), encoding="utf-8").read()
        self.assertIn("if report_type:\n                audience = \"both\"", src)   # replaces the old tone setting

    def test_title_and_banner_name_the_reader_and_are_never_repeated(self):
        once = rt.apply(AI, "directors")
        self.assertTrue(once.startswith("# Directors Report — qa\n\n_Report for: **Directors** — executives"))
        again = rt.apply(once, "technical")
        self.assertIn("# Technical Report — qa\n", again)
        self.assertEqual(again.count("_Report for:"), 1)
        old = "# Flash Report — qa\n\n_Report stage: **Flash** — initial notification._\n\n## Bottom Line\nx\n"
        self.assertNotIn("Report stage", rt.apply(old, "customer"))           # the earlier stage banner goes too

    def test_directors_get_no_tables_and_no_evidence(self):
        ai = rt.apply(AI, "directors")
        self.assertEqual(heads(ai), ["Bottom Line", "Decisions Needed"])       # what the model wrote, only
        self.assertIn("_Narrative by live LLM", ai)
        self.assertEqual(heads(rt.apply(TEMPLATE, "directors")), ["Executive Summary", "Attack Assessment", "Recommendations"])
        d = {"report_type": "directors", "include_evidence": True,
             "case_files": [{"id": "0123456789ab", "name": "Popup", "sha256": "x", "file_name": "p.png"}]}
        self.assertNotIn("Evidence attached", case_files.with_evidence("# R\n\n## Bottom Line\nx\n", d))
        d["report_type"] = "customer"
        self.assertIn("Evidence attached", case_files.with_evidence("# R\n\n## Summary\nx\n", d))

    def test_technical_customers_lose_our_internals_keep_what_they_act_on(self):
        ai = rt.apply(AI, "customer", {"DESKTOP-16OJFO6": "isolated"}, "contained")
        h = heads(ai)
        for gone in ("Analyst Validations", "Host Risk — who to focus on first"):
            self.assertNotIn(gone, h)
        for kept in ("Timeline of Events", "MITRE ATT&CK Mapping", "Indicators of Compromise (IOCs)", "Containment Status"):
            self.assertIn(kept, h)
        self.assertIn("| DESKTOP-16OJFO6 | Quarantined |", ai)
        self.assertEqual(rt.apply(ai, "customer").count("## Containment Status"), 1)   # rebuilt, never doubled
        self.assertNotIn("Containment Status", rt.apply(ai, "technical"))
        tmpl = heads(rt.apply(TEMPLATE, "customer"))
        self.assertNotIn("Analyst Validations", tmpl)
        self.assertIn("Indicators of Compromise (IOCs)", tmpl)

    def test_technical_keeps_everything(self):
        self.assertEqual(heads(rt.apply(AI, "technical")), heads(AI))

    def test_outside_readers_do_not_see_how_we_built_it(self):
        head = ("# Incident Case Report — qa\n\n> **All timestamps are UTC.**\n\n| | |\n|---|---|\n"
                "| **Hosts in scope** | 1 |\n| **Entities correlated** | 468 across 112 links |\n\n\n"
                "_**Focused report** — one scope, analysed in depth. Every finding below is inside this window._\n\n"
                "## Summary\nx\n\n_Report detail: **explicit** (set for this case)._\n\n"
                "---\n_Narrative by live LLM; fact tables deterministic._\n")
        c, d, t = (rt.apply(head, x) for x in ("customer", "directors", "technical"))
        for gone in ("Focused report", "Report detail", "Entities correlated"):
            self.assertNotIn(gone, c)
            self.assertNotIn(gone, d)
            self.assertIn(gone, t)
        self.assertIn("| **Hosts in scope** | 1 |", c)
        self.assertNotIn("Hosts in scope", d)
        self.assertNotIn("timestamps are UTC", d)
        self.assertIn("_Narrative by live LLM", d)             # the footer tells an AI report from a template
        again = rt.apply(c, "customer", {"h1": "isolated"})
        self.assertIn("| **Hosts in scope** | 1 |", again)       # re-shaping keeps the statistics
        self.assertEqual(again.count("## Containment Status"), 1)
        self.assertLess(again.index("Hosts in scope"), again.index("## Containment Status"))
        self.assertNotIn("\n\n\n", again)

    def test_the_pdf_cover_names_the_reader(self):
        src = open(os.path.join(_ROOT, "modules/backend/services/engagement/pdf.py"), encoding="utf-8").read()
        self.assertIn(r"_Report for: \*\*(Technical customers|Directors|Technical)\*\*", src)

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
        for t in ("customer", "directors"):
            self.assertIn("containment has not been recorded yet", rt.directive(t))
        src = open(os.path.join(_ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        self.assertEqual(src.count('g.case_status = case_info(d)["case_status"]'), 2)   # fuse + view graph
        self.assertEqual(src.count('gv.case_status = getattr(g, "case_status", None)'), 2)


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}
        self.t = iter(f"2026-09-29T10:{m:02d}:00" for m in range(60))

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((rt, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock()),
                        (store, "_now_iso", lambda: next(self.t))):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def test_each_report_is_kept_once_newest_first_with_its_label(self):
        a = rt.archive("c1", rt.apply(TEMPLATE, "directors"), "directors")
        self.assertIsNone(rt.archive("c1", rt.apply(TEMPLATE, "directors"), "directors"))   # reused: not twice
        b = rt.archive("c1", rt.apply(AI, "customer"), "customer")
        h = rt.history(self.d)
        self.assertEqual([(x["id"], x["label"], x["kind"]) for x in h],
                         [(b["id"], "Technical customers", "ai"), (a["id"], "Directors", "template")])
        self.assertIsNone(rt.read("c1", "../../etc/passwd"))

    def test_reports_from_the_stage_version_keep_their_label(self):
        old = {"report_history": [{"id": "0123456789ab", "stage": "final", "at": "2026-09-29T09:00:00"},
                                  {"id": "0123456789cd", "stage": "flash", "at": "2026-09-29T08:00:00"}]}
        self.assertEqual([x["label"] for x in rt.history(old)], ["Final", "Flash"])

    def test_same_second_the_later_is_current_and_delete(self):
        with mock.patch.object(store, "_now_iso", lambda: "2026-09-29T10:00:00"):
            a = rt.archive("c1", TEMPLATE, "technical")
            b = rt.archive("c1", AI, "directors")
        self.assertEqual([x["id"] for x in rt.history(self.d)], [b["id"], a["id"]])
        self.assertEqual(rt.delete("c1", a["id"]), {"deleted": a["id"]})
        rt.delete_case_reports("c1")
        self.assertFalse(os.path.exists(rt._dir("c1")))
        self.assertEqual(rt.history({"report_history": "junk"}), [])


class Page(unittest.TestCase):
    def test_selector_and_history_labels(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        src = open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        self.assertIn("${so('technical','Technical (us)')}${so('customer','Technical customers')}${so('directors','Directors')}", src)
        self.assertIn("report_type:_rt||undefined", src)
        js = ("const esc=s=>String(s); const window={};\n" + re.search(r"const RP_LABEL=\{.*?\};", src).group(0)
              + "\n" + re.search(r"function reportHistoryHtml\(.*?\n\}", src, re.S).group(0) + """
const H=[{id:'0123456789ab',type:'directors',label:'Directors',at:'2026-09-29T10:12:00',kind:'ai'},
         {id:'0123456789cd',type:'',label:'Final',at:'2026-09-28T08:00:00',kind:'ai'}];
console.log(JSON.stringify([reportHistoryHtml({case_id:'c1', report_history:H}, null),
  reportHistoryHtml({case_id:'c1', report_history:H}, {id:'0123456789ab', label:'Directors', at:'2026-09-29T10:12:00'})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn(">Directors</span>", out[0])
        self.assertIn(">Final</span>", out[0])                                  # an old stage report
        self.assertIn("Viewing the <b>Directors</b> report", out[1])


if __name__ == "__main__":
    unittest.main()
