"""Identities: the analyst marks a person compromised / not compromised.

Stored against the person's ACCOUNTS (the card key is a union-find root that can
change when accounts are merged), kept across re-fusion, cleared with "".
"""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, schema, store  # noqa: E402


class Store(unittest.TestCase):
    def setUp(self):
        self.d = {}

        def mutate(cid, field, fn):
            self.d[field] = fn(list(self.d.get(field) or []))
        self.p = [mock.patch.object(store, "get_case", return_value={"x": 1}),
                  mock.patch.object(store, "_mutate_list_field", mutate),
                  mock.patch.object(store, "log_case_event")]
        self.log = [p.start() for p in self.p][2]

    def tearDown(self):
        for p in self.p:
            p.stop()

    def test_set_replace_clear(self):
        store.set_identity_verdict("c", ["a1", "a2"], "compromised", name="kobia")
        self.assertIn("kobia marked compromised", self.log.call_args.args[1])
        # a later card holding a2 + a3 (merged) finds it, and a new verdict replaces it
        self.assertEqual(store._identity_verdict_for(self.d["identity_verdicts"], ["a3", "a2"])["verdict"],
                         "compromised")
        store.set_identity_verdict("c", ["a2", "a3"], "not_compromised")
        self.assertEqual([r["verdict"] for r in self.d["identity_verdicts"]], ["not_compromised"])
        store.set_identity_verdict("c", ["a3"], "")
        self.assertEqual(self.d["identity_verdicts"], [])
        self.assertIsNone(store._identity_verdict_for([], ["a1"]))

    def test_bad_input_is_refused(self):
        self.assertIn("error", store.set_identity_verdict("c", [], "compromised"))
        self.assertIn("error", store.set_identity_verdict("c", ["a"], "owned"))
        self.assertNotIn("identity_verdicts", self.d)


class Reach(unittest.TestCase):
    def test_findings_on_what_the_account_executed_count(self):
        g = schema.FusionGraph(case_id="c")
        g.relate(schema.Relationship("acc", "ev1", "executed"))
        g.relate(schema.Relationship("acc", "proc", "executed"))
        g.relate(schema.Relationship("proc", "det", "event_about"))       # a detection raised on its process
        g.relate(schema.Relationship("other", "ev2", "executed"))
        g.relate(schema.Relationship("proc2", "det2", "event_about"))     # someone else's process
        self.assertEqual(identities.person_reach(g, ["acc"]), {"acc", "ev1", "proc", "det"})


class Downstream(unittest.TestCase):
    """A person marked compromised reaches the deterministic report and every model call."""

    def _g(self):
        g = schema.FusionGraph(case_id="c")
        g.upsert(schema.Entity(id="acc1", type="account", label="CORP\\kobia"))
        g.upsert(schema.Entity(id="acc1b", type="account", label="CORP\\kobia"))   # same label, other host
        g.identity_verdicts = [{"accounts": ["acc1", "acc1b"], "name": "kobia", "verdict": "compromised"},
                               {"accounts": ["gone"], "name": "old", "verdict": "compromised"}]
        return g

    def test_report_section_recommendation_and_model_context(self):
        from services.fusion import llm_sim, render
        g = self._g()
        self.assertEqual(render.identity_verdict_lines(g), [("compromised", "kobia — CORP\\kobia")])
        md = render._analyst_validations_md(g, None, None)
        self.assertIn("**Identities marked compromised (1):**", md)
        self.assertNotIn("old", md)                              # its accounts left the graph
        recs = render._recommendations_md(g, [], [])
        self.assertIn("Treat these identities as compromised", recs)
        ctx = llm_sim.analyst_context(graph=g)
        self.assertEqual(ctx["analyst_identity_verdicts"],
                         [{"identity": "kobia — CORP\\kobia", "verdict": "compromised"}])
        self.assertNotIn("analyst_identity_verdicts", llm_sim.analyst_context(graph=schema.FusionGraph(case_id="c")))

    def test_view_graph_carries_them(self):
        d = {"identity_verdicts": [{"accounts": ["a"], "verdict": "compromised"}]}
        with mock.patch.object(store, "load_graph", return_value=schema.FusionGraph(case_id="c")):
            g = store.view_graph("c", d)
        self.assertEqual(g.identity_verdicts[0]["verdict"], "compromised")

    def test_host_and_window_filters_keep_them(self):
        # the report written during a Refusion filters the graph itself (no
        # view_graph); the host filter dropped the verdicts on the way
        g = self._g()
        g.upsert(schema.Entity(id="asset:H", type="asset", label="H"))
        self.assertEqual(store._filter_graph_by_hosts(g, ["H"]).identity_verdicts, g.identity_verdicts)
        w = {"start": "2026-01-01T00:00:00Z", "end": "2026-02-01T00:00:00Z"}
        self.assertEqual(store._filter_graph_by_window(g, w).identity_verdicts, g.identity_verdicts)

    def test_manual_events_reach_the_no_llm_report(self):
        from services.fusion import render
        g = schema.FusionGraph(case_id="c")
        g.manual_events = [{"ts": "2026-01-02T10:00:00Z", "host": "H1", "title": "IT pushed a GPO",
                            "severity": "low", "notes": "change ticket 42"}]
        md = render._analyst_validations_md(g, None, None)
        self.assertIn("**Events added by the analyst (1):**", md)
        self.assertIn("`2026-01-02T10:00:00Z` · H1 · IT pushed a GPO [low] — change ticket 42", md)
        # an event on an excluded host is not carried
        d = {"manual_timeline_events": [{"host": "H1", "title": "a"}, {"host": "H2", "title": "b"}],
             "excluded_hosts": ["h2"]}
        self.assertEqual([e["title"] for e in store._visible_manual_events(d)], ["a"])


class Card(unittest.TestCase):
    def test_verdict_select(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        js = r"""
const fs=require("fs"); const src=fs.readFileSync(process.argv[1],"utf8");
eval(src.match(/const ID_VERDICTS=\[.*?\];/s)[0].replace("const ","var ")); eval(src.match(/function idVerdictSel\(cid,it\)\{[\s\S]*?\n\}/)[0]);
const esc=s=>String(s), jsa=s=>String(s);
console.log(JSON.stringify([idVerdictSel("c1",{key:"k",verdict:"compromised"}), idVerdictSel("c1",{key:"k"})]));"""
        out = subprocess.run([node, "-e", js, os.path.join(_ROOT, "modules/nginx/html/cases.html")],
                             capture_output=True, text=True, check=True).stdout
        import json
        on, off = json.loads(out)
        self.assertIn('class="vsel v-compromised"', on)
        self.assertIn('<option value="compromised" selected>Compromised</option>', on)
        self.assertIn("idVerdict('c1','k',this.value)", on)
        self.assertIn('<option value="" selected>Not reviewed</option>', off)
        self.assertIn('v-none', off)
    def test_host_rows_link_both_ways(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        js = r"""
const fs=require("fs"); const src=fs.readFileSync(process.argv[1],"utf8");
for (const n of ["_entHosts","_hostPeople","_idJev","_riskWhy","_vchip","_hostStatusSelect","_hostStatusTags"]) eval(src.match(new RegExp("function "+n+"\\([^)]*\\)\\{[\\s\\S]*?\\n\\}"))[0]);
const esc=s=>String(s), jsa=s=>String(s);
eval(src.match(/const HOST_STATUS_LABEL=\{.*?\};/)[0].replace("const ", "var "));   // the host-status helpers read it
const people=[{key:"k1",name:"kobia",verdict:"compromised",seen_on:["WS1"],jev_compromise:0.9,worst:"high"},
              {key:"k2",name:"amy",seen_on:["WS1","WS2"]}];
const rows=[{host:"WS1",severity:"critical",risk_score:100,by_severity:{critical:1,high:2},finding_count:3,row_count:9,
             why:"Mimikatz on WS1; Odd service on WS1",escalate:true,next_action:"Deep-dive now",modules:["velociraptor"]},
            {host:"WS2",severity:"high",risk_score:60,by_severity:{high:1},finding_count:1,row_count:1,why:"x",modules:[]}];
var window={_idData:{sort:"jev"},_hostExpand:{WS1:true}};
console.log(_entHosts(rows,_hostPeople(people),{rows}));"""
        out = subprocess.run([node, "-e", js, os.path.join(_ROOT, "modules/nginx/html/cases.html")],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.count('class="prow'), 2)
        self.assertIn('class="prow v-compromised"', out)             # someone marked compromised was there
        self.assertIn("entOpenPerson('k1')", out)                    # host -> person
        self.assertIn("Mimikatz", out)
        self.assertIn("Odd service", out)                            # expanded: every top finding
        self.assertIn("Deep-dive now", out)
        self.assertIn('<span class="vchip c">compromised</span>', out)
        self.assertIn("Also seen:", out)                              # people without findings on one line
        self.assertIn("Why it ranks #1", out)
        self.assertIn("· Likely", out)
        self.assertIn(">escalate<", out)
        self.assertIn("<b>1</b> crit", out)


if __name__ == "__main__":
    unittest.main()
