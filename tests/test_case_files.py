"""Evidence (plan step 6): files attached to a case, each with a name and a
description (required), SHA-256, host / time / source, and the Timeline event it
belongs to when attached from there. "Include in AI" is off by default.
"""
import hashlib
import io
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
from services.fusion import case_files, correlate, llm_sim, store  # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402

TS = "2026-09-01T07:20:51Z"


def _graph():
    g = FusionGraph(case_id="c1")
    g.entities["asset:endpoint:C.1"] = Entity(id="asset:endpoint:C.1", type="asset", label="DESKTOP-16OJFO6")
    g.findings.append(Finding(id="f_row", title="SIGMA: AnyDesk Silent Installation (+1 related) on DESKTOP-16OJFO6",
                              severity="high", confidence="high", summary="", ts=TS,
                              asset_ids=["asset:endpoint:C.1"],
                              parts=[correlate._part("p1", "A", TS, None, 1, "1|" + TS, [], "high")]))
    return g


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((case_files, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock()),
                        (store, "load_graph", lambda cid: _graph())):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)
        self.behind = mock.patch.object(store, "_report_behind").start()
        self.addCleanup(mock.patch.stopall)

    def add(self, file_name, data, **kw):
        kw.setdefault("name", "AnyDesk prompt")
        kw.setdefault("description", "the silent-install prompt on the desktop")
        return case_files.add("c1", io.BytesIO(data), file_name, **kw)

    def test_name_and_description_are_required(self):
        for kw in ({"name": ""}, {"description": "  "}):
            self.assertIn("name and a description", self.add("a.png", b"x", **kw)["error"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "c1")) and os.listdir(os.path.join(self.tmp, "c1")))

    def test_from_the_timeline_only_the_file_is_needed(self):
        it = case_files.add("c1", io.BytesIO(b"img"), "IMG_9.png", name="", description="", finding_id="f_row")
        self.assertEqual(it["name"], "SIGMA: AnyDesk Silent Installation (+1 related) — screenshot")   # made from the event
        self.assertEqual(it["description"], "")
        log = case_files.add("c1", io.BytesIO(b"x"), "fw.log", name="", description="", finding_id="f_row")
        self.assertTrue(log["name"].endswith("— log"))
        self.behind.assert_called()                                    # the report is now behind

    def test_the_report_lists_the_evidence_once_before_its_footer(self):
        self.add("popup.png", b"img", finding_id="f_row", name="", description="")
        self.add("fw.csv", b"a", name="Kibana export", description="firewall rules", host="ALDC02", source="kibana")
        md = "# Report\n\n## Findings\n- x\n\n---\n_Deterministic report — no model_\n"
        once = case_files.with_evidence(md, self.d)
        self.assertEqual(case_files.with_evidence(once, self.d), once)          # rebuilt, never repeated
        self.assertEqual(once.count("## Evidence attached to this case"), 1)
        self.assertLess(once.index("## Evidence attached"), once.index("---\n_Deterministic report"))
        self.assertIn("supports: SIGMA: AnyDesk Silent Installation", once)
        self.assertIn("**Kibana export** — ALDC02 · from kibana", once)
        self.assertIn("SHA-256 `" + hashlib.sha256(b"img").hexdigest() + "`", once)
        self.assertLess(once.index("screenshot"), once.index("Kibana export"))  # linked items first
        self.assertEqual(case_files.with_evidence(md, {"name": "none"}), md)    # no evidence: unchanged
        self.assertNotIn("Evidence attached", case_files.with_evidence(once, {"name": "none"}))   # all deleted: section goes

    def test_a_manual_item_keeps_what_was_typed(self):
        it = self.add("ts-export.csv", b"a,b", host="ALDC02", time="2026-09-01T08:00:00Z", source="timesketch")
        self.assertEqual((it["host"], it["time"], it["source"], it["kind"], it["ai"], it["finding_id"]),
                         ("ALDC02", "2026-09-01T08:00:00Z", "timesketch", "text", False, ""))
        self.assertEqual(it["sha256"], hashlib.sha256(b"a,b").hexdigest())
        self.assertEqual(it["file_name"], "ts-export.csv")

    def test_attached_from_the_timeline_the_case_fills_host_time_and_event(self):
        it = self.add("popup.png", b"img", finding_id="f_row", host="SPOOFED", source="other")
        self.assertEqual((it["host"], it["time"], it["source"], it["finding_id"]),
                         ("DESKTOP-16OJFO6", TS, "timeline", "f_row"))
        self.assertIn("AnyDesk Silent Installation", it["finding_title"])
        self.assertEqual(self.add("p.png", b"i", finding_id="p1")["finding_id"], "f_row")   # a part links to its row
        self.assertIn("not in the case", self.add("x.png", b"i", finding_id="gone")["error"])
        self.assertEqual(case_files.per_finding(self.d), {"f_row": 2})

    def test_edit_unlink_and_delete(self):
        it = self.add("popup.png", b"img", finding_id="f_row")
        up = case_files.update("c1", it["id"], {"name": "Renamed", "ai": True, "finding_id": ""})
        self.assertEqual((up["name"], up["ai"], up["finding_id"], up["finding_title"]), ("Renamed", True, "", ""))
        self.assertIn("cannot be empty", case_files.update("c1", it["id"], {"name": " "})["error"])
        self.assertIn("source", case_files.update("c1", it["id"], {"source": "email"})["error"])
        p = case_files.path_of("c1", it["id"])
        self.assertEqual(case_files.delete("c1", it["id"]), {"deleted": it["id"]})
        self.assertFalse(os.path.exists(p))

    def test_limits_and_ids(self):
        self.assertIn("empty", self.add("a.txt", b"")["error"])
        with mock.patch.object(case_files, "MAX_BYTES", 4):
            self.assertIn("larger", self.add("a.txt", b"12345")["error"])
        for bad in ("../../etc/passwd", "..", "", "ABCDEF123456"):
            self.assertIsNone(case_files.path_of("c1", bad))

    def test_only_flagged_items_reach_the_model_with_their_event(self):
        pic = self.add("popup.png", b"img", finding_id="f_row")
        log = self.add("fw.log", b"line1", name="Firewall log", description="exported from Kibana", source="kibana")
        self.add("secret.txt", b"not for the model", name="Private", description="x")
        case_files.update("c1", pic["id"], {"ai": True})
        case_files.update("c1", log["id"], {"ai": True})
        got = case_files.for_model("c1", self.d)
        self.assertEqual(got[0], {"evidence": "AnyDesk prompt", "file": "popup.png", "type": "image",
                                  "description": "the silent-install prompt on the desktop",
                                  "host": "DESKTOP-16OJFO6", "time": TS, "source": "timeline",
                                  "supports_finding": _graph().findings[0].title})
        self.assertEqual(got[1]["text"], "line1")
        self.assertNotIn("Private", json.dumps(got))
        g = FusionGraph(case_id="c1")
        g.case_files = got
        self.assertEqual(llm_sim.analyst_context(graph=g)["analyst_attached_files"], got)

    def test_older_and_damaged_items(self):
        # the first version of this feature: name = file name, no description / host
        old = {"case_files": [{"id": "0123456789ab", "name": "IMG_1.png", "size": 3, "sha256": "ab", "kind": "image"}]}
        it = case_files.listing(old)[0]
        self.assertEqual((it["name"], it["file_name"], it["description"], it["source"]), ("IMG_1.png", "IMG_1.png", "", "other"))
        self.assertEqual(case_files.listing({"case_files": "junk"}), [])
        self.assertEqual(case_files.listing({"case_files": [5, {"id": "../x", "name": "a"}]}), [])
        self.assertEqual(case_files.per_finding({"name": "old"}), {})


class Page(unittest.TestCase):
    def run_js(self, calls):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        parts = [re.search(r"const EV_SOURCES=.*?;\n", src).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0)
                 for n in ("_evFields", "_evItem", "renderEvidence", "_evList", "_evHostList")] + \
                [re.search(r"function %s\(.*?\}\n" % n, src).group(0) for n in ("_evSize", "_evSrc")]
        js = ("const esc=s=>String(s); const window={}; let OUT=''; const $=()=>({set innerHTML(v){OUT=v}});"
              "const api=()=>Promise.resolve({rows:[]}); let curInfo=null;\n" + "\n".join(parts) + "\n" + calls)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            return json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)

    def test_grouped_by_host_linked_items_jump_to_the_event_ai_off(self):
        out = self.run_js("""
const it=(id,name,host,fid,ai)=>({id,name,description:'d',file_name:name+'.png',size:2048,sha256:'ab'.repeat(32),kind:'image',ai:!!ai,host,time:'',source:fid?'timeline':'other',finding_id:fid||'',finding_title:fid?'SIGMA: AnyDesk':''});
curInfo={case_id:'c1', case_files:[it('0123456789a1','Kibana export','ALDC02'), it('0123456789a2','Popup','DESKTOP-16OJFO6','f_row'), it('0123456789a3','Customer mail','')]};
renderEvidence(curInfo); const all=OUT;
window._evFilter='f_row'; renderEvidence(curInfo); const one=OUT;
curInfo={case_id:'c1', case_files:'junk'}; window._evFilter=''; renderEvidence(curInfo); const bad=OUT;
const form=_evFields('evn',{},true,false), linked=_evFields('eva',{},true,true);
console.log(JSON.stringify([all, one, bad, form, linked]));""")
        all_, one, bad, form, linked = out
        self.assertLess(all_.index("ALDC02"), all_.index("DESKTOP-16OJFO6"))          # grouped by host, A-Z
        self.assertLess(all_.index("DESKTOP-16OJFO6"), all_.index("Not linked to a host"))   # unlinked last
        self.assertIn("evGoEvent('f_row')", all_)
        self.assertNotIn('style="width:auto" checked', all_)                          # Include in AI: off
        self.assertIn("Evidence for: <b>SIGMA: AnyDesk</b>", one)
        self.assertNotIn("Kibana export", one)                                         # filtered to that event
        self.assertIn("No evidence yet", bad)                                          # damaged: empty, no crash
        self.assertIn('id="evn-file"', form)                                          # the add form: file,
        self.assertIn("Name <span style=\"color:var(--crit)\">*", form)               # name and description required
        self.assertIn("Description <span style=\"color:var(--crit)\">*", form)
        self.assertIn('id="evn-host" list="ev-hosts"', form)                           # host picked or typed
        self.assertNotIn("evn-host", linked.replace("eva", "evn"))                     # from the Timeline: host comes from the event

    def test_the_timeline_row_shows_its_evidence_count(self):
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("evShowFor('${esc(r.finding_id)}')\">📎 ${r.evidence}", src)
        self.assertIn("📎 Attach evidence", src)


if __name__ == "__main__":
    unittest.main()
