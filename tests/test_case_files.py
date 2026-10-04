"""Evidence (plan step 6): files attached to a case, each with a name and a
description (required), SHA-256, host / time / source, and the Timeline event it
belongs to when attached from there. It goes into the report when the case's
switch is on, and never to the AI.
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
        self.assertEqual(case_files.with_evidence(md, self.d), md)                # switch off: no section
        self.d["include_evidence"] = True
        once = case_files.with_evidence(md, self.d)
        pic = next(x for x in case_files.listing(self.d) if x["kind"] == "image")
        self.assertIn(f"](evidence:{pic['id']})", once)                              # the picture is in the section
        self.assertEqual(once.count("](evidence:"), 1)                                # the CSV is not a picture
        self.d["include_evidence"] = False
        self.assertNotIn("Evidence attached", case_files.with_evidence(once, self.d))  # switched off: section goes
        self.d["include_evidence"] = True
        self.assertEqual(case_files.with_evidence(once, self.d), once)          # rebuilt, never repeated
        self.assertEqual(once.count("## Evidence attached to this case"), 1)
        self.assertLess(once.index("## Evidence attached"), once.index("---\n_Deterministic report"))
        self.assertIn("supports: SIGMA: AnyDesk Silent Installation", once)
        self.assertIn("**Kibana export** — ALDC02 · from kibana", once)
        self.assertIn("SHA-256 `" + hashlib.sha256(b"img").hexdigest() + "`", once)
        self.assertLess(once.index("screenshot"), once.index("Kibana export"))  # linked items first
        self.assertEqual(case_files.with_evidence(md, {"name": "none"}), md)    # no evidence: unchanged
        self.assertNotIn("Evidence attached", case_files.with_evidence(once, {"name": "none"}))   # all deleted: section goes

    def test_pictures_resolve_per_output(self):
        pic = self.add("popup.png", b"\x89PNGdata", finding_id="f_row", name="", description="")
        md = f"x\n\n![Popup](evidence:{pic['id']})\n\n![Gone](evidence:0000000000aa)\n"
        url = case_files.resolve_pictures(md, "c1", self.d, "url")
        self.assertIn(f"![Popup](/api/cases/c1/files/{pic['id']}?inline=1)", url)
        self.assertIn("_(picture removed: Gone)_", url)
        emb = case_files.resolve_pictures(md, "c1", self.d, "embed")
        import base64
        self.assertIn("![Popup](data:image/png;base64," + base64.b64encode(b"\x89PNGdata").decode() + ")", emb)
        with mock.patch.object(case_files, "EMBED_CAP", 3):
            self.assertIn("picture not embedded", case_files.resolve_pictures(md, "c1", self.d, "embed"))
        self.assertIn("_(picture: popup.png)_", case_files.resolve_pictures(md, "c1", self.d, "name"))

    def test_only_raster_pictures_are_ever_shown_inline(self):
        self.assertEqual(case_files.picture_mime("a.PNG"), "image/png")
        for bad in ("a.svg", "a.html", "a.htm", "a.txt", "a"):
            self.assertIsNone(case_files.picture_mime(bad), bad)

    def test_the_switch_is_off_for_old_and_damaged_cases(self):
        for d in ({"name": "old"}, {"include_evidence": "yes"}, {"include_evidence": 1}, None):
            self.assertFalse(case_files.included(d))
        self.assertTrue(case_files.included({"include_evidence": True}))

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

    def test_evidence_never_reaches_the_model(self):
        # "remove the AI ... no need since it had all the data in the timeline already"
        self.add("fw.log", b"line1", name="Firewall log", description="exported from Kibana", source="kibana")
        self.d["include_evidence"] = True
        self.assertFalse(hasattr(case_files, "for_model"))
        ctx = llm_sim.analyst_context(graph=FusionGraph(case_id="c1"))
        self.assertNotIn("analyst_attached_files", ctx)
        with open(os.path.join(_ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("case_files = ", src)
        self.assertIn("case_files.with_evidence(report", src)                  # the report keeps it

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
                 for n in ("_evFields", "_evThumb", "_evItem", "renderEvidence", "_evList", "_evHostList")] + \
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
        # a picture shows as a thumbnail that opens full size ("show the images minimized")
        self.assertIn('<img src="/api/cases/c1/files/0123456789a1?inline=1"', all_)
        self.assertIn('href="/api/cases/c1/files/0123456789a1?inline=1" target="_blank"', all_)
        self.assertIn('loading="lazy"', all_)
        self.assertNotIn("Include in AI", all_)                                        # one switch, not per item
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
        # one click: the button IS the file picker — no second "choose file" form
        self.assertIn("📎 Attach evidence<input type=\"file\" multiple", src)
        self.assertIn("fd.append('finding_id',fid)", src)
        self.assertNotIn("evAttachForm", src)


class ReportPictures(unittest.TestCase):
    def test_the_page_shows_only_this_cases_evidence_pictures(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = "\n".join(re.search(r"function %s\(s\)\{.*?\n" % n, src).group(0) for n in ("escape", "inline"))
        js = fns + """
console.log(JSON.stringify([
  inline('![Popup](/api/cases/case_1/files/0123456789ab?inline=1)'),
  inline('![x](https://evil.example/a.png)'),
  inline('![x](/api/cases/c/files/../../etc?inline=1)')]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn('<img src="/api/cases/case_1/files/0123456789ab?inline=1" alt="Popup"', out[0])
        self.assertNotIn("<img", out[1])                  # nothing external
        self.assertNotIn("<img", out[2])

    def test_the_analysis_tab_has_the_switch_and_the_html_download(self):
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("Include evidence in the report</label>", src)
        self.assertIn("dl('/report/download/html','HTML')", src)             # in the Export menu


class Paste(unittest.TestCase):
    def test_only_a_picture_on_the_clipboard_is_taken(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function _evPastedPicture\(e\)\{.*?\n\}", src, re.S).group(0)
        js = ("class File{constructor(p,n,o){this.name=n;this.type=o.type;}}\n" + fn + """
const ev=items=>({clipboardData:{items}});
const pic={kind:'file', type:'image/jpeg', getAsFile:()=>({type:'image/jpeg'})};
const txt={kind:'string', type:'text/plain', getAsFile:()=>null};
const doc={kind:'file', type:'application/pdf', getAsFile:()=>({type:'application/pdf'})};
const a=_evPastedPicture(ev([txt,pic])), b=_evPastedPicture(ev([txt])), c=_evPastedPicture(ev([doc])), d=_evPastedPicture({});
console.log(JSON.stringify([a&&a.name, a&&a.type, b, c, d]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertRegex(out[0], r"^pasted-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.jpg$")
        self.assertEqual(out[1], "image/jpeg")
        self.assertEqual(out[2:], [None, None, None])        # text / a PDF / nothing: normal paste
        self.assertIn("evPasteConfirm(window._fdFid, pic)", src)    # with an event open: asks first
        self.assertNotIn("evAttachFiles(window._fdFid,[pic])", src)  # never uploaded silently
        self.assertIn("Attach this pasted picture to the event?", src)


class PasteConfirm(unittest.TestCase):
    def test_paste_asks_first_attach_uses_the_edited_name_cancel_sends_nothing(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = "\n".join(re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0)
                        for n in ("evPasteConfirm", "evPasteCancel", "evPasteAttach"))
        js = ("""class File{constructor(p,n,o){this.name=n;this.type=o.type;}}
const esc=s=>String(s); const window={}; const URL={createObjectURL:()=>'blob:x',revokeObjectURL:()=>{}};
let BOX={innerHTML:''}; const inputs={}; const sent=[];
const $=sel=>sel==='#ev-attach'?BOX:(sel==='#ev-paste'?{remove(){BOX.innerHTML='';}}:null);
const document={getElementById:id=>inputs[id]||null};
const evAttachFiles=(fid,files)=>sent.push([fid,files.map(f=>f.name)]);
""" + fns + """
const pic=new File([], 'pasted-2026-09-29-10-00-00.png', {type:'image/png'});
evPasteConfirm('f_row', pic); const shown=BOX.innerHTML; const before=sent.length;
inputs['ev-paste-name']={value:'anydesk-popup'}; evPasteAttach('f_row');
evPasteConfirm('f_row', pic); evPasteCancel(); 
console.log(JSON.stringify([shown.includes('value="pasted-2026-09-29-10-00-00.png"'), before, sent]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertTrue(out[0])                                   # the box shows the file name
        self.assertEqual(out[1], 0)                               # nothing sent before Attach
        self.assertEqual(out[2], [["f_row", ["anydesk-popup.png"]]])   # edited name, extension kept; cancel sent nothing


if __name__ == "__main__":
    unittest.main()
