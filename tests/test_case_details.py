"""Case details (plan step 3): name, status, severity, owner, description.
Labels only. Cases from older versions — and upgraded machines keep theirs — have
none of these fields and must read as Open / unset, never fail.
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
from services.fusion import store  # noqa: E402


class OldCases(unittest.TestCase):
    def test_a_case_from_an_older_version_reads_as_open_and_unset(self):
        self.assertEqual(store.case_info({"name": "old"}),
                         {"case_status": "open", "case_owner": "", "case_description": ""})
        # a severity stored on a case from before it was removed is ignored
        self.assertNotIn("case_severity", store.case_info({"case_severity": "high"}))

    def test_damaged_values_fall_back_instead_of_failing(self):
        info = store.case_info({"case_status": 7, "case_severity": "huge", "case_owner": ["x"],
                                "case_description": None})
        self.assertEqual(info, {"case_status": "open", "case_owner": "", "case_description": ""})
        self.assertEqual(store.case_info(None)["case_status"], "open")


class Save(unittest.TestCase):
    def run_it(self, fields, case=None):
        case = {"name": "qa test"} if case is None else case
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "_merge_case_details") as merge, \
             mock.patch.object(store, "log_case_event") as log, \
             mock.patch.object(store, "fuse_case") as fuse:
            res = store.update_case_info("c1", fields)
        fuse.assert_not_called()                                   # labels only
        return res, (merge.call_args.args[1] if merge.called else None), log

    def test_fields_are_saved_and_logged(self):
        res, patch, log = self.run_it({"name": " Acme IR ", "case_status": "Contained", "case_severity": "HIGH",
                                       "case_owner": "Dan", "case_description": "ransomware on 3 hosts"})
        self.assertEqual(patch, {"name": "Acme IR", "case_status": "contained",          # no severity any more
                                 "case_owner": "Dan", "case_description": "ransomware on 3 hosts"})
        self.assertEqual((res["case_status"], res["name"]), ("contained", "Acme IR"))
        log.assert_called_once()

    def test_only_the_given_fields_change(self):
        _, patch, _ = self.run_it({"case_owner": "Dan"})
        self.assertEqual(patch, {"case_owner": "Dan"})

    def test_bad_values_save_nothing(self):
        for bad in ({"case_status": "finished"}, {"case_severity": "high"}, {"name": "  "}, {}):
            res, patch, _ = self.run_it(bad)
            self.assertIn("error", res, bad)
            self.assertIsNone(patch, bad)

    def test_the_built_in_cases_keep_their_names(self):
        for case in ({"name": "Default", "is_default": True}, {"name": "System"}):
            res, patch, _ = self.run_it({"name": "Renamed"}, case)
            self.assertIn("cannot be renamed", res["error"])
            self.assertIsNone(patch)
        res, patch, _ = self.run_it({"name": "Default", "case_status": "closed"}, {"name": "Default"})
        self.assertEqual(patch["case_status"], "closed")          # same name + other fields: fine

    def test_an_unknown_case(self):
        with mock.patch.object(store, "get_case", return_value=None):
            self.assertEqual(store.update_case_info("nope", {"case_owner": "x"}), {"error": "case not found"})


class Page(unittest.TestCase):
    def test_header_line_and_box_cope_with_missing_and_bad_fields(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        parts = [re.search(r"const CASE_STATUS_LABEL=\{.*?\};", src).group(0),
                 re.search(r"let _cdEdit=null, _cdDraft=\{\};", src).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0) for n in ("caseMetaHtml", "caseEditForm")]
        js = "const esc=s=>String(s);\n" + "\n".join(parts) + """
console.log(JSON.stringify([
  caseMetaHtml({name:'old case'}),
  caseMetaHtml({case_status:'contained', case_severity:'high', case_owner:'Dan', case_description:'ransomware'}),
  caseMetaHtml({case_status:5, case_severity:'huge', case_owner:['x'], case_description:null}),
  caseMetaHtml(null),
  caseEditForm({case_id:'c1', name:'Default', is_default:true}),
  caseEditForm({case_id:'c2', name:'qa', case_status:'bogus'}),
  (()=>{ _cdDraft={'cdf-owner':'typed before a redraw'}; return caseEditForm({case_id:'c2', name:'qa', case_owner:'saved'}); })()]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn(">Open<", out[0])
        self.assertIn(">Contained<", out[1])
        for o in out:
            self.assertNotIn("chip c-", o)                        # no case severity shown anywhere
            self.assertNotIn("Severity", o)
            self.assertNotIn("cdf-sev", o)
        self.assertIn("Description <span", out[5])               # "(optional)"
        self.assertIn("(optional)", out[5])
        self.assertIn("owner: Dan", out[1])
        self.assertIn(">Open<", out[2])                          # damaged: defaults, no crash
        self.assertNotIn("huge", out[2])
        self.assertIn(">Open<", out[3])
        self.assertIn('id="cdf-name" value="Default" maxlength="100" disabled style="opacity:.5', out[4])
        self.assertIn("The built-in Default case keeps its name.", out[4])
        self.assertNotIn("keeps its name", out[5])
        self.assertNotIn("disabled", out[5].split('id="cdf-name"')[1].split(">")[0])
        self.assertIn('onclick="event.stopPropagation()"', out[5])    # a click in the form never switches case
        self.assertIn('<option value="open" selected>', out[5])         # damaged status: Open
        self.assertIn('value="typed before a redraw"', out[6])          # typing survives a list redraw
        self.assertNotIn("caseDetailsBox", src)                         # not in the Analysis rail any more



class CreateAsksForTheDetails(unittest.TestCase):
    """The New Case pop-up asks for the owner and an optional description, not just
    a name that then had to be edited. A new case is always Open; no severity. Runs the REAL route (case_routes needs Flask,
    so its source runs here with a stub request)."""
    SRC = open(os.path.join(_ROOT, "modules/backend/routes/case_routes.py"), encoding="utf-8").read()

    def post(self, body):
        fn = re.search(r'@case_bp.route\("/api/cases", methods=\["POST"\]\)\ndef create_case\(\):.*?(?=\n\n\n)', self.SRC, re.S).group(0)
        fn = fn.split("\n", 1)[1]                                   # drop the decorator
        made, saved = [], []
        ns = {"request": mock.Mock(get_json=lambda silent=True: body), "jsonify": lambda x: x, "store": store}
        with mock.patch.object(store, "create_case", lambda name, **kw: made.append(name) or "case_new"), \
                mock.patch.object(store, "update_case_info", lambda cid, f: saved.append((cid, f)) or {}):
            exec(fn, ns)
            out = ns["create_case"]()
        return out, made, saved

    def test_the_details_are_saved_with_the_new_case(self):
        out, made, saved = self.post({"name": "IR 05", "case_status": "contained", "case_severity": "high",
                                      "case_owner": "Dan", "case_description": "phishing"})
        self.assertEqual(out, {"case_id": "case_new", "status": "created"})
        # status and severity are not taken at creation: a new case is Open
        self.assertEqual(saved, [("case_new", {"case_owner": "Dan", "case_description": "phishing"})])

    def test_a_name_alone_still_works(self):                      # the API and older callers
        out, made, saved = self.post({"name": "IR 05"})
        self.assertEqual((made, saved), (["IR 05"], []))

    def test_the_page_sends_every_field_and_the_selector_opens_the_form(self):
        html = open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        dlg = re.search(r'<dialog id="ncdlg">.*?</dialog>', html, re.S).group(0)
        for i in ('id="cname"', 'id="cowner"', 'id="cdesc"'):
            self.assertIn(i, dlg)                                      # in the pop-up, not always open
            self.assertEqual(html.count(i), 1)
        for gone in ('id="cstatus"', 'id="csev"', "Severity", "Status"):
            self.assertNotIn(gone, dlg)                                # always Open; no severity
        self.assertIn("(optional)", dlg.split('id="cdesc"')[0].rsplit("<label>", 1)[1])
        self.assertIn('onclick="openNewCase()"', html)
        if not shutil.which("node"):
            self.skipTest("no node on this host")
        fn = re.search(r"function createWorkspace\(\)\{.*?\n\}", html, re.S).group(0)
        js = """
const vals={cname:' IR 05 ',cowner:' Dan ',cdesc:' phishing '};
const $=s=>({value:vals[s.slice(1)]}); let sent=null;
const api=(p,o)=>{sent=JSON.parse(o.body); return {then(){return {catch(){}};}};}; const toast=()=>{};
""" + fn + "\ncreateWorkspace(); console.log(JSON.stringify(sent));"
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True)
        self.assertEqual(json.loads(out.stdout), {"name": "IR 05", "case_owner": "Dan", "case_description": "phishing"},
                         out.stderr)
        ac = open(os.path.join(_ROOT, "modules/nginx/html/js/active-case.js"), encoding="utf-8").read()
        self.assertNotIn("prompt('New case name", ac)
        self.assertIn("app.switchTab('cases')", ac)

if __name__ == "__main__":
    unittest.main()
