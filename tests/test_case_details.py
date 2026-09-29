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
                         {"case_status": "open", "case_severity": "", "case_owner": "", "case_description": ""})

    def test_damaged_values_fall_back_instead_of_failing(self):
        info = store.case_info({"case_status": 7, "case_severity": "huge", "case_owner": ["x"],
                                "case_description": None})
        self.assertEqual(info, {"case_status": "open", "case_severity": "", "case_owner": "",
                                "case_description": ""})
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
        self.assertEqual(patch, {"name": "Acme IR", "case_status": "contained", "case_severity": "high",
                                 "case_owner": "Dan", "case_description": "ransomware on 3 hosts"})
        self.assertEqual((res["case_status"], res["name"]), ("contained", "Acme IR"))
        log.assert_called_once()

    def test_only_the_given_fields_change(self):
        _, patch, _ = self.run_it({"case_owner": "Dan"})
        self.assertEqual(patch, {"case_owner": "Dan"})

    def test_bad_values_save_nothing(self):
        for bad in ({"case_status": "finished"}, {"case_severity": "urgent"}, {"name": "  "}, {}):
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
        parts = [re.search(r"const CASE_STATUS_LABEL=\{.*?\};", src).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0) for n in ("caseMetaHtml", "caseDetailsBox")]
        js = "const esc=s=>String(s);\n" + "\n".join(parts) + """
console.log(JSON.stringify([
  caseMetaHtml({name:'old case'}),
  caseMetaHtml({case_status:'contained', case_severity:'high', case_owner:'Dan', case_description:'ransomware'}),
  caseMetaHtml({case_status:5, case_severity:'huge', case_owner:['x'], case_description:null}),
  caseMetaHtml(null),
  caseDetailsBox({case_id:'c1', name:'Default', is_default:true}),
  caseDetailsBox({case_id:'c2', name:'qa'})]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn(">Open<", out[0])
        self.assertNotIn("chip", out[0])                         # no severity set: no chip
        self.assertIn(">Contained<", out[1])
        self.assertIn('class="chip c-high"', out[1])
        self.assertIn("owner: Dan", out[1])
        self.assertIn(">Open<", out[2])                          # damaged: defaults, no crash
        self.assertNotIn("huge", out[2])
        self.assertIn(">Open<", out[3])
        self.assertIn('id="cd-name" value="Default" maxlength="100" disabled', out[4])
        self.assertNotIn("disabled", out[5].split('id="cd-name"')[1].split(">")[0])
        self.assertIn('oninput="event.stopPropagation()"', out[5])   # never marks the Refusion rail edited


if __name__ == "__main__":
    unittest.main()
