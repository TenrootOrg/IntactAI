"""A cross-host group's verdict: one request, ONE re-fuse, one record per row.

A group header sets the same verdict on every host row it holds. Each row still
gets its own record with its own watermark (a verdict belongs to one host's
activity), and the whole change costs at most one re-fuse — the single-row path
re-fuses per click (~30 s), which a 9-host group would have made minutes.
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
from services.fusion import store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid, occ):
    return Finding(id=fid, title=f"T on {fid}", severity="high", confidence="medium",
                   summary="", occ_count=occ, occ_latest="2026-06-01T10:00:00Z")


class Many(unittest.TestCase):
    def run_it(self, ids, status, dispositions=()):
        state = {"timeline_validations": [], "dispositions": list(dispositions)}
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: fn(state)

        def mut(cid, field, fn):
            state[field] = fn(list(state.get(field) or []))
        g = types.SimpleNamespace(findings=[_f("a", 2), _f("b", 5), _f("c", 1)])
        with mock.patch.object(store, "get_case", side_effect=lambda cid: dict(state)), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_mutate_list_field", side_effect=mut), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(store, "_report_behind"), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "fuse_case") as fuse:
            store.validate_timeline_many("c1", ids, status)
        return state, fuse.call_count

    def test_false_positive_on_three_rows_is_one_refuse_and_three_records(self):
        state, fuses = self.run_it(["a", "b", "c"], "false_positive")
        self.assertEqual(fuses, 1)
        self.assertEqual({v["finding_id"]: v["watermark"] for v in state["timeline_validations"]},
                         {"a": "2|2026-06-01T10:00:00Z", "b": "5|2026-06-01T10:00:00Z",
                          "c": "1|2026-06-01T10:00:00Z"})
        self.assertEqual(sorted(d["target"] for d in state["dispositions"]), ["a", "b", "c"])

    def test_true_positive_with_nothing_to_clear_does_not_refuse(self):
        state, fuses = self.run_it(["a", "b"], "true_positive")
        self.assertEqual(fuses, 0)
        self.assertEqual(len(state["timeline_validations"]), 2)

    def test_true_positive_clears_suppression_with_one_refuse(self):
        state, fuses = self.run_it(["a", "b"], "true_positive",
                                   dispositions=[{"target": "a"}, {"target": "b"}, {"target": "z"}])
        self.assertEqual(fuses, 1)
        self.assertEqual([d["target"] for d in state["dispositions"]], ["z"])

    def test_the_single_row_path_is_the_same_code(self):
        with mock.patch.object(store, "validate_timeline_many") as many:
            store.validate_timeline("c1", "a", "known")
        many.assert_called_once_with("c1", ["a"], "known", "")


class Header(unittest.TestCase):
    """The real _tlGroupHead / tlPaint from cases.html, run in node."""

    def test_group_renders_as_a_header_over_its_rows(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = [re.search(rf"function {n}\(.*?\n\}}", src, re.S).group(0)
               for n in ("_tlRow", "_tlGroupHead", "tlPaint")]
        js = ("const esc=s=>String(s);const TL_STATES=[['pending','Pending'],['true_positive','TP'],"
              "['false_positive','FP'],['known','Known']];const _tlUntil=()=>'';const _tlJev=()=>'';"
              "const _tlTitle=r=>r.title;let OUT='';const $=()=>({set innerHTML(v){OUT=v}});\n"
              + "\n".join(fns) + """
const G={id:'g1',name:'Encoded PowerShell',hosts:2,link:'time only'};
const rows=[{finding_id:'a',ts:'10:30',host:'H1',title:'x',severity:'high',group:G},
            {finding_id:'p',ts:'10:32',host:'H3',title:'y',severity:'high'},
            {finding_id:'b',ts:'10:35',host:'H2',title:'x',severity:'high',group:G,validation:'known'}];
window={_tlData:rows}; const tlVisible=()=>rows;
tlPaint(); const open=OUT; window._tlClosed={g1:true}; tlPaint(); const shut=OUT;
console.log(JSON.stringify([open, shut]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            r = subprocess.run([node, t.name], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            open_, shut = json.loads(r.stdout)
        finally:
            os.unlink(t.name)
        self.assertEqual(open_.count("tlgroup"), 1)
        self.assertIn("2 hosts, 2 rows", open_)
        self.assertIn("linked by time only", open_)
        self.assertIn("1 of 2 reviewed", open_)
        self.assertIn("tlValidateMany([&quot;a&quot;,&quot;b&quot;],'false_positive')", open_)
        # the group's rows sit together under its header; the ungrouped row after
        self.assertLess(open_.index("tlValidate('b'"), open_.index("tlValidate('p'"))
        self.assertNotIn("tlValidate('a'", shut)            # collapsed: host rows hidden
        self.assertIn("tlValidate('p'", shut)               # ungrouped row still shown


if __name__ == "__main__":
    unittest.main()
