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


class NewHostIsNeverAutoJudged(unittest.TestCase):
    """Asked in review: "if I add new hosts in the same timeframe, will they be
    True Positive automatically?" — No: the group verdict covered only the rows
    that existed; the new host's row arrives Pending."""

    def test_group_marked_true_positive_then_a_new_host_arrives_pending(self):
        import test_timeline_episodes as T
        from services.fusion import jev
        a = [T._row("HOSTA", "2026-06-01T10:30:00Z", rec=1)]
        b = [T._row("HOSTB", "2026-06-01T10:40:00Z", rec=2)]
        c = [T._row("HOSTC", "2026-06-01T10:50:00Z", rec=3)]
        g1 = T._fuse(a, b)
        vals = [{"finding_id": f.id, "status": "true_positive", "watermark": f.watermark()}
                for f in g1.findings if "Encoded PowerShell" in f.title]
        g2 = T._fuse(a, b, c)
        case = {"timeline_validations": vals}
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "view_graph", return_value=g2), \
             mock.patch.object(store, "view_window", return_value=None), \
             mock.patch.object(jev, "enabled", return_value=False):
            rows = [r for r in store.get_timeline("c1") if "Encoded PowerShell" in r["title"]]
        status = {r["host"]: r["validation"] for r in rows}
        self.assertEqual(status, {"HOSTA": "true_positive", "HOSTB": "true_positive",
                                  "HOSTC": "pending"})
        self.assertEqual(len({r["group"]["id"] for r in rows}), 1)      # all three in one group


class GroupNews(unittest.TestCase):
    """Asked in review: when a group gains rows — a new host, the severity lowered,
    more artifacts, more hits — the analyst must be TOLD."""

    def _f(self, fid, wm_occ=1):
        return Finding(id=fid, title=f"x on {fid}", severity="high", confidence="m", summary="",
                       occ_count=wm_occ, occ_latest="2026-06-01T10:00:00Z")

    def test_never_reviewed_group_shows_rows_that_joined_after_it_appeared(self):
        fmap = {"a": self._f("a"), "b": self._f("b"), "c": self._f("c")}
        seen = {"a": "2026-09-27T08:00:00Z", "b": "2026-09-27T08:00:00Z", "c": "2026-09-27T09:00:00Z"}
        n = store._group_news(["a", "b", "c"], fmap, seen, {})
        self.assertEqual((n["new"], n["reviewed"]), (["c"], False))

    def test_a_review_clears_it_and_later_growth_brings_it_back(self):
        fmap = {"a": self._f("a", 5), "b": self._f("b")}
        seen = {"a": "2026-09-27T08:00:00Z", "b": "2026-09-27T09:00:00Z"}
        ack = {"a": {"at": "2026-09-27T09:30:00Z", "wm": "5|2026-06-01T10:00:00Z"},
               "b": {"at": "2026-09-27T09:30:00Z", "wm": "1|2026-06-01T10:00:00Z"}}
        self.assertEqual(store._group_news(["a", "b"], fmap, seen, ack), {})
        fmap["a"] = self._f("a", 9)                       # more hits after the review
        n = store._group_news(["a", "b"], fmap, seen, ack)
        self.assertEqual((n["new"], n["grown"], n["reviewed"]), ([], ["a"], True))

    def test_fuse_records_first_seen_and_logs_a_group_that_gained_a_row(self):
        grp = {"id": "g", "name": "Encoded PowerShell", "rows": ["a", "c"]}
        g = types.SimpleNamespace(findings=[Finding(id="a", title="t", severity="high", confidence="m",
                                                    summary="", asset_ids=["asset:A"], group=grp),
                                            Finding(id="c", title="t", severity="high", confidence="m",
                                                    summary="", asset_ids=["asset:C"], group=grp)],
                                  entities={})
        written = {}
        with mock.patch.object(store, "get_case", return_value={"row_seen": {"a": "2026-09-27T08:00:00Z",
                                                                             "gone": "x"}}), \
             mock.patch.object(store, "_merge_case_details",
                               side_effect=lambda cid, p: written.update(p)), \
             mock.patch.object(store, "log_case_event") as log:
            store._track_rows("c1", g)
        self.assertEqual(set(written["row_seen"]), {"a", "c"})          # vanished rows pruned
        self.assertEqual(written["row_seen"]["a"], "2026-09-27T08:00:00Z")
        self.assertIn("gained new rows", log.call_args.args[1])
        self.assertIn("+1 row", log.call_args.args[3])

    def test_a_verdict_counts_as_a_review(self):
        with mock.patch.object(store, "ack_rows") as ack, \
             mock.patch.object(store, "get_case", return_value={}), \
             mock.patch.object(store, "load_graph", return_value=types.SimpleNamespace(findings=[])), \
             mock.patch.object(store, "_mutate_list_field"), \
             mock.patch.object(store, "_report_behind"), \
             mock.patch.object(store, "log_case_event"):
            store.validate_timeline_many("c1", ["a", "b"], "true_positive")
        self.assertEqual(ack.call_args.args[1], ["a", "b"])


class Header(unittest.TestCase):
    """The real _tlGroupHead / tlPaint from cases.html, run in node."""

    def test_group_renders_as_a_header_over_its_rows(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fns = [re.search(r"const _TL_SEVS=\[.*?\];", src).group(0)] + [re.search(rf"function {n}\(.*?\n\}}", src, re.S).group(0)
               for n in ("_tlRow", "_tlRowHtml", "_tlParts", "_tlPartsToggle", "_tlSevChip", "_tlGroupHead", "tlPaint", "_tlUntil", "_tlGroupNews", "_tlLoggedAs", "_tlGroupJev")]
        js = ("const esc=s=>String(s);const TL_STATES=[['pending','Pending'],['true_positive','TP'],"
              "['false_positive','FP'],['known','Known']];const _tlJev=()=>'';"
              "const _tlTitle=r=>r.title;let OUT='';const $=()=>({set innerHTML(v){OUT=v}});\n"
              + "\n".join(fns) + """
const G={id:'g1',name:'Encoded PowerShell',hosts:2,link:'time only',news:{new:['b'],grown:[],since:'2026-09-27T08:00:00Z',reviewed:true}};
const rows=[{finding_id:'a',ts:'10:30',host:'H1',title:'x',severity:'high',group:G},
            {finding_id:'p',ts:'10:32',host:'H3',title:'y',severity:'high'},
            {finding_id:'b',ts:'10:35',host:'H2',title:'x',severity:'high',group:G,validation:'known',is_new:true},
            {finding_id:'u',ts:null,host:'H3',title:'web',severity:'high'}];
window={_tlData:rows}; const tlVisible=()=>rows;
const agree=_tlGroupHead(G,[{finding_id:'a',validation:'known'},{finding_id:'b',validation:'known'}],false);
tlPaint(); const shut=OUT; window._tlOpen={g1:true}; tlPaint(); const open=OUT;
window._tlf={order:'severity'}; tlPaint(); const bysev=OUT;
console.log(JSON.stringify([open, shut, bysev, agree]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            r = subprocess.run([node, t.name], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            open_, shut, bysev, agree = json.loads(r.stdout)
        finally:
            os.unlink(t.name)
        self.assertEqual(open_.count("tlgroup"), 1)
        self.assertIn("H1, H2", open_)                     # the header names the hosts
        self.assertIn("2 hosts · 2 rows · 2 hits", open_)
        self.assertEqual(open_.count('class="tlgrp'), 1)          # one visible block
        self.assertIn('class="tlgkids"', open_)                   # its rows inside the block
        self.assertIn("linked by time only", open_)
        self.assertIn("1 of 2 reviewed", open_)
        self.assertIn("tlValidateMany([&quot;a&quot;,&quot;b&quot;],'false_positive')", open_)
        # the group can be set back to Pending; a mixed group lights no button
        self.assertIn("tlValidateMany([&quot;a&quot;,&quot;b&quot;],'pending')", open_)
        head = open_[open_.index("tlgroup"):open_.index("tlgkids")]
        self.assertNotIn(" on\"", head)
        self.assertIn('class="s-known on"', agree)                # every row Known -> Known lit
        # the group's rows sit together under its header; the ungrouped row after
        self.assertLess(open_.index("tlValidate('b'"), open_.index("tlValidate('p'"))
        self.assertIn("tlgroup", shut)
        # the table says how a grouped row's severity is set
        self.assertIn("rated by their highest-severity part", shut)
        # undated rows sort last under a divider that says why (time order only)
        self.assertEqual(open_.count("<b>Undated</b>"), 1)
        self.assertLess(open_.index("tlValidate('p'"), open_.index("<b>Undated</b>"))
        self.assertLess(open_.index("<b>Undated</b>"), open_.index("tlValidate('u'"))
        self.assertNotIn("<b>Undated</b>", bysev)
        self.assertIn('class="tlgrp hasnew"', shut)                  # the block turns amber
        self.assertIn("NEW since your review: +1 new row (H2)", shut)  # visible even collapsed
        self.assertIn("tlMarkSeen(", shut)
        self.assertIn("NEW</span> <strong>H2</strong>", open_)       # row b is tagged NEW
        self.assertNotIn("NEW</span> <strong>H1</strong>", open_)    # row a is not
        self.assertNotIn("tlValidate('a'", shut)            # collapsed BY DEFAULT: host rows hidden
        self.assertIn("tlValidate('a'", open_)
        self.assertIn("tlValidate('p'", shut)               # ungrouped row still shown


if __name__ == "__main__":
    unittest.main()
