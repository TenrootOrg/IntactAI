"""Jev's suggested verdict: asked once per change, shown only when it is sure,
never on a finding a person already judged, and never in the fuse's way.

A fuse runs after every landing run and every verdict click, so the suggestion
pass must be incremental (ask only about findings whose occurrences moved) and
must run after the fuse lock is released — it is a network call, and the next
fuse must not queue behind it. A chip on a stale or unsure answer, or on a
finding someone already triaged, would be noise at best.
"""
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
from services.fusion import jev, store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid, occ=1, kind="single"):
    return Finding(id=fid, title=f"T {fid}", severity="high", confidence="medium",
                   summary="s", kind=kind, occ_count=occ, occ_latest="2026-09-01")


def _ans(label, conf=0.9):
    return {"choice": label, "confidence": conf,
            "probabilities": {label: conf, "true_positive": 1 - conf}}


class SuggestDispositions(unittest.TestCase):
    def run_pass(self, d, findings, answers):
        g = types.SimpleNamespace(findings=findings, entities={})
        asked = []

        def fake_ask_each(items, render, question, **kw):
            asked.extend(f.id for f in items)
            return [answers.get(f.id) for f in items]
        with mock.patch.object(jev, "ask_each", fake_ask_each), \
             mock.patch.object(jev, "finding_state", lambda g, f: {"id": f.id}), \
             mock.patch.object(jev, "min_confidence", return_value=0.8), \
             mock.patch.object(store, "log_case_event") as self.logged, \
             mock.patch.object(store, "_merge_case_details") as merge:
            n = jev.suggest_dispositions("c1", d, g)
        self.merged = merge.call_args.args[1] if merge.called else None
        written = self.merged["jev_suggestions"] if merge.called else None
        return n, asked, written

    def test_only_unjudged_changed_findings_are_asked(self):
        a, b, c, e = _f("a"), _f("b", occ=3), _f("c"), _f("e", kind="dispositioned")
        d = {"timeline_validations": [{"finding_id": "c", "status": "known"}],
             "jev_suggestions": {"a": {"wm": a.watermark(), "label": "known"},
                                 "b": {"wm": "1|old", "label": "known"},
                                 "gone": {"wm": "1|x", "label": "known"}}}
        n, asked, written = self.run_pass(d, [a, b, c, e], {"b": _ans("true_positive")})
        self.assertEqual(asked, ["b"])          # a unchanged, c judged, e dispositioned
        self.assertEqual(written["b"]["label"], "true_positive")
        self.assertEqual(written["b"]["wm"], b.watermark())
        self.assertIn("a", written)
        self.assertNotIn("gone", written)       # findings that vanished are dropped

    def test_nothing_to_do_writes_nothing(self):
        a = _f("a")
        n, asked, written = self.run_pass(
            {"jev_suggestions": {"a": {"wm": a.watermark()}}}, [a], {})
        self.assertEqual((n, asked, written), (0, [], None))

    def test_a_failed_or_odd_answer_is_not_stored(self):
        n, asked, written = self.run_pass({}, [_f("a"), _f("b")],
                                          {"a": None, "b": {"choice": "banana"}})
        self.assertEqual(asked, ["a", "b"])
        self.assertIsNone(written)


class Notice(unittest.TestCase):
    """Findings Jev is SURE are malicious, not yet reviewed: a notice, logged once."""

    def test_notice_holds_confident_true_positives_and_logs_only_new_ones(self):
        t = SuggestDispositions()
        a, b, c = _f("a"), _f("b"), _f("c")
        d = {"jev_suggestions": {"a": {"wm": a.watermark(), "label": "true_positive", "confidence": 0.9}}}
        t.run_pass(d, [a, b, c], {"b": _ans("true_positive", 0.95), "c": _ans("true_positive", 0.5)})
        self.assertEqual([n["id"] for n in t.merged["jev_notice"]], ["a", "b"])   # c is unsure
        self.assertEqual(t.logged.call_args.kwargs["finding_ids"], ["b"])         # a was already known
        self.assertIn("T b", t.logged.call_args.args[3])

    def test_reviewed_findings_drop_out_and_off_shows_nothing(self):
        d = {"jev_notice": [{"id": "a", "title": "A"}, {"id": "b", "title": "B"}],
             "timeline_validations": [{"finding_id": "a", "status": "known"}]}
        with mock.patch.object(jev, "enabled", return_value=True):
            self.assertEqual(jev.unreviewed_notice(d), [{"id": "b", "title": "B"}])
        with mock.patch.object(jev, "enabled", return_value=False):
            self.assertEqual(jev.unreviewed_notice(d), [])


class SuggestionFor(unittest.TestCase):
    def test_stale_unsure_or_absent_gives_no_chip(self):
        s = {"f": {"wm": "2|t", "label": "known", "p": 0.93, "confidence": 0.9}}
        with mock.patch.object(jev, "min_confidence", return_value=0.8):
            self.assertEqual(jev.suggestion_for(s, "f", "2|t"), {"label": "known", "p": 0.93})
            self.assertIsNone(jev.suggestion_for(s, "f", "3|t"))
            self.assertIsNone(jev.suggestion_for(s, "x", "2|t"))
        with mock.patch.object(jev, "min_confidence", return_value=0.95):
            self.assertIsNone(jev.suggestion_for(s, "f", "2|t"))


class Timeline(unittest.TestCase):
    def rows(self, enabled):
        f1, f2 = _f("f1"), _f("f2")
        d = {"timeline_validations": [{"finding_id": "f2", "status": "known",
                                       "watermark": f2.watermark()}],
             "jev_suggestions": {k: {"wm": f.watermark(), "label": "known", "p": 0.9,
                                     "confidence": 0.9} for k, f in (("f1", f1), ("f2", f2))}}
        g = types.SimpleNamespace(findings=[f1, f2])
        with mock.patch.object(store, "get_case", return_value=d), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch.object(store, "view_window", return_value=None), \
             mock.patch.object(store.render, "timeline",
                               return_value=[{"finding_id": "f1"}, {"finding_id": "f2"}]), \
             mock.patch.object(jev, "enabled", return_value=enabled), \
             mock.patch.object(jev, "min_confidence", return_value=0.8):
            return {r["finding_id"]: r["jev"] for r in store.get_timeline("c1")}

    def test_chip_only_on_unjudged_findings_while_enabled(self):
        self.assertEqual(self.rows(True), {"f1": {"label": "known", "p": 0.9}, "f2": None})
        self.assertEqual(self.rows(False), {"f1": None, "f2": None})


class FuseHook(unittest.TestCase):
    def test_runs_after_the_lock_and_only_on_success(self):
        seen = {}

        def locked(*a, **kw):
            return "G"

        def hook(cid):
            # The fuse lock is an RLock (re-entrant for its holder), so only
            # ANOTHER thread can tell whether it is still held.
            import threading
            lk = store._fuse_lock(cid)

            def probe():
                got = lk.acquire(blocking=False)
                seen["locked_during_hook"] = not got
                if got:
                    lk.release()
            t = threading.Thread(target=probe)
            t.start()
            t.join()
        with mock.patch.object(store, "_fuse_case_locked", locked), \
             mock.patch.object(jev, "after_fuse", side_effect=hook) as af:
            self.assertEqual(store.fuse_case("c-hook", _record=False), "G")
        af.assert_called_once_with("c-hook")
        self.assertFalse(seen["locked_during_hook"])
        with mock.patch.object(store, "_fuse_case_locked", side_effect=RuntimeError("x")), \
             mock.patch.object(jev, "after_fuse") as af:
            with self.assertRaises(RuntimeError):
                store.fuse_case("c-hook", _record=False)
        af.assert_not_called()

    def test_disabled_starts_no_thread(self):
        with mock.patch.object(jev, "_cfg", return_value={}), \
             mock.patch.object(jev.threading, "Thread") as th:
            jev.after_fuse("c1")
        th.assert_not_called()


class Chip(unittest.TestCase):
    """The real _tlJev from cases.html, run in node (skips where node is absent)."""

    def test_chip_markup(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function _tlJev\(r\)\{.*?\n\}", src, re.S)
        note = re.search(r"function _jevNote\(info\)\{.*?\n\}", src, re.S)
        self.assertTrue(note, "_jevNote missing from cases.html")
        states = re.search(r"const TL_STATES=\[.*?\];", src)
        self.assertTrue(fn and states, "_tlJev / TL_STATES missing from cases.html")
        js = (states.group(0) + "\nconst esc=s=>String(s).replace(/[<>&'\"]/g,'');\n"
              + fn.group(0) + "\n" + note.group(0) + """
const out=[
  _tlJev({finding_id:'f1', jev:{label:'known', p:0.914}}),
  _tlJev({finding_id:'f1'}),
  _tlJev({finding_id:'f1', jev:{label:'nonsense', p:0.9}}),
  _jevNote({jev_unreviewed:[{id:'a',title:'Log Cleared on HOST1'},{id:'b',title:'Mimikatz on HOST1'}]}),
  _jevNote({jev_unreviewed:[]}),
  _jevNote(null),
];
console.log(JSON.stringify(out));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(t.name)
        import json
        chip, none, bad, notice, empty, nothing = json.loads(out)
        self.assertIn("<b>2</b> findings look malicious", notice)
        self.assertIn("Log Cleared · Mimikatz", notice)
        self.assertEqual((empty, nothing), ("", ""))
        self.assertIn("Jev: likely Known · 91%", chip)
        self.assertIn("event.stopPropagation();tlValidate('f1','known')", chip)
        self.assertEqual((none, bad), ("", ""))


if __name__ == "__main__":
    unittest.main()
