"""Jev's estimate on the scope cards: asked after the fuse, cached per exact set
of findings, shown only when current — and the cards stay deterministic.

The cards load on every visit to the Analysis tab, so they must never wait on
a network call: the estimate is computed by the post-fuse pass and only read
here. A window whose findings changed (new occurrence, finding added) must
show no number until Jev is asked again — a stale percentage on a changed
window is worse than none. With Jev off the cards are exactly as before.
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
from services.fusion import jev, store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid, occ=1):
    return Finding(id=fid, title=f"T {fid}", severity="high", confidence="high", summary="",
                   occ_count=occ, occ_latest="2026-09-01")


def _cards(*groups):
    return [{"n": i + 1, "finding_ids": list(ids), "host_labels": ["H"], "window": {}}
            for i, ids in enumerate(groups)] + [{"rollup": True, "finding_ids": ["x"]}]


class Suggest(unittest.TestCase):
    def run_pass(self, d, findings, cards, answers):
        g = types.SimpleNamespace(findings=findings, entities={})
        asked = []

        def fake_ask_each(items, render, question, **kw):
            asked.extend(tuple(z["finding_ids"]) for z, _ in items)
            return [answers.get(tuple(z["finding_ids"])) for z, _ in items]
        with mock.patch.object(store, "scope_cards", return_value=("macro", "", cards, g)), \
             mock.patch.object(jev, "ask_each", fake_ask_each), \
             mock.patch.object(jev, "_scope_state", lambda z, by, g: {}), \
             mock.patch.object(store, "_merge_case_details") as merge:
            jev.suggest_scopes("c1", d)
        return asked, (merge.call_args.args[1]["jev_scopes"] if merge.called else None)

    def test_asks_each_new_window_once_never_the_rollup(self):
        a, b = _f("a"), _f("b")
        asked, saved = self.run_pass({}, [a, b], _cards(["a"], ["b"]),
                                     {("a",): {"noul": 0.82}, ("b",): {"noul": 0.1}})
        self.assertEqual(asked, [("a",), ("b",)])
        self.assertEqual(sorted(saved.values()), [0.1, 0.82])
        asked, saved2 = self.run_pass({"jev_scopes": saved}, [a, b], _cards(["a"], ["b"]), {})
        self.assertEqual((asked, saved2), ([], None))              # cached, nothing written

    def test_a_changed_window_is_asked_again_and_the_old_answer_dropped(self):
        a = _f("a")
        _, saved = self.run_pass({}, [a], _cards(["a"]), {("a",): {"noul": 0.9}})
        a2 = _f("a", occ=2)                                        # a new occurrence
        asked, saved2 = self.run_pass({"jev_scopes": saved}, [a2], _cards(["a"]),
                                      {("a",): {"noul": 0.4}})
        self.assertEqual(asked, [("a",)])
        self.assertEqual(list(saved2.values()), [0.4])


class Attach(unittest.TestCase):
    def test_only_current_estimates_and_nothing_when_off(self):
        a, b = _f("a"), _f("b")
        g = types.SimpleNamespace(findings=[a, b])
        by_id = {f.id: f for f in g.findings}
        cards = _cards(["a"], ["b"])
        d = {"jev_scopes": {jev._scope_sig(cards[0], by_id): 0.82}}
        with mock.patch.object(jev, "enabled", return_value=True):
            jev.attach_scope_estimates(cards, d, g)
        self.assertEqual([c.get("jev_p") for c in cards], [0.82, None, None])
        cards = _cards(["a"], ["b"])
        with mock.patch.object(jev, "enabled", return_value=False):
            jev.attach_scope_estimates(cards, d, g)
        self.assertEqual([c.get("jev_p") for c in cards], [None, None, None])


class Card(unittest.TestCase):
    def test_card_line(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function _ztJev\(t\)\{.*?\n\}", src, re.S)
        self.assertTrue(fn, "_ztJev missing from cases.html")
        js = fn.group(0) + "\nconsole.log(JSON.stringify([_ztJev({jev_p:0.816}),_ztJev({}),_ztJev(null)]));"
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(t.name)
        line, none1, none2 = json.loads(out)
        self.assertIn("Jev: 82% likely attacker activity", line)
        self.assertEqual((none1, none2), ("", ""))


class PayloadUnchanged(unittest.TestCase):
    def test_finding_ids_do_not_reach_the_model(self):
        from services.fusion import render
        z = {"n": 1, "window": {}, "finding_count": 1, "severity": "high",
             "finding_ids": ["secret-id"], "top_titles": ["t"]}
        with mock.patch.object(render, "analysable", lambda zt: zt):
            self.assertNotIn("finding_ids", json.dumps(render.timeframes_for_payload([z])))


if __name__ == "__main__":
    unittest.main()
