"""Jev's "is this person compromised?" on each Identities card.

Asked after the fuse and cached per exact accounts + findings (+ occurrences),
so the tab never waits on the network and a person whose evidence changed shows
no stale number. People with no findings are not asked. Off -> nothing shown.
"""
import os
import shutil
import subprocess
import sys
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, jev, store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid, occ=1):
    return Finding(id=fid, title=f"T {fid}", severity="high", confidence="high", summary="",
                   entity_ids=["acc-" + fid[0]], occ_count=occ, occ_latest="2026-09-01")


def _card(name, *accs):
    return {"key": name, "name": name, "accounts": [{"id": a, "label": a} for a in accs]}


class Suggest(unittest.TestCase):
    def run_pass(self, d, findings, cards, answers):
        g = types.SimpleNamespace(findings=findings, relationships=[], entities={})
        asked = []

        def fake_ask_each(items, render, question, **kw):
            asked.extend(c["name"] for c, fs, sig in items)
            return [answers.get(c["name"]) for c, fs, sig in items]
        with mock.patch.object(store, "identity_view", return_value={"identities": cards}), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch.object(jev, "ask_each", fake_ask_each), \
             mock.patch.object(jev, "mask_for", return_value=None), \
             mock.patch.object(store, "_merge_case_details") as merge:
            jev.suggest_compromise("c1", d)
        return asked, (merge.call_args.args[1]["jev_compromise"] if merge.called else None)

    def test_asks_people_with_findings_once(self):
        a = _f("a")
        cards = [_card("kobia", "acc-a"), _card("quiet", "acc-z")]
        asked, saved = self.run_pass({}, [a], cards, {"kobia": {"noul": 0.83}})
        self.assertEqual(asked, ["kobia"])                         # no findings -> not asked
        self.assertEqual(list(saved.values()), [0.83])
        asked, saved2 = self.run_pass({"jev_compromise": saved}, [a], cards, {})
        self.assertEqual((asked, saved2), ([], None))              # cached

    def test_changed_evidence_is_asked_again_and_the_old_answer_dropped(self):
        cards = [_card("kobia", "acc-a")]
        _, saved = self.run_pass({}, [_f("a")], cards, {"kobia": {"noul": 0.9}})
        asked, saved2 = self.run_pass({"jev_compromise": saved}, [_f("a", occ=2)], cards,
                                      {"kobia": {"noul": 0.4}})
        self.assertEqual(asked, ["kobia"])
        self.assertEqual(list(saved2.values()), [0.4])

    def test_estimate_read_only_while_enabled_and_current(self):
        fs = [_f("a")]
        sig = jev.compromise_sig(["acc-a"], fs)
        d = {"jev_compromise": {sig: 0.7}}
        with mock.patch.object(jev, "enabled", return_value=True):
            self.assertEqual(jev.compromise_estimate(d, ["acc-a"], fs), 0.7)
            self.assertIsNone(jev.compromise_estimate(d, ["acc-a"], [_f("a", occ=3)]))
            self.assertIsNone(jev.compromise_estimate(d, ["acc-a"], []))
        with mock.patch.object(jev, "enabled", return_value=False):
            self.assertIsNone(jev.compromise_estimate(d, ["acc-a"], fs))

    def test_the_pass_runs_only_when_ticked(self):
        with mock.patch.object(store, "get_case", return_value={"x": 1}), \
             mock.patch.object(store, "view_graph", return_value="G"), \
             mock.patch.object(jev, "enabled", side_effect=lambda u, *a: u == "compromise"), \
             mock.patch.object(jev, "suggest_compromise") as sc, \
             mock.patch.object(jev, "suggest_identities") as si:
            jev._one_pass("c1")
        si.assert_not_called()
        sc.assert_called_once_with("c1", {"x": 1})
        self.assertIn("compromise", jev.DEFAULTS["uses"])


class Order(unittest.TestCase):
    """Jev on: your verdict first (compromised, then not), then Jev's estimate
    highest first, then A–Z. Jev off: A–Z only."""

    def order(self, on):
        cards = [{"key": n, "name": n, "buckets": [], "accounts": [{"id": "a-" + n, "label": n}]}
                 for n in ("zed", "amy", "bob", "cat", "dan", "eve")]
        verdicts = [{"accounts": ["a-dan"], "verdict": "not_compromised"},
                    {"accounts": ["a-zed"], "verdict": "compromised"}]
        est = {"bob": 0.4, "cat": 0.9, "zed": 0.1}
        ws = mock.Mock()
        ws.get_automation_runs_by_case.return_value = []
        with mock.patch.object(store, "get_case", return_value={"identity_verdicts": verdicts}), \
             mock.patch.object(store, "view_graph", return_value=types.SimpleNamespace(findings=[], relationships=[], entities={})), \
             mock.patch.object(store, "_identity_decisions", return_value={}), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(identities, "case_buckets", return_value=["endpoint"]), \
             mock.patch.object(identities, "compute_candidates", return_value=[]), \
             mock.patch.object(identities, "analyst_inputs", return_value={"fuzzy": [], "merges": [], "splits": set(), "host_excludes": {}}), \
             mock.patch.object(identities, "resolve_identities", return_value=cards), \
             mock.patch.object(jev, "compromise_estimate", side_effect=lambda d, ids, fs: est.get(ids[0][2:]) if on else None), \
             mock.patch.object(jev, "enabled", return_value=on):
            v = store.identity_view("c1")
        return v["sort"], [c["name"] for c in v["identities"]]

    def test_with_jev(self):
        self.assertEqual(self.order(True), ("jev", ["zed", "dan", "cat", "bob", "amy", "eve"]))

    def test_without_jev_alphabet_only(self):
        self.assertEqual(self.order(False), ("alpha", ["amy", "bob", "cat", "dan", "eve", "zed"]))


class Pill(unittest.TestCase):
    def test_markup(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        js = r"""
const fs=require("fs"); const src=fs.readFileSync(process.argv[1],"utf8");
eval(src.match(/function _idJev\(it\)\{[\s\S]*?\n\}/)[0]);
console.log(JSON.stringify([_idJev({jev_compromise:0.834}), _idJev({jev_compromise:0.1}), _idJev({}), _idJev({jev_compromise:null})]));"""
        import json
        hi, lo, none, null = json.loads(subprocess.run(
            [node, "-e", js, os.path.join(_ROOT, "modules/nginx/html/cases.html")],
            capture_output=True, text=True, check=True).stdout)
        self.assertIn(">83%</b>", hi)
        self.assertIn("width:83%;background:var(--crit)", hi)
        self.assertIn(">10%</b>", lo)
        self.assertIn("var(--ok)", lo)
        for x in (none, null):                                   # not asked: a dash, no number
            self.assertIn(">—</span>", x)
            self.assertNotIn("%", x)

if __name__ == "__main__":
    unittest.main()
