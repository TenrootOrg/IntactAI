"""Jev's "same person?" hint: only for pairs still awaiting the analyst, asked
once per pair, and never when masking is on.

Masking replaces both account names with unrelated pseudonyms, and the names are
the whole question — so a masked case gets no hint rather than a confident
answer about noise. Pairs that were auto-merged or already decided are not the
analyst's problem any more and are never sent.
"""
import os
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, jev, store  # noqa: E402


def _cand(cid, auto=False):
    return {"id": cid, "a_label": "jsmith", "b_label": "john.smith", "a_ctx": "HOST1",
            "b_ctx": "azure", "reason": "first.last vs flast", "auto": auto}


class PendingPairs(unittest.TestCase):
    def test_auto_and_decided_pairs_are_not_pending(self):
        cands = [_cand("p1"), _cand("p2", auto=True), _cand("p3")]
        with mock.patch.object(identities, "compute_candidates", return_value=cands), \
             mock.patch.object(identities, "analyst_inputs", return_value={"fuzzy": cands}), \
             mock.patch.object(store, "_identity_decisions",
                               return_value={"p3": {"decision": "declined"}}):
            got = jev._pending_identity_pairs({}, types.SimpleNamespace())
        self.assertEqual([c["id"] for c in got], ["p1"])


class SuggestIdentities(unittest.TestCase):
    def run_pass(self, d, pairs, answers):
        asked = []

        def fake_ask_each(items, render, question, **kw):
            asked.extend(c["id"] for c in items)
            self.assertEqual(render(items[0])["account_a"], "jsmith")
            return [answers.get(c["id"]) for c in items]
        with mock.patch.object(jev, "_pending_identity_pairs", return_value=pairs), \
             mock.patch.object(jev, "ask_each", fake_ask_each), \
             mock.patch.object(store, "_merge_case_details") as merge:
            jev.suggest_identities("c1", d, None)
        return asked, (merge.call_args.args[1]["jev_identity"] if merge.called else None)

    def test_asks_only_new_pairs_and_stores_probability(self):
        asked, written = self.run_pass({"jev_identity": {"p1": 0.2}},
                                       [_cand("p1"), _cand("p2"), _cand("p3")],
                                       {"p2": {"noul": 0.87}, "p3": None})
        self.assertEqual(asked, ["p2", "p3"])
        self.assertEqual(written, {"p1": 0.2, "p2": 0.87})

    def test_masked_case_sends_nothing(self):
        with mock.patch.object(jev, "_pending_identity_pairs") as pend, \
             mock.patch.object(jev, "ask_each") as ask:
            self.assertEqual(jev.suggest_identities("c1", {"masking": {"enabled": True}}, None), 0)
        pend.assert_not_called()
        ask.assert_not_called()


class IdentityView(unittest.TestCase):
    def view(self, enabled):
        c = {**_cand("p1"), "a_id": "A", "b_id": "B", "score": 0.65, "kind": "same_identity"}
        idents = [{"key": k, "name": n, "buckets": ["endpoint"], "accounts": [{"id": a}]}
                  for k, n, a in (("jsmith", "jsmith", "A"), ("john.smith", "john.smith", "B"))]
        ws = mock.Mock()
        ws.get_automation_runs_by_case.return_value = []
        with mock.patch.object(store, "get_case", return_value={"jev_identity": {"p1": 0.87}}), \
             mock.patch.object(store, "view_graph", return_value=None), \
             mock.patch.object(store, "_identity_decisions", return_value={}), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(identities, "case_buckets", return_value=["endpoint"]), \
             mock.patch.object(identities, "compute_candidates", return_value=[c]), \
             mock.patch.object(identities, "analyst_inputs",
                               return_value={"fuzzy": [c], "merges": [], "splits": set(),
                                             "host_excludes": {}}), \
             mock.patch.object(identities, "resolve_identities", return_value=idents), \
             mock.patch.object(jev, "enabled", return_value=enabled):
            v = store.identity_view("c1")
        return [s["jev_p"] for it in v["identities"] for s in it["suggestions"]]

    def test_hint_rides_on_the_suggestion_only_while_enabled(self):
        self.assertEqual(self.view(True), [0.87, 0.87])
        self.assertEqual(self.view(False), [None, None])


class Pass(unittest.TestCase):
    def test_each_use_runs_only_when_ticked(self):
        with mock.patch.object(store, "get_case", return_value={"x": 1}), \
             mock.patch.object(store, "view_graph", return_value="G"), \
             mock.patch.object(jev, "enabled", side_effect=lambda u, *a: u == "identity"), \
             mock.patch.object(jev, "suggest_dispositions") as sd, \
             mock.patch.object(jev, "suggest_identities") as si:
            jev._one_pass("c1")
        sd.assert_not_called()
        si.assert_called_once_with("c1", {"x": 1}, "G")


if __name__ == "__main__":
    unittest.main()
