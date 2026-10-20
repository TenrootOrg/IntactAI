"""Switching the decision model no longer blanks the case, and a Refusion asks it early.

Kev 4B had answered all six phase cards; the operator switched to Jev 1.14 and the
cards, people and chips went blank until a Refusion finished -- whose decision pass
only started after the report (minutes), so the report never had its estimates
either ("I still don't see the classifier percentage on each phase").
"""
import os
import re
import sys
import types
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
for _pkg, _rel in (("services", "services"), ("services.fusion", "services/fusion")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")
    sys.modules["requests"].post = None

from services.fusion import decision_model as dm  # noqa: E402

JEV = {"online_llm": {"provider": "openrouter", "api_key": "k"},
       "decision_model": {"enabled": True, "model": "typesafe/jev-1.14"}}
CASE = {"decision_scopes": {"sig1": 0.94},
        "decision_by": {"scopes": "openrouter/jaredpalmer/kev-4b"}}


class Shown(unittest.TestCase):
    def test_previous_model_shown_with_its_name_but_not_counted_as_asked(self):
        self.assertEqual(({"sig1": 0.94}, "jaredpalmer/kev-4b"), dm.shown(CASE, "scopes", JEV))
        self.assertEqual({}, dm.cached(CASE, "scopes", JEV))      # so Jev still asks

    def test_current_model_answers_win_unlabelled(self):
        d = {**CASE, "decision_by": {"scopes": "openrouter/typesafe/jev-1.14"}}
        self.assertEqual(({"sig1": 0.94}, ""), dm.shown(d, "scopes", JEV))

    def test_nothing_saved_shows_nothing(self):
        self.assertEqual({}, dm.shown({}, "scopes", JEV)[0])


class Wiring(unittest.TestCase):
    def setUp(self):
        self.store = open(os.path.join(_BACKEND, "services/fusion/store.py")).read()
        self.dm = open(os.path.join(_BACKEND, "services/fusion/decision_model.py")).read()
        self.page = open(os.path.join(_ROOT, "modules/nginx/html/cases.html")).read()

    def test_every_display_reads_shown_and_every_asker_reads_cached(self):
        self.assertIn('est, by = shown(d, "scopes")', self.dm)
        self.assertIn('return shown(d, "compromise")[0]', self.dm)
        self.assertIn('_dm.shown(d, "identity")', self.store)
        self.assertIn('dm_s, dm_by = dm.shown(d, "suggestions")', self.store)
        for asker in ('have = cached(d, "suggestions")', 'have = cached(d, "identity")',
                      'have = cached(d, "scopes")', 'have = cached(d, "compromise")'):
            self.assertIn(asker, self.dm)

    def test_the_refusion_asks_before_its_report_and_hands_it_the_answers(self):
        body = self.store[self.store.index("def _fuse_case_locked("):self.store.index("def _decision_estimates(")]
        early = body.index("_dm_early.after_fuse(case_id")
        self.assertLess(early, body.index("llm_sim.generate_report("))
        self.assertIn("_dm_early.wait_idle(case_id, _dm_early.report_wait_seconds())", body)
        self.assertIn("estimates=_decision_estimates(case_id, _d_est, gr, _narrate, waited=_dm_waited)", body)

    def test_the_page_names_the_earlier_model(self):
        for label in ("t.decision_by", "j.by", "it.decision_by", "s.decision_by"):
            self.assertIn(label, self.page)


if __name__ == "__main__":
    unittest.main()
