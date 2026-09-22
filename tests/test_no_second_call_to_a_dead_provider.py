"""One fuse must not call an unreachable provider twice.

From a live case log, an air-gapped box with an OpenRouter model still
configured:

    13:42:01  Report    · sending request to the LLM
    13:42:33  Report    · LLM call failed — cannot reach the AI provider   (32s)
    13:42:33  Checklist · sending request to the LLM      <-- same dead provider
    13:43:06  Checklist · complete — 0 item(s)                             (33s)

~65 seconds of dead waiting per Refusion, with "generating report (this waits on
the model)" on screen the whole time. The report's attempt had already proved
there was no route; the checklist call spent another full timeout learning it.

The fix is scoped to ONE fuse deliberately. Nothing is remembered between runs:
every Refusion gets a fresh attempt, so a connection that comes back is used
immediately, with no cooldown to wait out and no state to go stale.

generate_report classifies its own failure and renders it into the report's
closing note, keeping the code to itself — so these also pin the mapping back
from that sentence to a reason code, which is what makes the skip decidable.
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion import llm_sim  # noqa: E402

STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")


def sentence_for(code):
    """The sentence a deterministic report's closing note carries for `code`."""
    reason, fix = llm_sim._llm_reason_text(code)
    return reason + (" " + fix if fix else "")


class NoRouteIsToldApartFromAProviderThatAnswered(unittest.TestCase):

    def test_no_internet_is_no_route(self):
        self.assertTrue(llm_sim.provider_unreachable(sentence_for("no_internet")))

    def test_a_timeout_is_no_route(self):
        self.assertTrue(llm_sim.provider_unreachable(sentence_for("timeout")))

    def test_a_rejected_key_is_NOT(self):
        """The provider answered — it just said no. A second call may well
        succeed (different endpoint, different payload), so do not skip it."""
        self.assertFalse(llm_sim.provider_unreachable(sentence_for("invalid_key")))

    def test_out_of_credit_is_NOT(self):
        self.assertFalse(llm_sim.provider_unreachable(sentence_for("no_credit")))

    def test_an_unsupported_model_is_NOT(self):
        self.assertFalse(llm_sim.provider_unreachable(sentence_for("model_unsupported")))

    def test_the_sentence_maps_back_to_its_own_code(self):
        for code in ("no_internet", "timeout", "invalid_key", "no_credit",
                     "rate_limited", "model_unsupported"):
            self.assertEqual(code, llm_sim.reason_code_of(sentence_for(code)), code)

    def test_something_unrecognised_is_not_treated_as_no_route(self):
        for junk in ("", None, "the model did not return a narrative", "???"):
            self.assertEqual("", llm_sim.reason_code_of(junk), repr(junk))
            self.assertFalse(llm_sim.provider_unreachable(junk), repr(junk))


class TheFuseActsOnIt(unittest.TestCase):

    def setUp(self):
        with open(STORE, encoding="utf-8") as fh:
            self.src = fh.read()

    def test_the_checklist_is_gated_on_it(self):
        # Matched in two pieces, not as one line: the same `if` also carries the
        # scope gate now (a checklist is generated once for the life of a case, so
        # it must not be born inside a zoomed scope). What must not come back is
        # calling a provider the report just failed to reach.
        self.assertIn("if allow_llm and (not _no_route or _offline)", self.src,
                      "the checklist must not call a provider the report just "
                      "failed to reach")
        self.assertIn('and not d.get("disposition_checklist")', self.src,
                      "and it must still only run when the case has no checklist")

    def test_both_failure_paths_set_it(self):
        """generate_report usually ABSORBS the failure and returns a template, so
        keying off the exception alone would miss the common case — which is the
        one in the log."""
        self.assertIn("_no_route = llm_sim.provider_unreachable(_why)", self.src,
                      "the absorbed-failure path (template returned, reason in the "
                      "closing note) must set it")
        self.assertIn("llm_sim._classify_llm_error(_e) in llm_sim._NO_ROUTE_CODES",
                      self.src, "the raising path must set it too")

    def test_it_starts_false_every_fuse(self):
        """Scoped to one run: no cross-fuse memory, by design."""
        self.assertIn("_no_route = False", self.src)
        self.assertLess(self.src.index("_no_route = False"),
                        self.src.index("_no_route = llm_sim.provider_unreachable"),
                        "it must be initialised before either failure path runs")

    def test_the_skip_is_visible_in_the_case_log(self):
        self.assertIn('"Checklist · skipped"', self.src,
                      "a call that did not happen must say so, or the operator sees "
                      "a checklist silently missing")

    def test_nothing_caches_reachability_across_fuses(self):
        """The ask was explicitly 'just for each time it tries to make refusion'."""
        window = self.src[self.src.index("_no_route = False"):]
        window = window[:window.index("def ", 200)] if "def " in window[200:] else window
        for banned in ("_UNREACHABLE_COOLDOWN", "time.time() - _last_no_route",
                       "_NO_ROUTE_UNTIL"):
            self.assertNotIn(banned, window,
                             f"{banned} would make the skip outlive the fuse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
