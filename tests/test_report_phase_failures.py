"""A segmented report should not fail in most cases, and when a phase does fail the
report says why.

Live: every phase came back empty (DeepSeek) or rate-limited (Codex) and the
synthesis was still sent over blank phases, with nothing telling it -- or the
reader -- which phases were missing.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim as _LLM  # noqa: E402
from test_analyst_context_everywhere import _graph  # noqa: E402


class Model:
    """Scripted fake: phase calls follow `phase_script` per call number; the synthesis
    (system prompt starts with the synthesis prompt) is recorded."""
    def __init__(self, phase_outcome):
        self.phase_outcome, self.calls, self.synth = phase_outcome, 0, []

    def __call__(self, system, user, **k):
        if system.endswith(_LLM.PHASE_SYSTEM_PROMPT) or _LLM.PHASE_SYSTEM_PROMPT in system:
            self.calls += 1
            return self.phase_outcome(self.calls, user)
        self.synth.append((system, user))
        return "## Executive Summary\nsynthesised " + "x" * 50


def _run(model, retries=None):
    cfg = {} if retries is None else {"report_phase_retries": retries}
    events = []
    with mock.patch.object(_LLM, "_real_llm", model), mock.patch.object(_LLM, "_use_real", lambda: True), \
         mock.patch.object(_LLM, "_agentic_cfg", lambda: cfg), \
         mock.patch.object(_LLM, "_case_event", lambda rid, a, s, d="": events.append((a, d))):
        md = _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode="macro", run_id="c")
    return md, events


class PhaseFailures(unittest.TestCase):
    def test_an_empty_answer_is_retried_once_and_the_report_is_whole(self):
        seen = set()

        def outcome(n, user):
            if user not in seen:
                seen.add(user)
                return ""                                  # first try of every phase: empty
            return "**Name:** ok\nanalysis " + "y" * 40
        m = Model(outcome)
        md, events = _run(m)
        self.assertTrue(any(a.endswith("— retrying") for a, _ in events))
        self.assertNotIn("was not analysed", md)
        self.assertIn("_Narrative by live LLM", md)

    def test_a_rate_limit_is_not_retried(self):
        m = Model(lambda n, u: (_ for _ in ()).throw(Exception("429 You've hit your usage limit")))
        _run(m)
        phases = m.calls
        m2 = Model(lambda n, u: (_ for _ in ()).throw(Exception("429 You've hit your usage limit")))
        _run(m2, retries=3)
        self.assertEqual(phases, m2.calls, "a rate limit must not be retried")

    def test_every_phase_failing_skips_the_synthesis_and_says_why(self):
        m = Model(lambda n, u: (_ for _ in ()).throw(Exception("429 You've hit your usage limit")))
        md, events = _run(m)
        self.assertEqual(m.synth, [], "no synthesis over blank phases")
        self.assertTrue(any(a == "Report · synthesis skipped" for a, _ in events))
        self.assertIn("_Deterministic report — The AI provider is limiting requests", md)

    def test_some_phases_failing_are_named_to_the_model_and_the_reader(self):
        def outcome(n, user):
            return "" if n == 1 else "**Name:** ok\\nanalysis " + "y" * 40
        m = Model(outcome)
        md, _ = _run(m, retries=0)
        self.assertEqual(len(m.synth), 1)
        system, user = m.synth[0]
        self.assertIn("not_analysed", user)
        self.assertIn("Say plainly which phases were not analysed", system)
        self.assertIn("This phase was not analysed by the AI model: The AI model answered with nothing.", md)


if __name__ == "__main__":
    unittest.main()


class TheOverviewFailingKeepsThePhases(unittest.TestCase):
    """Measured live: six phases answered over 15 minutes, the synthesis call then
    failed, and the run fell back to the offline report — every analysis lost."""

    def _run_with_failing_synthesis(self):
        calls = []

        def model(system, user, **k):
            if _LLM.PHASE_SYSTEM_PROMPT in system:
                calls.append("phase")
                return "**Name:** ok\nphase analysis " + "y" * 60
            calls.append("synthesis")
            raise Exception("Connection aborted: RemoteDisconnected")
        with mock.patch.object(_LLM, "_real_llm", model), mock.patch.object(_LLM, "_use_real", lambda: True), \
             mock.patch.object(_LLM, "_agentic_cfg", lambda: {}), \
             mock.patch.object(_LLM, "_case_event", lambda *a, **k: None):
            md = _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode="macro", run_id="c")
        return md, calls

    def test_the_phase_analyses_are_in_the_report(self):
        md, calls = self._run_with_failing_synthesis()
        self.assertIn("phase analysis", md)
        self.assertIn("Overview not written", md)
        self.assertIn("_Narrative by live LLM", md)          # still an AI-written report
        self.assertNotIn("_Deterministic report —", md)
        self.assertGreater(calls.count("phase"), 1)

    def test_an_empty_overview_also_keeps_the_phases(self):
        """What actually happened live: the overview answered NOTHING."""
        def model(system, user, **k):
            if _LLM.PHASE_SYSTEM_PROMPT in system:
                return "**Name:** ok\nphase analysis " + "y" * 60
            return "   "                                   # empty overview
        with mock.patch.object(_LLM, "_real_llm", model), mock.patch.object(_LLM, "_use_real", lambda: True), \
             mock.patch.object(_LLM, "_agentic_cfg", lambda: {}), \
             mock.patch.object(_LLM, "_case_event", lambda *a, **k: None):
            md = _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode="macro", run_id="c")
        self.assertIn("phase analysis", md)
        self.assertIn("Overview not written", md)
        self.assertNotIn("_Deterministic report —", md)

    def test_a_focused_report_still_falls_back(self):
        """One call, nothing to keep: the offline report with the reason is right."""
        def model(system, user, **k):
            raise Exception("429 You've hit your usage limit")
        with mock.patch.object(_LLM, "_real_llm", model), mock.patch.object(_LLM, "_use_real", lambda: True), \
             mock.patch.object(_LLM, "_agentic_cfg", lambda: {}), \
             mock.patch.object(_LLM, "_case_event", lambda *a, **k: None):
            md = _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode="focused", run_id="c")
        self.assertIn("_Deterministic report —", md)


class EveryCallSaysHowMuchContextItCarries(unittest.TestCase):
    def test_each_phase_and_the_synthesis(self):
        events = []
        model = Model(lambda n, u: "**Name:** ok\nanalysis " + "y" * 40)
        with mock.patch.object(_LLM, "_real_llm", model), mock.patch.object(_LLM, "_use_real", lambda: True), \
             mock.patch.object(_LLM, "_agentic_cfg", lambda: {}), \
             mock.patch.object(_LLM, "_case_event", lambda rid, a, s, d="": events.append((a, d))):
            _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode="macro", run_id="c")
        sending = [(a, d) for a, d in events if a.endswith("— sending")]
        self.assertTrue(sending)
        for a, d in sending:
            self.assertRegex(d, r"context [\d,]+ chars \(~[\d,]+ tokens\)", a)
