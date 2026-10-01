"""The report reads Jev's estimates (Jev use "report").

"Jev can provide more accuracy for the timeline and compromise possibility": the
report step waits, bounded, for Jev's after-fuse pass and gives the report model
its verdict suggestions and compromise estimates -- labelled as automated
estimates, never as verdicts. Anything the analyst judged is left out (their own
verdict already reaches the model and rules). Off, slow or unreachable: the report
is written without them, exactly as before.
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import jev, llm_sim, schema, store  # noqa: E402

import test_analyst_context_everywhere as ctx  # noqa: E402  (its graph segments into phases)


def _f(fid, title):
    return schema.Finding(id=fid, title=title, severity="high", confidence="medium", summary="s",
                          asset_ids=["asset:H"], ts="2026-01-01T10:00:00Z", kind="single")


class Estimates(unittest.TestCase):
    def setUp(self):
        self.g = schema.FusionGraph(case_id="c")
        self.g.findings = [_f("f1", "Eventlog Cleared"), _f("f2", "Defender disabled"),
                           _f("f3", "Judged by the analyst"), _f("f4", "Evidence changed since"),
                           _f("f5", "Jev was unsure")]
        wm = {f.id: f.watermark() for f in self.g.findings}
        self.d = {"timeline_validations": [{"finding_id": "f3", "status": "known"}],
                  "jev_suggestions": {
                      "f1": {"wm": wm["f1"], "label": "true_positive", "p": 0.9, "confidence": 0.93},
                      "f2": {"wm": wm["f2"], "label": "known", "p": 0.9, "confidence": 0.85},
                      "f3": {"wm": wm["f3"], "label": "true_positive", "p": 0.9, "confidence": 0.99},
                      "f4": {"wm": "an older watermark", "label": "true_positive", "p": 0.9, "confidence": 0.99},
                      "f5": {"wm": wm["f5"], "label": "true_positive", "p": 0.6, "confidence": 0.55}}}
        self.people = [{"name": "adatum\\srv", "jev_compromise": 0.91, "verdict": None},
                       {"name": "adatum\\dan", "jev_compromise": 0.97, "verdict": "compromised"},   # analyst decided
                       {"name": "adatum\\nobody", "jev_compromise": None, "verdict": None}]

    def run_it(self, uses=("report", "disposition", "compromise")):
        with mock.patch.object(jev, "enabled", lambda u, cfg=None: u in uses), \
                mock.patch.object(jev, "min_confidence", lambda: 0.8), \
                mock.patch.object(store, "identity_view", lambda cid: {"identities": self.people}):
            return jev.report_estimates("c", self.d, self.g)

    def test_only_valid_confident_undecided_estimates_are_given(self):
        est = self.run_it()
        self.assertEqual(est["findings"], [
            {"finding": "Eventlog Cleared", "estimate": "likely malicious", "confidence": 0.93},
            {"finding": "Defender disabled", "estimate": "likely expected or administrative activity", "confidence": 0.85}])
        self.assertEqual(est["identities"], [{"identity": "adatum\\srv", "compromise_probability": 0.91}])
        self.assertIn("NOT analyst verdicts", est["note"])
        self.assertIn("never 'confirmed'", est["note"])

    def test_off_means_nothing_and_a_failure_means_nothing(self):
        self.assertEqual(self.run_it(uses=("disposition", "compromise")), {})        # the report use is off
        self.assertEqual(self.run_it(uses=("report",)), {})                          # nothing to give
        with mock.patch.object(jev, "enabled", lambda u, cfg=None: True), \
                mock.patch.object(jev, "suggestion_for", side_effect=RuntimeError("x")):
            self.assertEqual(jev.report_estimates("c", self.d, self.g), {})          # never a failed report
        self.assertIn("report", jev.USES)
        self.assertTrue(jev.DEFAULTS["uses"]["report"])


class Wait(unittest.TestCase):
    def tearDown(self):
        jev._running.discard("c")

    def test_it_waits_for_the_pass_but_not_for_ever(self):
        self.assertTrue(jev.wait_idle("c", 5))                        # nothing running: at once
        jev._running.add("c")
        t0 = time.monotonic()
        self.assertFalse(jev.wait_idle("c", 0.4))                     # still running: gives up
        self.assertLess(time.monotonic() - t0, 2)
        threading.Timer(0.3, lambda: jev._running.discard("c")).start()
        self.assertTrue(jev.wait_idle("c", 5))                        # finished meanwhile


class ReportModel(unittest.TestCase):
    EST = {"note": jev.ESTIMATES_NOTE, "findings": [{"finding": "Finding 3", "estimate": "likely malicious", "confidence": 0.93}]}

    def calls(self, altitude, estimates):
        out = []

        def fake(system, user, **k):
            out.append((system, user))
            return "## Executive Summary\nok " + "x" * 50
        with mock.patch.object(llm_sim, "_real_llm", fake), mock.patch.object(llm_sim, "_use_real", lambda: True):
            llm_sim.generate_report(ctx._graph(), prefer_llm=True, altitude_mode=altitude, estimates=estimates)
        return out

    def test_every_call_of_the_report_carries_them_with_the_rule(self):
        for alt in ("focused", "macro"):
            calls = self.calls(alt, self.EST)
            self.assertTrue(calls)
            for _sys, user in calls:
                self.assertIn("automated_estimates", user, alt)
                self.assertIn("NOT analyst verdicts", user, alt)          # the note travels with the data
            self.assertIn("never 'confirmed'", calls[-1][0])              # and the final call's instructions
        self.assertGreater(len(self.calls("macro", self.EST)), 1)        # phases + synthesis

    def test_without_estimates_nothing_changes(self):
        for _sys, user in self.calls("focused", None) + self.calls("focused", {}):
            self.assertNotIn("automated_estimates", user)
            self.assertNotIn("automated_estimates", _sys)

    def test_the_report_step_waits_and_says_what_it_used(self):
        src = open(os.path.join(_ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        body = src.split("def regenerate_report(")[1].split("\ndef ")[0]
        self.assertLess(body.index("_jev.wait_idle(case_id, _jev.report_wait_seconds())"),
                        body.index("d = get_case(case_id)\n    g = load_graph(case_id)"))    # waits, THEN reads the case
        self.assertIn("estimates=_estimates", body)
        logs = []
        with mock.patch.object(store, "log_case_event", lambda cid, a, s, d="", **k: logs.append((a, d))), \
                mock.patch.object(jev, "enabled", lambda u, cfg=None: True), \
                mock.patch.object(jev, "report_estimates", lambda cid, d, g: dict(self.EST)):
            self.assertEqual(store._jev_estimates("c", {}, None, True), self.EST)
            self.assertEqual(store._jev_estimates("c", {}, None, False), {})                 # offline report: none
        self.assertEqual([a for a, _ in logs], ["Report · using Jev's estimates"])
        self.assertIn("not as verdicts", logs[0][1])
        logs.clear()
        with mock.patch.object(store, "log_case_event", lambda cid, a, s, d="", **k: logs.append((a, d))), \
                mock.patch.object(jev, "enabled", lambda u, cfg=None: True), \
                mock.patch.object(jev, "report_estimates", lambda cid, d, g: {}):
            store._jev_estimates("c", {}, None, True, waited=False)
        self.assertIn("still working", logs[0][1])                        # says it did not wait any longer


if __name__ == "__main__":
    unittest.main()
