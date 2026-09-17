"""What the analyst told the case reaches every model call that writes about it.

The segmented (phase-by-phase) report rebuilt its phase and synthesis payloads
without the triage, manual Timeline events reached no model, and chat ignored the
case's Steering.
"""
import json
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim as _LLM, render, schema  # noqa: E402

MANUAL = [{"ts": "2026-06-14T10:00:00Z", "host": "ALDC02", "title": "IT pushed a GPO", "status": "known_it"}]
VALID = [{"finding_id": "f1", "status": "not_real"}]
DISP = [{"target": "f1", "verdict": "benign"}]


def _graph():
    g = schema.FusionGraph(case_id="c")
    hosts = ["H%d" % i for i in range(6)]
    for h in hosts:
        g.upsert(schema.Entity(id="asset:" + h, type="asset", label=h))
    fs = []
    # two bursts a year apart on several hosts, so the case segments into phases
    for n, (day, sev) in enumerate([("2025-01-0%d" % d, "high") for d in range(1, 8)] +
                                   [("2026-01-0%d" % d, "critical") for d in range(1, 8)]):
        fs.append(schema.Finding(id="f%d" % n, title="Finding %d" % n, severity=sev, confidence="high",
                                 summary="s", asset_ids=["asset:" + hosts[n % 6], "asset:" + hosts[(n + 1) % 6]],
                                 ts=day + "T10:00:00Z", kind="cross_host"))
    g.findings = fs
    return g


class AnalystContext(unittest.TestCase):
    def _report_calls(self, altitude):
        calls = []

        def fake(system, user, **k):
            calls.append((system, user))
            return "## Executive Summary\nok " + "x" * 50
        with mock.patch.object(_LLM, "_real_llm", fake), mock.patch.object(_LLM, "_use_real", lambda: True):
            _LLM.generate_report(_graph(), prefer_llm=True, altitude_mode=altitude,
                                 dispositions=DISP, validations=VALID, manual_events=MANUAL)
        return calls

    def _assert_all_carry(self, calls):
        self.assertTrue(calls)
        for _sys, user in calls:
            self.assertIn("IT pushed a GPO", user)
            self.assertIn("analyst_validations", user)
            self.assertIn("operator_dispositions", user)

    def test_focused_report(self):
        self._assert_all_carry(self._report_calls("focused"))

    def test_segmented_report_every_phase_and_the_synthesis(self):
        calls = self._report_calls("macro")
        self.assertGreater(len(calls), 1, "the test case must segment into phases")
        self._assert_all_carry(calls)

    def test_chat_gets_manual_events_and_steering(self):
        seen = {}
        with mock.patch.object(_LLM, "_real_llm", lambda s, u, **k: seen.update(s=s, u=u) or "ok"), \
             mock.patch.object(_LLM, "_use_real", lambda: True):
            _LLM.chat(_graph(), "what happened?", full_context=True, require_llm=True,
                      manual_events=MANUAL, master_prompt="ignore the backup host noise")
        self.assertIn("IT pushed a GPO", seen["u"])
        self.assertIn("ignore the backup host noise", seen["s"])


if __name__ == "__main__":
    unittest.main()
