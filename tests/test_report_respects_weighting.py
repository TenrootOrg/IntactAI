"""The AI report respects the weighting, and cannot out-rate the evidence.

2026-10-07, a real two-server admin case: the model called a security agent's
own updater a masquerading backdoor, WinRAR installers years of data staging,
rated phases with no critical finding "Severity: Critical" and the case
"Risk: CRITICAL". Every report call now carries WEIGHTING_RULE, and whatever
the model writes, a phase's Severity is held to its strongest finding and the
case Risk to the strongest finding in scope -- with a note when it had to be.
"""
import copy
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim  # noqa: E402
import test_analyst_context_everywhere as ctx  # noqa: E402  (its graph segments into phases)


def high_only_graph():
    g = copy.deepcopy(ctx._graph())
    for f in g.findings:
        if f.severity == "critical":
            f.severity = "high"
    return g


def run(altitude):
    calls = []

    def fake(system, user, **k):
        calls.append(system)
        if "ONE PHASE" in system:
            return "**Name:** Something on HOST\n- **Severity:** Critical\n- **Confidence:** High\n\n**What happened:** x"
        return "## Executive Summary\nA story.\n\n**Risk: CRITICAL** — it is all very bad.\n" + "x" * 60
    with mock.patch.object(llm_sim, "_real_llm", fake), mock.patch.object(llm_sim, "_use_real", lambda: True):
        report = llm_sim.generate_report(high_only_graph(), prefer_llm=True, altitude_mode=altitude)
    return calls, report


class EveryCallCarriesTheRule(unittest.TestCase):
    def test_phases_and_synthesis(self):
        for alt in ("focused", "macro"):
            calls, _ = run(alt)
            self.assertTrue(calls, alt)
            for system in calls:
                self.assertIn(llm_sim.WEIGHTING_RULE, system, alt)
        self.assertGreater(len(run("macro")[0]), 1)                 # phases + synthesis


class TheReportCannotOutRateTheEvidence(unittest.TestCase):
    def test_risk_and_phase_severity_are_held_to_the_strongest_finding(self):
        _, report = run("macro")
        self.assertNotIn("Risk: CRITICAL**", report)
        self.assertIn("**Risk: HIGH _(the model said CRITICAL; held to the strongest finding in this case, which is high)_**", report)
        self.assertNotIn("**Severity:** Critical", report)
        self.assertIn("**Severity:** High _(the model said Critical; held to the strongest finding "
                      "in this phase, which is high)_", report)

    def test_the_cap_changes_nothing_at_or_below_the_ceiling(self):
        for text in ("**Risk: HIGH** — x", "- **Severity:** Medium", "**Risk: LOW** — y"):
            self.assertEqual(llm_sim._cap_severity_word(text, "high", "case"), text)

    def test_an_informational_ceiling_reads_low(self):
        out = llm_sim._cap_severity_word("- **Severity:** High", "informational", "phase")
        self.assertTrue(out.startswith("- **Severity:** Low _(the model said High"), out)


if __name__ == "__main__":
    unittest.main()
