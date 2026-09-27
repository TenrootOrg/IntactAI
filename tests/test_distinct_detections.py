"""Headline numbers count DISTINCT detections, not episode rows.

Found in the audit after the Timeline moved to one row per episode: host risk
summed rows, so a rule that came back on eight days outweighed eight different
detections (ALCA01: 35 rows, 8 distinct, lifted above hosts with 20), and the
report header / summary / scope cards counted repeats (19 critical rows were 5
distinct critical detections). A daily routine also set a host's tier by itself.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, render, schema  # noqa: E402


def _f(fid, title, host, sev="high", day=1, recurring=None):
    return schema.Finding(id=fid, title=f"{title} on {host}", severity=sev, confidence="m",
                          summary="", asset_ids=[f"asset:{host}"], ts=f"2026-06-{day:02d}T10:00:00Z",
                          recurring=recurring)


def _graph(findings):
    g = schema.FusionGraph(case_id="c")
    for h in sorted({a for f in findings for a in f.asset_ids}):
        g.upsert(schema.Entity(id=h, type="asset", label=h.split(":")[1]))
    g.findings = findings
    return g


class Cleared(unittest.TestCase):
    """A finding the analyst marked False Positive / Known stops counting.
    Found by tests/live_case_integration.py: 35 detections stayed 35."""

    def test_a_cleared_detection_is_not_counted_or_scored(self):
        fs = [_f("a", "Mimikatz", "H1", "high"), _f("b", "Odd service", "H1", "high")]
        before = render.risk_table(_graph(fs))[0]
        fs[1].severity, fs[1].kind = "informational", "dispositioned"   # what a False Positive does
        after = render.risk_table(_graph(fs))[0]
        self.assertEqual((before["finding_count"], after["finding_count"]), (2, 1))
        self.assertNotIn("Odd service", after["why"])
        self.assertLess(correlate._host_intensity("asset:H1", [fs[0], fs[1]], 1),
                        correlate._host_intensity("asset:H1", [fs[0], _f("c", "Odd service", "H1", "high")], 1))


class Risk(unittest.TestCase):
    def test_breadth_beats_repetition(self):
        repeat = [_f(f"r{d}", "SIGMA: Suspicious Service Name", "REPEAT", day=d) for d in range(1, 9)]
        broad = [_f(f"b{i}", t, "BROAD") for i, t in enumerate(
            ["SIGMA: Mimikatz", "SIGMA: Encoded PowerShell", "SIGMA: Eventlog Cleared"])]
        g = _graph(repeat + broad)
        sc = correlate.score_assets_over(list(g.by_type("asset")), g.findings, 2)
        self.assertGreater(sc["asset:BROAD"]["risk_intensity"], sc["asset:REPEAT"]["risk_intensity"])

    def test_a_routine_does_not_set_the_tier_alone(self):
        g = _graph([_f("x", "SIGMA: Suspicious Service Path (recurring daily ~10:52)", "H",
                       sev="high", recurring={"tod": "10:52", "days": 40, "per_day_max": 2})])
        sc = correlate.score_assets_over(list(g.by_type("asset")), g.findings, 1)
        self.assertEqual(sc["asset:H"]["severity"], "medium")
        self.assertEqual(g.findings[0].severity, "high")          # the row keeps its own severity


class Counts(unittest.TestCase):
    def setUp(self):
        self.g = _graph([_f(f"c{d}", "SIGMA: Defender Alert (Severe)", "H", sev="critical", day=d)
                         for d in range(1, 13)] + [_f("m", "SIGMA: Mimikatz", "H", sev="critical")])

    def test_header_counts_detections_with_rows_secondary(self):
        hdr = render.report_header(self.g)
        self.assertIn("| **Detections** | 2 distinct (2 critical", hdr)
        self.assertIn("across 13 Timeline rows", hdr)

    def test_risk_table_tally_is_distinct(self):
        row = render.risk_table(self.g)[0]
        self.assertEqual((row["by_severity"]["critical"], row["finding_count"], row["row_count"]),
                         (2, 2, 13))


if __name__ == "__main__":
    unittest.main()
