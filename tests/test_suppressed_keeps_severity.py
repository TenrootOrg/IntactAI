"""A False positive / Known lowers a finding to informational FOR RISK only; every
screen keeps showing the detection's own severity, greyed (QA 2026-09-29: a
cancelled False positive still read "informational").
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, render  # noqa: E402
from services.fusion.schema import Finding, FusionGraph  # noqa: E402

TS = "2026-09-01T07:20:51Z"


def _graph(parts=False):
    g = FusionGraph(case_id="c")
    g.findings.append(Finding(
        id="f1", title="SIGMA: Curl Download on H", severity="high", confidence="medium", summary="s",
        ts=TS, occ_count=1, occ_latest=TS,
        parts=[correlate._part("p1", "A", TS, None, 1, "1|" + TS, [], "high"),
               correlate._part("p2", "B", TS, None, 1, "1|" + TS, [], "medium")] if parts else []))
    return g


def _fp(target):
    return {"target": target, "verdict": "benign", "attribution": "operator"}


class KeepsSeverity(unittest.TestCase):
    def test_a_false_positive_is_informational_for_risk_but_shown_as_it_was(self):
        g = _graph()
        correlate._apply_dispositions(g, [_fp("f1")])
        f = g.findings[0]
        self.assertEqual((f.severity, f.kind), ("informational", "dispositioned"))   # risk
        self.assertEqual(f.shown_severity(), "high")                                   # screens
        self.assertEqual(render.timeline(g)[0]["severity"], "high")

    def test_cancelling_the_verdict_leaves_nothing_behind(self):
        g = _graph()                                     # the next fuse starts from the mapped data
        correlate._apply_dispositions(g, [])
        self.assertEqual((g.findings[0].severity, g.findings[0].orig_severity), ("high", None))

    def test_a_row_suppressed_by_its_parts_shows_its_own_severity(self):
        g = _graph(parts=True)
        correlate._apply_dispositions(g, [_fp("p1"), _fp("p2")])
        self.assertEqual(g.findings[0].severity, "informational")
        self.assertEqual(render.timeline(g)[0]["severity"], "high")

    def test_the_original_survives_save_and_load(self):
        g = _graph()
        correlate._apply_dispositions(g, [_fp("f1")])
        back = Finding.from_dict(g.findings[0].to_dict())
        self.assertEqual((back.severity, back.orig_severity), ("informational", "high"))
        self.assertIsNone(Finding.from_dict(_graph().findings[0].to_dict()).orig_severity)


if __name__ == "__main__":
    unittest.main()
