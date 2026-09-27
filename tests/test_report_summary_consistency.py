"""The report agrees with the Risk tab and with its own evidence span.

Found in the audit (jev_test):
  * the Containment line sorted hosts by tier only and cut at 6 in graph order —
    it named ALClient04 (#7) and left out ALCA01 (#5), and could drop a critical;
  * the executive summary took the LAST timeline row's time, but undated rows
    sort last with an empty ts — a 757-day case read "activity runs around
    2024-05-24".
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402


def _g(spec):
    g = schema.FusionGraph(case_id="c")
    fs = []
    for h, rows in spec.items():
        g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h, severity="high"))
        for i, (sev, ts, last) in enumerate(rows):
            fs.append(schema.Finding(id=f"{h}{i}", title=f"SIGMA: rule {i} on {h}", severity=sev,
                                     confidence="m", summary="", asset_ids=[f"asset:{h}"], ts=ts,
                                     occ_latest=last))
    g.findings = fs
    return g


class Containment(unittest.TestCase):
    def test_follows_the_risk_order_and_keeps_every_critical(self):
        spec = {f"H{i}": [("high", "2026-06-01T10:00:00Z", None)] * (i + 1) for i in range(8)}
        spec = {h: [(s, t, l) for j, (s, t, l) in enumerate(r)] for h, r in spec.items()}
        spec["CRIT"] = [("critical", "2026-06-01T10:00:00Z", None)]
        # distinct detections per host = row count here (each row is a different rule)
        g = _g(spec)
        rec = render._recommendations_md(g, g.findings, list(g.by_type("asset")))
        line = [l for l in rec.splitlines() if "Containment" in l][0]
        named = line.split("pending eradication: ")[1].rstrip(".").split(", ")
        self.assertEqual(named[0], "CRIT")                      # critical first, always there
        self.assertEqual(named[1:], ["H7", "H6", "H5", "H4", "H3"])   # then the Risk order, 6 in all


class Span(unittest.TestCase):
    def test_summary_span_uses_dated_rows_and_row_ends(self):
        g = _g({"A": [("high", "2024-05-24T17:49:46Z", "2024-05-24T18:00:00Z"),
                      ("high", "2026-06-01T10:00:00Z", "2026-06-20T12:00:00Z"),
                      ("high", None, None)]})
        summ = render._exec_summary(g, list(g.by_type("asset")), g.findings)
        self.assertIn("between `2024-05-24T17:49:46Z` and `2026-06-20T12:00:00Z`", summ)


if __name__ == "__main__":
    unittest.main()
