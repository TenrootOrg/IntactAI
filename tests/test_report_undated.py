"""Undated high/critical rows are named in the report, not silently dropped.

Found in the audit (jev_test): three web rows with no timestamp were on the
Timeline tab and nowhere in the report — the report timeline needs a time.
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


def _f(fid, ts, sev="high"):
    return schema.Finding(id=fid, title=f"Web visit {fid}", severity=sev, confidence="m", summary="", ts=ts)


class Undated(unittest.TestCase):
    def test_named_under_the_timeline(self):
        g = schema.FusionGraph(case_id="c")
        fs = [_f("a", "2026-09-01T10:00:00Z"), _f("b", None), _f("c", None, "low")]
        md = render.timeline_md(g, fs, eff_detail="full")
        self.assertIn("Undated: 1 high/critical finding(s)", md)
        self.assertIn("Web visit b", md)
        self.assertNotIn("Web visit c", md)                      # below high, as for dated rows

    def test_nothing_said_when_all_dated(self):
        md = render.timeline_md(schema.FusionGraph(case_id="c"), [_f("a", "2026-09-01T10:00:00Z")], eff_detail="full")
        self.assertNotIn("Undated", md)


if __name__ == "__main__":
    unittest.main()
