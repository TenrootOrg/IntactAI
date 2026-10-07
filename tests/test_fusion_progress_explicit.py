"""A long fuse says where it is: step, rows done of total, rate, time left.

2026-10-07: a 233k-row fuse logged "Refusion · building case graph · 45%" and
nothing else for 15+ minutes, so a slow build and a stuck one looked the same.
correlate.assemble now reports each step (mapping <artifact>, merging, linking,
every analysis pass) to a listener, and store writes a throttled Log line.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, store  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

ART = "Windows.EventLogs.CondensedAccountUsage"


def rows(n):
    return {ART: [{"UserName": f"u{i % 7}", "DomainName": "CORP", "IpAddress": f"10.0.0.{i % 5}",
                   "Computer": "DC01.corp.local", "EventID": 4624, "LogonType": 3,
                   "EventTime": "2026-09-01T10:00:00Z", "_hostname": "DC01", "_client_id": "C.1"}
                  for i in range(n)]}


def fuse(progress):
    def contributions():                       # lazy, like store.py: mapping runs inside assemble
        yield map_agentic(rows(12_000), run_id="r1")
    return correlate.assemble("c", contributions(), ["r1"], progress=progress)


class TheLogSaysWhereTheFuseIs(unittest.TestCase):
    def test_every_step_is_reported_with_counts(self):
        lines = []
        g = fuse(store._fuse_progress_logger(lambda t, s, msg, pct=None: lines.append(msg), every=0))
        self.assertTrue(g.entities)
        text = "\n".join(lines)
        self.assertIn(f"mapping {ART} — 5,000 of 12,000 (41%)", text)
        self.assertRegex(text, r"merging mapped items — [\d,]+ of [\d,]+")
        self.assertIn("analysis · derive findings", text)
        self.assertIn("in this step", lines[-1])

    def test_the_log_is_throttled(self):
        lines = []
        fuse(store._fuse_progress_logger(lambda t, s, msg, pct=None: lines.append(msg), every=3600))
        self.assertEqual(lines, [])


class AListenerNeverBreaksAFuse(unittest.TestCase):
    def test_a_listener_that_raises_still_gets_a_graph(self):
        def broken(stage, done, total):
            raise RuntimeError("listener bug")
        self.assertTrue(fuse(broken).entities)

    def test_a_later_fuse_without_a_listener_does_not_call_the_old_one(self):
        calls = []
        fuse(lambda *a: calls.append(a))
        n = len(calls)
        fuse(None)
        self.assertEqual(len(calls), n)


if __name__ == "__main__":
    unittest.main()
