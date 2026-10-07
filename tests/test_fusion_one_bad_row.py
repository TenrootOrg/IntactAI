"""One bad row costs that row -- never the run, never the fuse.

2026-10-07, after a 233k-row case: map_agentic had no guard in its row loop,
so a single row that made a handler raise took the whole run's mapping with it
and the case got nothing from 233,751 rows. Every loop in the mapper (rows,
Sigma folding/episodes, process tree, SID names, detection linking) now skips
the failing item, counts it per artifact, and assemble reports the counts as
recoverable errors -- the case Log's "graph built with recoverable errors".
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, schema  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

ART = "Windows.EventLogs.CondensedAccountUsage"


class Poison(dict):
    """A row whose every read raises, wherever a handler touches it."""
    def get(self, *a, **k):
        raise ValueError("poisoned row")

    def __getitem__(self, k):
        raise ValueError("poisoned row")


def logon(i):
    return {"UserName": f"u{i}", "DomainName": "CORP", "IpAddress": "10.0.0.9", "Computer": "DC01",
            "EventID": 4624, "LogonType": 10, "EventTime": "2026-09-01T10:00:00Z",
            "_hostname": "DC01", "_client_id": "C.1"}


def data():
    rows = [logon(i) for i in range(8)]
    rows[3] = Poison(logon(3))
    return {ART: rows}


class OneBadRow(unittest.TestCase):
    def test_the_rest_of_the_run_still_maps_with_its_own_row_numbers(self):
        ents, _ = map_agentic(data(), run_id="r1")
        locs = {ev.locator for e in ents for ev in e.evidence}
        for i in (0, 2, 4, 7):
            self.assertIn(f"{ART}/row={i}", locs)
        self.assertNotIn(f"{ART}/row=3", locs)

    def test_the_fuse_reports_the_skip_as_a_recoverable_error(self):
        errs = []
        g = correlate.assemble("c", [map_agentic(data(), run_id="r1")], ["r1"], errors=errs)
        self.assertTrue(g.entities)
        self.assertEqual(errs, [])                    # mapped OUTSIDE assemble: nobody was listening
        errs = []

        def lazy():                                    # as store.py does: mapping runs inside assemble
            yield map_agentic(data(), run_id="r1")
        g = correlate.assemble("c", lazy(), ["r1"], errors=errs)
        self.assertTrue(g.entities)
        self.assertIn({"where": f"mapping {ART}: 1 item(s) skipped", "error": "ValueError: poisoned row"}, errs)

    def test_timesketch_cloud_and_memory_mappers_skip_the_bad_item_too(self):
        from services.fusion.mappers.timesketch import map_timesketch
        from services.fusion.mappers.cloud import map_cloud
        from services.fusion.mappers.memory import map_memory
        ev = lambda i: {"datetime": "2026-09-01T10:00:00Z", "message": f"evt {i} 10.0.0.{i}", "tag": ["suspicious"]}
        ts, _ = map_timesketch([ev(0), Poison(ev(1)), ev(2)], run_id="t1", asset="asset:x")
        self.assertGreater(len(ts), 1)                 # more than the asset itself
        fnd = lambda i: {"rule": "r", "severity": "high", "_timestamp": "2026-09-01T10:00:00Z",
                         "matched_record": {"userIdentity": {"arn": f"arn:aws:iam::1:user/u{i}"}, "sourceIPAddress": "1.2.3.4"}}
        cl, _ = map_cloud([fnd(0), Poison(fnd(1)), fnd(2)], run_id="c1", provider="aws")
        self.assertGreater(len(cl), 1)
        proc = lambda pid: {"PID": pid, "PPID": 4, "ImageFileName": f"p{pid}.exe", "CreateTime": "2026-09-01T10:00:00Z"}
        mem, _ = map_memory({"plugins": {"windows.pslist.PsList": [proc(100), Poison(proc(101)), proc(102)]}},
                            run_id="m1", asset="asset:x")
        self.assertGreaterEqual(sum(e.type == "process" for e in mem), 2)

    def test_a_skip_with_no_listener_never_raises(self):
        schema.map_skip("anything", RuntimeError("x"))


if __name__ == "__main__":
    unittest.main()
