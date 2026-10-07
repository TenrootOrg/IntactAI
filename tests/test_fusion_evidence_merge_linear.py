"""Merging evidence into one entity is linear in the rows, and still exact.

2026-10-07, a migrated appliance (Ubuntu 22.04): a hunt brought 233,751 rows,
204,353 of them logon events with one user in 168,094. The case fuse sat in
"Refusion · building case graph" for 15+ minutes at 100% CPU, every Regenerate
waited on it, and a Rescan answered 409. FusionGraph.upsert rebuilt the
evidence key set from the entity's WHOLE evidence list on every merge, so one
busy entity cost n^2/2 set inserts. The key set is now kept between merges.
Measured on a synthetic copy of that case: 75k rows 33.5 s -> 1.9 s, and the
full 233k rows assemble in ~7 s; the stored graph is byte-identical.
"""
import os
import sys
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion.schema import Entity, EvidenceRef, FusionGraph  # noqa: E402


def ent(*locators, run="r1"):
    return Entity(id="user:alice", type="user", label="alice",
                  evidence=[EvidenceRef("agentic", run, loc) for loc in locators])


def locs(g):
    return [(x.run_id, x.locator) for x in g.entities["user:alice"].evidence]


class TheMergeIsExact(unittest.TestCase):
    def test_duplicates_are_dropped_and_order_is_kept(self):
        g = FusionGraph(case_id="c")
        g.upsert(ent("a", "b"))
        g.upsert(ent("b", "c"))
        g.upsert(ent("a", "c", "d"))
        g.upsert(ent("a", run="r2"))                        # same locator, other run: kept
        self.assertEqual(locs(g), [("r1", "a"), ("r1", "b"), ("r1", "c"), ("r1", "d"), ("r2", "a")])

    def test_a_list_trimmed_elsewhere_is_re_read(self):
        g = FusionGraph(case_id="c")
        g.upsert(ent("a", "b"))
        g.upsert(ent("c"))
        del g.entities["user:alice"].evidence[1:]           # e.g. a cap applied after a merge
        g.upsert(ent("b", "c"))
        self.assertEqual(locs(g), [("r1", "a"), ("r1", "b"), ("r1", "c")])

    def test_a_list_replaced_elsewhere_is_re_read(self):
        g = FusionGraph(case_id="c")
        g.upsert(ent("a"))
        g.upsert(ent("b"))
        g.entities["user:alice"].evidence = [EvidenceRef("agentic", "r1", "z")]
        g.upsert(ent("z", "a"))
        self.assertEqual(locs(g), [("r1", "z"), ("r1", "a")])

    def test_the_cache_is_never_stored(self):
        g = FusionGraph(case_id="c")
        g.upsert(ent("a"))
        g.upsert(ent("b"))
        self.assertNotIn("_ev_seen", g.to_dict())


class TheMergeIsLinear(unittest.TestCase):
    def test_40k_rows_on_one_entity_merge_in_seconds(self):
        # Quadratic, this is ~800M set inserts (minutes); linear, well under 1 s.
        g = FusionGraph(case_id="c")
        t = time.monotonic()
        for i in range(40_000):
            g.upsert(ent(f"row={i}"))
        took = time.monotonic() - t
        self.assertEqual(len(g.entities["user:alice"].evidence), 40_000)
        self.assertLess(took, 10, f"40k merges took {took:.1f}s -- quadratic again?")


if __name__ == "__main__":
    unittest.main()
