"""A host excluded in Configuration is not part of the fusion at all.

It used to be fused and only hidden from some views, so it still produced
findings, counted as a cross-host sighting and shaped risk scores.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from test_fusion_behavioral import _assemble  # noqa: E402


class ExcludedHostIsNotFused(unittest.TestCase):
    def test_everything_on_it_is_gone_and_nothing_is_cross_host(self):
        full = _assemble()
        self.assertTrue(any(f.kind == "cross_host" for f in full.findings))   # guard: the input does correlate

        g = _assemble(excluded_hosts=["aldc02"])        # case and form of the label do not matter
        self.assertNotIn("asset:c1", g.entities)
        self.assertNotIn("proc:1", g.entities)          # seen only on the excluded host
        self.assertEqual(g.entities["ioc:h"].attrs["_assets"], ["asset:c2"])   # shared: kept, host stripped
        self.assertFalse(any(f.kind == "cross_host" for f in g.findings))
        self.assertFalse(any("asset:c1" in (f.asset_ids or []) for f in g.findings))
        self.assertFalse(any("ALDC02" in (f.title or "") for f in g.findings))
        for r in g.relationships:
            self.assertIn(r.src, g.entities); self.assertIn(r.dst, g.entities)

    def test_no_exclusion_is_unchanged(self):
        from test_fusion_behavioral import _canon
        self.assertEqual(_canon(_assemble()), _canon(_assemble(excluded_hosts=[])))

    def test_changing_the_exclusion_forces_a_rebuild(self):
        from services.fusion import store
        a = store._graph_filter_signature({"excluded_hosts": []}, None)
        b = store._graph_filter_signature({"excluded_hosts": ["DESKTOP-16OJFO6"]}, None)
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
