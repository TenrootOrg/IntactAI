"""The detail panel says how many hits an occurrence holds, and until when.

Found in the audit (jev_test): a 60-day row with 1,512 hits — all on one folded
SIGMA entity — showed "1 occurrence".
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import schema, store  # noqa: E402


class Hits(unittest.TestCase):
    def test_folded_entity_reports_hits_and_last(self):
        g = schema.FusionGraph(case_id="c")
        g.upsert(schema.Entity(id="ev", type="event", label="SIGMA: x (x1,512)", first_seen="2026-03-26T10:00:00Z",
                               last_seen="2026-05-25T10:00:00Z", attrs={"occurrences": 1512}))
        g.findings = [schema.Finding(id="f", title="SIGMA: x on H", severity="high", confidence="m",
                                     summary="", entity_ids=["ev"], occ_count=1512)]
        with mock.patch.object(store, "get_case", return_value={"x": 1}), \
             mock.patch.object(store, "load_graph", return_value=g):
            d = store.get_finding_detail("c1", "f")
        o = d["occurrences"][0]
        self.assertEqual((o["hits"], o["last"]), (1512, "2026-05-25T10:00:00Z"))


if __name__ == "__main__":
    unittest.main()
