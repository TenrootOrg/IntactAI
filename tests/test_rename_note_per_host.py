"""The report's rename note counts THAT host's findings.

Found in the audit (jev_test): every host with an earlier name was told the
case-wide count — "41 finding(s) predate its current name" on two domain
controllers that had none, which tells a reader to discount 41 findings on a DC.
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


class RenameNote(unittest.TestCase):
    def test_each_host_gets_its_own_count(self):
        g = schema.FusionGraph(case_id="c")
        for h in ("WS", "DC"):
            g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h,
                                   attrs={"name_history": [{"name": f"OLD-{h}", "previous": True,
                                                            "last": "2025-01-01"}]}))
        fs = []
        for i in range(3):
            g.upsert(schema.Entity(id=f"ev{i}", type="event", label="e", flags=["previous_name"],
                                   attrs={"_assets": ["asset:WS"]}))
            fs.append(schema.Finding(id=f"f{i}", title=f"SIGMA: rule {i} on WS", severity="high",
                                     confidence="m", summary="", asset_ids=["asset:WS"], entity_ids=[f"ev{i}"],
                                     ts="2025-01-01T00:00:00Z"))
        g.findings = fs
        md = render._limitations_md(g, list(g.by_type("asset")), fs)
        self.assertIn("**WS** was previously recorded as OLD-WS", md)
        self.assertIn("**3 of its detection(s) predate its current name**", md)
        self.assertIn("**DC** was previously recorded as OLD-DC", md)
        self.assertIn("None of its findings predate its current name", md)


if __name__ == "__main__":
    unittest.main()
