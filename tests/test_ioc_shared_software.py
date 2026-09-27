"""Common software on several hosts is not an IOC, and is never on the block list.

Found in the audit (jev_test): all 12 "high-confidence" IOCs were there only for
being on 2+ hosts — OneDrive.exe, Everything.exe, Advanced IP Scanner — and the
deterministic Recommendations told the customer to block 8 of those hashes.
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


def _graph():
    g = schema.FusionGraph(case_id="c")
    for h in ("A", "B"):
        g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h))
    g.upsert(schema.Entity(id="ioc:onedrive", type="ioc", label="a" * 64, severity="informational",
                           flags=["cross_host"], attrs={"_assets": ["asset:A", "asset:B"], "ioc_kind": "hash",
                                                        "source_name": "OneDrive.exe"}))
    g.upsert(schema.Entity(id="ioc:mimi", type="ioc", label="b" * 64, severity="high",
                           attrs={"_assets": ["asset:A"], "ioc_kind": "hash", "source_name": "mimikatz.exe"}))
    g.findings = [schema.Finding(id="f1", title="SIGMA: Mimikatz on A", severity="critical", confidence="high",
                                 summary="", asset_ids=["asset:A"], entity_ids=["ioc:mimi"],
                                 ts="2026-06-01T10:00:00Z")]
    return g


class SharedSoftware(unittest.TestCase):
    def test_spread_alone_is_review_not_an_indicator(self):
        kept, _ = render._high_confidence_iocs(_graph())
        reasons = {i.id: r for i, r in kept}
        self.assertEqual(reasons["ioc:mimi"], "detection")
        self.assertEqual(reasons["ioc:onedrive"], render.SHARED_SOFTWARE)

    def test_never_on_the_block_list(self):
        g = _graph()
        rec = render._recommendations_md(g, g.findings, list(g.by_type("asset")))
        self.assertIn("b" * 64, rec)
        self.assertNotIn("a" * 64, rec)

    def test_listed_separately_in_the_report(self):
        g = _graph()
        md = render.facts_md(g)
        ioc_table = md.split("## Indicators of Compromise")[1].split("###")[0]
        self.assertNotIn("a" * 64, ioc_table)
        self.assertIn("cited by a finding", ioc_table)
        self.assertIn("Shared across hosts — review, not confirmed malicious", md)


if __name__ == "__main__":
    unittest.main()
