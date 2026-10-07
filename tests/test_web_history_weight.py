"""Web-history hits weigh what their category means -- not "high" for everything.

2026-10-07, a real two-server admin case: every DetectRaptor.Webhistory hit
scored 40 (high), and every domain visited from both servers became a HIGH
"Indicator ... seen on 2 hosts -- shared C2" finding. 7-zip.org topped the
host-risk table; drive.google.com, canva.com and admins opening device panels
by IP made ~70 high rows, and the report narrated them as C2. The weight is
now by category meaning (words, not domain names), unknown categories stay
medium, local addresses are informational, generated-looking names on abused
TLDs are medium, and a cross-host indicator is high only when it is itself
suspicious.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

ART = "DetectRaptor.Windows.Detection.Webhistory"
# The per-category weights are rules in config/fusion_weighting.yaml; their
# examples run in test_fusion_weighting_catalogue.py. This file checks them end
# to end: mapper -> catalogue -> cross-host grading.


def visit(host, cat, dom):
    return {"Detection": {"Category": cat, "DomainRegex": dom}, "Category": cat, "Domain": dom,
            "BrowserArtifact": "Chrome", "ArtifactData": {"Visit_Date": "2026-09-01T10:00:00Z"},
            "_hostname": host, "_client_id": f"C.{host}"}


class AcrossHosts(unittest.TestCase):
    def setUp(self):
        rows = [visit(h, c, d) for h in ("SRV1", "SRV2") for c, d in (
            ("Archive Utilities", "www.7-zip.org"), ("RMM", "www.teamviewer.com"),
            ("Malware Hosting and Exfiltration", "pastebin.com"))]
        ents, rels = map_agentic({ART: rows}, run_id="r1")
        g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="informational")
        self.xhost = {f.title.split(" seen on")[0].replace("Indicator ", ""): f.severity
                      for f in g.findings if f.kind == "cross_host"}

    def test_an_everyday_domain_on_both_hosts_is_not_a_finding(self):
        self.assertFalse([k for k in self.xhost if "7-zip" in k])

    def test_a_common_tool_on_both_hosts_is_medium_not_shared_c2(self):
        self.assertEqual([v for k, v in self.xhost.items() if "teamviewer" in k], ["medium"])

    def test_a_suspicious_domain_on_both_hosts_stays_high(self):
        self.assertEqual([v for k, v in self.xhost.items() if "pastebin" in k], ["high"])


if __name__ == "__main__":
    unittest.main()
