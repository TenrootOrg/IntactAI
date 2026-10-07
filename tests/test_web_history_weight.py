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
from services.fusion.mappers.agentic import _web_weight, map_agentic  # noqa: E402
from services.fusion.severity import from_anomaly  # noqa: E402

ART = "DetectRaptor.Windows.Detection.Webhistory"


def sev(cat, dom):
    return from_anomaly(_web_weight(cat, dom))


class TheCategoryDecides(unittest.TestCase):
    def test_everyday_tools_are_informational(self):
        self.assertEqual(sev("Archive Utilities", "www.7-zip.org"), "informational")

    def test_common_context_dependent_categories_are_low(self):
        for cat, dom in (("RMM", "www.teamviewer.com"), ("Phishing Hosting", "drive.google.com"),
                         ("URL Shortener", "tinyurl.com"), ("TLD", "moridim.xyz"),
                         ("Direct IP address", "84.110.121.170")):
            self.assertEqual(sev(cat, dom), "low", cat)

    def test_what_deserves_a_look_is_medium(self):
        for cat, dom in (("Malware Hosting and Exfiltration", "pastebin.com"),
                         ("Enumeration", "www.advanced-ip-scanner.com"),
                         ("TLD", "ljzq.lzqmjakbblmvy.top")):          # generated-looking name
            self.assertEqual(sev(cat, dom), "medium", dom)

    def test_local_addresses_are_informational(self):
        for ip in ("169.254.95.118", "10.1.2.3", "192.168.1.1", "127.0.0.1"):
            self.assertEqual(sev("Direct IP address", ip), "informational", ip)

    def test_an_unknown_category_is_never_silently_downgraded(self):
        self.assertEqual(sev("Some Category Added Next Year", "x.example"), "medium")


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
