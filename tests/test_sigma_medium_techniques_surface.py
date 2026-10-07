"""Medium SIGMA technique detections must surface as findings; medium NOISE must not.

2026-10-07, an APTSimulator run on a lab Win11: WMI Persistence, "Change PowerShell
Policy to Insecure", and a firewall rule added via WmiPrvSE were all DETECTED (Hayabusa
rated them medium) but NEVER surfaced -- the SIGMA->finding path had a hard `high` floor,
so only log-clearing (the only thing Hayabusa rates high on a hands-on box) ever showed.
The medium NOISE the high floor was really hiding is the broad PowerShell heuristic
("Potentially Malicious PwSh", 446 hits that run, mostly benign module loads).

The fix: the finding floor is now `medium` (correlate), and the broad PowerShell
heuristics are downweighted to low in fusion_weighting.yaml. So the real medium
techniques surface and the heuristic noise stays below the floor -- without a per-title
allowlist that would miss next year's technique.
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

ART = "Windows.Hayabusa.Rules"
HOST = "WS01"


def sigma(title, level, eid=4104, chan="Microsoft-Windows-PowerShell/Operational"):
    return {"Timestamp": "2026-10-07T10:27:01Z", "Computer": HOST, "Channel": chan,
            "EID": eid, "Level": level, "Title": title, "RecordID": hash(title) & 0xffff,
            "Details": "x", "_hostname": HOST, "_client_id": f"C.{HOST}"}


def findings_for(rows):
    ents, rels = map_agentic({ART: rows}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="medium")
    return {f.title: f for f in g.findings}


class MediumTechniquesSurface(unittest.TestCase):
    def test_real_medium_technique_becomes_a_finding(self):
        fs = findings_for([sigma("WMI Persistence", "medium", eid=5859,
                                 chan="Microsoft-Windows-WMI-Activity/Operational")])
        hit = [t for t in fs if "WMI Persistence" in t]
        self.assertEqual(len(hit), 1, list(fs))
        self.assertEqual(fs[hit[0]].severity, "medium")

    def test_broad_powershell_heuristic_is_not_a_finding(self):
        # 20 hits of the noisy heuristic, as a real run produces -- still zero findings.
        fs = findings_for([sigma("Potentially Malicious PwSh", "medium") for _ in range(20)])
        self.assertFalse([t for t in fs if "Malicious PwSh" in t], list(fs))

    def test_noise_does_not_bury_the_real_technique_when_both_present(self):
        rows = [sigma("Potentially Malicious PwSh", "medium") for _ in range(20)]
        rows += [sigma("Uncommon PowerShell Hosts", "medium")]
        rows += [sigma("WMI Persistence", "medium", eid=5859,
                       chan="Microsoft-Windows-WMI-Activity/Operational")]
        fs = findings_for(rows)
        self.assertTrue([t for t in fs if "WMI Persistence" in t], list(fs))
        self.assertFalse([t for t in fs if "PwSh" in t or "PowerShell Hosts" in t], list(fs))


if __name__ == "__main__":
    unittest.main()
