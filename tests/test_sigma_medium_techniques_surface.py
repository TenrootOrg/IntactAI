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


class OneEventRecordIsOneFinding(unittest.TestCase):
    """Two SIGMA rules matching the SAME Windows event record (same win_id) are one
    thing that happened, not two findings. 2026-10-08, every lab case: one log clear
    fired a high "Security Eventlog Cleared" AND a medium "Security Event Log Cleared"
    on EID 1102, and a high "Important Windows Eventlog Cleared" AND a medium "Log File
    Cleared" on EID 104 — four findings for two events. The medium naming must fold
    into the higher one, not surface again via the lone-medium pass."""

    def _rec_row(self, title, level, rec, eid=1102, chan="Security"):
        return {"Timestamp": "2026-10-07T10:27:01Z", "Computer": HOST, "Channel": chan,
                "EID": eid, "Level": level, "Title": title, "RecordID": rec,
                "Details": "x", "_hostname": HOST, "_client_id": f"C.{HOST}"}

    def test_the_medium_naming_of_one_record_is_not_a_second_finding(self):
        fs = findings_for([self._rec_row("Security Eventlog Cleared", "high", 777),
                           self._rec_row("Security Event Log Cleared", "medium", 777)])
        titles = list(fs)
        self.assertTrue(any("Security Eventlog Cleared" in t for t in titles), titles)
        self.assertFalse(any(t.startswith("SIGMA: Security Event Log Cleared") for t in titles),
                         f"the medium rule on the SAME record must not be its own finding: {titles}")
        self.assertEqual(1, sum(1 for t in titles if "clear" in t.lower()),
                         f"one record, one finding: {titles}")

    def test_a_medium_on_its_OWN_record_still_surfaces(self):
        # Guard: the dedup is by shared record, not "any medium near a high".
        fs = findings_for([self._rec_row("Security Eventlog Cleared", "high", 1),
                           self._rec_row("WMI Persistence", "medium", 2, eid=5861,
                                         chan="Microsoft-Windows-WMI-Activity/Operational")])
        self.assertTrue(any("WMI Persistence" in t for t in fs),
                        f"a medium on its own record must still surface: {list(fs)}")


if __name__ == "__main__":
    unittest.main()
