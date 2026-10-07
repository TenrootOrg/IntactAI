"""Software that updates itself is one low row, not dozens of high ones.

2026-10-07, a real two-server case: a security agent's own updater service,
reinstalled every few weeks for 2.5 years (...\\Drivers\\<vendor>\\18913-<x>.exe,
19011-<x>.exe ...), fired the same high SIGMA rule ~45 times. Every episode
was a HIGH row, it drove host risk, and the report called it a masquerading
backdoor. The pattern -- generic, no vendor named -- is the same detection on
the same host many times over months about an object that differs only by
numbers. It folds to one LOW row with its count and span; a one-off, a short
series or a different object each time does not.
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


def hit(title, details, month, day=3):
    return {"Title": title, "Level": "high", "Channel": "System", "EID": 7045, "Computer": "SRV1",
            "Timestamp": f"2025-{month:02d}-{day:02d}T03:15:00Z", "Details": details,
            "_hostname": "SRV1", "_client_id": "C.1"}


def fuse(rows):
    ents, rels = map_agentic({ART: rows}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="informational")
    return [f for f in g.findings if f.kind != "cross_host"]


class Maintenance(unittest.TestCase):
    def test_an_updater_reinstalled_for_months_is_one_low_row(self):
        rows = [hit("Suspicious Service Path",
                    f"Svc: AgentUpdateSvc ¦ Path: %SystemRoot%\\system32\\Drivers\\Vendor\\{18900 + m * 7}-AgentUpdater.exe ¦ Acct: LocalSystem",
                    m) for m in range(1, 11)]
        fs = [f for f in fuse(rows) if "Suspicious Service Path" in f.title]
        self.assertEqual(len(fs), 1, [f.title for f in fs])
        self.assertEqual(fs[0].severity, "low")
        self.assertIn("recurring maintenance, 10×", fs[0].title)
        self.assertEqual(fs[0].recurring["period"], "maintenance")

    def test_a_different_object_each_time_is_not_maintenance(self):
        names = ["svcA", "qwerty", "x_upd", "helper", "zz9", "winsvc2", "abcde", "fooBar", "upd", "nn"]
        rows = [hit("Suspicious Service Path", f"Svc: {names[m - 1]} ¦ Path: C:\\Temp\\{names[m - 1]}.exe", m)
                for m in range(1, 11)]
        fs = [f for f in fuse(rows) if "Suspicious Service Path" in f.title]
        self.assertGreater(len(fs), 1)
        self.assertTrue(all(f.severity == "high" and not f.recurring for f in fs))

    def test_a_short_series_is_not_maintenance(self):
        rows = [hit("Suspicious Service Path", f"Svc: AgentUpdateSvc ¦ Path: C:\\Vendor\\{m}-upd.exe", m)
                for m in (1, 4, 8)]
        fs = [f for f in fuse(rows) if "Suspicious Service Path" in f.title]
        self.assertTrue(all(f.severity == "high" for f in fs))


if __name__ == "__main__":
    unittest.main()
