#!/usr/bin/env python3
"""Family skill cards: which artifact families a case has, and which cards go
into the phase vs the final report prompt."""
import os
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.agentic import skills  # noqa: E402
from services.fusion.schema import EvidenceRef, Finding  # noqa: E402


def _f(i, *locs, module="velociraptor", mitre=()):
    return Finding(id=f"f{i}", title="t", severity="high", confidence="high", summary="s",
                   evidence=[EvidenceRef(module, "r", loc) for loc in locs], mitre=list(mitre))


def _graph(findings):
    return types.SimpleNamespace(findings=findings)


INDEX = {
    "win": {"families": ["windows_ad"], "body": "WINDOWS CARD"},
    "lin": {"families": ["linux"], "body": "LINUX CARD"},
    "rec": {"families": ["any"], "report_only": True, "body": "RECOVERY CARD"},
    "old": {"body": "OLD MACRO WITHOUT FAMILIES"},
}


class CaseFamilies(unittest.TestCase):
    def test_windows_case(self):
        g = _graph([_f(i, "Windows.EventLogs.Evtx/row=1") for i in range(5)])
        self.assertEqual(skills.case_families(g), ["windows_ad"])

    def test_stray_row_does_not_add_a_family(self):
        g = _graph([_f(i, "Windows.EventLogs.Evtx/row=1") for i in range(19)]
                   + [_f(99, "Linux.Sys.Users/row=1")])
        self.assertEqual(skills.case_families(g), ["windows_ad"])

    def test_cloud_memory_and_ransomware(self):
        g = _graph([_f(1, "azure/finding=1", module="cloud"), _f(2, "aws/finding=2", module="cloud"),
                    _f(3, "PsScan/PID=7", module="memory", mitre=["T1486"])])
        fams = skills.case_families(g)
        self.assertEqual(fams[0], "ransomware")
        self.assertEqual(set(fams), {"ransomware", "azure_m365", "aws", "memory_malware"})

    def test_empty_case(self):
        self.assertEqual(skills.case_families(_graph([])), [])


class Prompt(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(skills._MACRO_INDEX, INDEX, clear=True)
        p.start()
        self.addCleanup(p.stop)
        q = mock.patch.object(skills, "_SKILLS_LOADED", True)
        q.start()
        self.addCleanup(q.stop)
        self.g = _graph([_f(i, "Windows.EventLogs.Evtx/row=1") for i in range(3)])

    def test_phase_gets_family_card_only(self):
        out = skills.family_skills_prompt("BASE", self.g)
        self.assertIn("WINDOWS CARD", out)
        self.assertNotIn("RECOVERY CARD", out)
        self.assertNotIn("LINUX CARD", out)
        self.assertNotIn("OLD MACRO", out)

    def test_final_report_adds_recovery(self):
        out = skills.family_skills_prompt("BASE", self.g, final=True)
        self.assertLess(out.index("WINDOWS CARD"), out.index("RECOVERY CARD"))

    def test_no_evidence_means_no_cards(self):
        self.assertEqual(skills.family_skills_prompt("BASE", _graph([]), final=True), "BASE")

    def test_bad_graph_falls_back_to_base(self):
        self.assertEqual(skills.family_skills_prompt("BASE", object()), "BASE")


if __name__ == "__main__":
    unittest.main()
