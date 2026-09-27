"""A "+N related" row keeps its id when it gains a member — and a verdict given
under the old id scheme finds it again.

Found live (jev_test): an analyst's False-positive on "Malicious PowerShell
Commandlets (+1 related) on ALClient06" matched no row after the group became
"+2 related" — its id hashed every member id, so membership change = new id.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

TS = "2026-06-21T13:30:08Z"


def _row(title, rec=4242):
    return {"Timestamp": TS, "Title": title, "Level": "high", "Computer": "HOSTA",
            "Channel": "Microsoft-Windows-PowerShell/Operational", "EID": 4104, "RecordID": rec,
            "Details": "ScriptBlockID: 1234abcd ¦ MessageNumber: 1", "_hostname": "HOSTA",
            "_client_id": "C.HOSTA"}


def _fuse(titles, dispositions=None):
    ents, rels = map_agentic({"Windows.Hayabusa.Rules": [_row(t) for t in titles]}, run_id="r1")
    return correlate.assemble("c", [(ents, rels)], ["r1"], dispositions=dispositions)


def _group(g):
    return next(f for f in g.findings if "related" in f.title)


class StableIds(unittest.TestCase):
    TWO = ["Malicious PowerShell Commandlets", "Suspicious Powershell Commandlets"]
    THREE = TWO + ["Mimikatz Execution via PowerShell"]

    def test_the_id_survives_a_new_member(self):
        g2, g3 = _fuse(self.TWO), _fuse(self.THREE)
        self.assertIn("(+1 related)", _group(g2).title)
        self.assertIn("(+2 related)", _group(g3).title)
        self.assertEqual(_group(g2).id, _group(g3).id)

    def test_a_verdict_under_the_old_scheme_comes_back(self):
        g2 = _fuse(self.TWO)
        grp = _group(g2)
        # the pre-stable id of the 2-member group: host, first second, logged, member ids
        member_ids = [f.id for f in _fuse(["Malicious PowerShell Commandlets"]).findings] + \
                     [f.id for f in _fuse(["Suspicious Powershell Commandlets"]).findings]
        old_id = correlate._fid("grp", grp.asset_ids[0], TS[:19], "", *sorted(member_ids))
        g3 = _fuse(self.THREE, dispositions=[{"target": old_id, "verdict": "benign",
                                              "attribution": "operator"}])
        row = _group(g3)
        self.assertIn(old_id, row.ids())
        self.assertEqual(row.kind, "dispositioned")


class LeadRule(unittest.TestCase):
    def test_the_specific_rule_names_the_row(self):
        g = _fuse(["Suspicious Powershell Commandlets", "Mimikatz Execution via PowerShell"])
        self.assertTrue(_group(g).title.startswith("SIGMA: Mimikatz Execution via PowerShell (+1 related)"),
                        _group(g).title)

    def test_same_rules_same_name_whatever_the_order(self):
        a = _fuse(["Suspicious Service Name", "Suspicious Service Path"])
        b = _fuse(["Suspicious Service Path", "Suspicious Service Name"])
        self.assertEqual(_group(a).title, _group(b).title)


if __name__ == "__main__":
    unittest.main()
