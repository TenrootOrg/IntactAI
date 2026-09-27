"""One severity rule for an account / person on several hosts.

Found in the audit (jev_test): `kobia` on two workstations was HIGH (one account
entity — hard-coded), while `nofl` on three hosts including two DCs was
informational (written differently per host, so it took the accounts' own
severity) and the medium floor dropped it. Same situation, opposite answers.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, schema  # noqa: E402


def _graph(hosts, accounts):
    g = schema.FusionGraph(case_id="c")
    for h in hosts:
        g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h))
    for eid, label, on in accounts:
        g.upsert(schema.Entity(id=eid, type="account", label=label, attrs={"_assets": [f"asset:{h}" for h in on]},
                               evidence=[schema.EvidenceRef("velociraptor", "r1", "Windows.System.Pslist/row=1")]))
    return g


class Rule(unittest.TestCase):
    def sev(self, g):
        correlate._cross_host_findings(g)
        correlate._identity_cross_host_findings(g)
        return {f.title: f.severity for f in g.findings}

    def test_one_account_on_two_workstations_is_medium(self):
        g = _graph(["WS1", "WS2"], [("account:domain:corp\\kobia", "CORP\\kobia", ["WS1", "WS2"])])
        self.assertEqual(self.sev(g), {"Account 'CORP\\kobia' used across 2 hosts": "medium"})

    def test_a_dc_makes_it_high_whichever_rule_fires(self):
        g = _graph(["WS1", "ALDC02"], [("account:domain:corp\\kobia", "CORP\\kobia", ["WS1", "ALDC02"])])
        self.assertEqual(list(self.sev(g).values()), ["high"])
        # written differently per host: the person rule, same answer
        g = _graph(["WS1", "ALDC02"], [("account:domain:corp\\nofl", "CORP\\nofl", ["ALDC02"]),
                                       ("account:asset:WS1:nofl@corp.local", "nofl@corp.local", ["WS1"])])
        got = self.sev(g)
        self.assertEqual(len(got), 1, got)
        self.assertIn("under different account forms", next(iter(got)))
        self.assertEqual(list(got.values()), ["high"])

    def test_never_below_what_the_accounts_carry(self):
        g = _graph(["WS1", "WS2"], [("account:domain:corp\\x", "CORP\\x", ["WS1", "WS2"])])
        g.entities["account:domain:corp\\x"].severity = "critical"
        self.assertEqual(list(self.sev(g).values()), ["critical"])


if __name__ == "__main__":
    unittest.main()
