"""A domain controller is recognised from the logs, not only from its name.

APT29 / APT3 (2026-10-14): the DCs were named NEWYORK and HFDC01, so the name hint never
fired and every report said no domain controller was identified. A computer's own
account (NAME$) logs on to the DCs it talks to: a host where the machine accounts of
other hosts in the case log on is a DC. And those logons are how a domain works, so a
machine account "used across hosts" is not lateral movement.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, render, schema  # noqa: E402


def graph(hosts, accounts):
    """hosts: short names; accounts: {account label: [short host names it was seen on]}."""
    g = schema.FusionGraph(case_id="t")
    for h in hosts:
        g.upsert(schema.Entity(id=f"asset:{h.lower()}", type="asset", label=f"{h}.corp.local"))
    for lbl, seen in accounts.items():
        g.upsert(schema.Entity(id=f"account:{lbl}", type="account", label=lbl,
                               attrs={"_assets": [f"asset:{h.lower()}" for h in seen]}))
    return g


class RoleFromEvidence(unittest.TestCase):
    def test_machine_accounts_of_other_hosts_make_a_dc(self):
        g = graph(["WS1", "WS2", "NEWYORK"], {"corp\\ws1$": ["WS1", "NEWYORK"], "corp\\ws2$": ["WS2", "NEWYORK"]})
        correlate._infer_host_roles(g)
        self.assertEqual("domain controller", g.entities["asset:newyork"].attrs.get("role"))
        self.assertIn("ws1", g.entities["asset:newyork"].attrs["role_evidence"])
        self.assertNotIn("role", g.entities["asset:ws1"].attrs)

    def test_one_other_host_is_enough_in_a_two_host_case_but_not_in_a_bigger_one(self):
        g = graph(["DESK", "SRV"], {"corp\\desk$": ["DESK", "SRV"]})
        correlate._infer_host_roles(g)
        self.assertEqual("domain controller", g.entities["asset:srv"].attrs.get("role"))
        g = graph(["DESK", "SRV", "WS9"], {"corp\\desk$": ["DESK", "SRV"]})
        correlate._infer_host_roles(g)
        self.assertNotIn("role", g.entities["asset:srv"].attrs)

    def test_setup_leftovers_and_a_hosts_own_account_do_not_count(self):
        g = graph(["WS1", "SRV"], {"workgroup\\win-abc123$": ["SRV"], "corp\\srv$": ["SRV"], "minwinpc$": ["SRV"]})
        correlate._infer_host_roles(g)
        self.assertNotIn("role", g.entities["asset:srv"].attrs)

    def test_the_report_and_severity_use_the_evidence_role(self):
        g = graph(["WS1", "WS2", "NEWYORK"], {"corp\\ws1$": ["WS1", "NEWYORK"], "corp\\ws2$": ["WS2", "NEWYORK"]})
        correlate._infer_host_roles(g)
        rows = render._host_coverage(g, [e for e in g.entities.values() if e.type == "asset"], [])
        row = next(r for r in rows if r["host"].startswith("NEWYORK"))
        self.assertEqual("domain controller", row["role_hint"])
        self.assertIn("role_evidence", row)
        self.assertEqual("domain controller", correlate._host_role_of(g, "asset:newyork"))


class MachineAccountsAreNotLateralMovement(unittest.TestCase):
    def test_a_machine_account_on_two_hosts_is_no_finding_a_user_is(self):
        g = graph(["WS1", "NEWYORK"], {"corp\\ws1$": ["WS1", "NEWYORK"], "corp\\alice": ["WS1", "NEWYORK"]})
        correlate._cross_host_findings(g)
        titles = [f.title for f in g.findings]
        self.assertFalse([t for t in titles if "ws1$" in t], titles)
        self.assertTrue([t for t in titles if "alice" in t], titles)


if __name__ == "__main__":
    unittest.main()
