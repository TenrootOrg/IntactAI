"""External data: a bare username in a log reaches the account the case knows.

Known bug (2026-11-08): a log added under Case Analysis -> External data linked
an account only when it carried its domain (CORP\\kobi, kobi@corp.com). A bare
`kobi` -- Linux auth, VPN and many firewall logs -- joined nothing, even with
CORP\\kobi already in the case from a Velociraptor collection.

A bare name now joins when the case has exactly ONE account with that short
name. It stays out when two do (ambiguous), when none does, and always for
names every system has (admin, root, guest...).
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
from services.fusion.mappers.external import map_external  # noqa: E402

ART = "Windows.EventLogs.CondensedAccountUsage"


def logon(domain, user, host="SRV1"):
    return {"UserName": user, "DomainName": domain, "IpAddress": "10.0.0.5", "Computer": host,
            "EventID": 4624, "LogonType": 10, "EventTime": "2026-11-01T09:00:00Z",
            "_hostname": host, "_client_id": f"C.{host}"}


def vpn(user, sev="high"):
    """One VPN alert row naming a bare user (what external_logs.normalize gives)."""
    return {"n": {"ts": "2026-11-02T10:00:00Z", "user": user, "src_ip": "203.0.113.9",
                  "severity": sev, "rule": "VPN login from new country"}}


def allusers(user, host="SRV1"):
    """A host's user listing: no domain column, so every profile is a LOCAL account."""
    return {"Name": user, "UUID": "S-1-5-21-1-2-3-1105", "Directory": f"C:\\Users\\{user}",
            "_hostname": host, "_client_id": f"C.{host}"}


def fuse(endpoint_rows, log_rows, listing=None, log2=None):
    collected = {ART: endpoint_rows}
    if listing:
        collected["Windows.Sys.AllUsers"] = listing
    batches = [map_agentic(collected, run_id="r1"),
               map_external({"External.idp": log_rows}, run_id="r2", data_type="idp", label="vpn")]
    runs = ["r1", "r2"]
    if log2:
        batches.append(map_external({"External.idp": log2}, run_id="r3", data_type="idp", label="idp"))
        runs.append("r3")
    return correlate.assemble("c", batches, runs, min_severity="informational")


def accounts(g):
    return {e.id: e for e in g.entities.values() if e.type == "account"}


class BareNames(unittest.TestCase):
    def test_a_bare_name_joins_the_one_account_with_that_name(self):
        g = fuse([logon("corp", "kobi")], [vpn("kobi")])
        acc = accounts(g)
        self.assertIn("account:domain:corp\\kobi", acc)
        self.assertFalse([i for i in acc if i.startswith("account:bare:")], "folded in, not a second card")
        kobi = acc["account:domain:corp\\kobi"]
        self.assertIn("external", kobi.sources, "the log's rows are now on the case's account")
        alert = next(e for e in g.entities.values() if e.type == "event" and "VPN" in e.label)
        linked = {r.src for r in g.relationships if r.dst == alert.id} | \
                 {r.dst for r in g.relationships if r.src == alert.id}
        self.assertIn("account:domain:corp\\kobi", linked, "the alert is about that account")

    def test_two_accounts_with_the_name_is_ambiguous(self):
        g = fuse([logon("corp", "kobi"), logon("lab", "kobi", host="SRV2")], [vpn("kobi")])
        acc = accounts(g)
        self.assertFalse([i for i in acc if i.startswith("account:bare:")])
        for i in ("account:domain:corp\\kobi", "account:domain:lab\\kobi"):
            self.assertNotIn("external", acc[i].sources, f"{i} must not take a guess")

    def test_names_every_system_has_never_join(self):
        g = fuse([logon("corp", "admin"), logon("corp", "root")], [vpn("admin"), vpn("root")])
        acc = accounts(g)
        for i in ("account:domain:corp\\admin", "account:domain:corp\\root"):
            self.assertNotIn("external", acc[i].sources)

    def test_a_name_the_case_does_not_know_stays_out(self):
        g = fuse([logon("corp", "kobi")], [vpn("dana")])
        self.assertFalse([i for i in accounts(g) if "dana" in i], "no card for a bare log-only name")

    def test_a_domain_users_local_profile_twin_is_not_ambiguity(self):
        # Sys.AllUsers lists CORP\\kobi's profile as a local "kobi" on SRV1.
        g = fuse([logon("corp", "kobi")], [vpn("kobi")], listing=[allusers("kobi")])
        self.assertIn("external", accounts(g)["account:domain:corp\\kobi"].sources)

    def test_a_local_account_on_another_host_is_not_joined(self):
        # A local kobi on SRV1 is not the kobi of an alert that names SRV9.
        row = vpn("kobi")
        row["n"]["host"] = "SRV9"
        g = fuse([logon("corp", "dana", host="SRV9")], [row], listing=[allusers("kobi")])
        self.assertFalse([f for f in g.findings if f.kind == "cross_host" and "kobi" in f.title.lower()],
                         "no 'used across 2 hosts' out of a guessed join")
        local = [e for i, e in accounts(g).items() if i.startswith("account:asset:") and i.endswith(":kobi")]
        self.assertTrue(local and all("external" not in e.sources for e in local))

    def test_a_name_only_another_log_mentions_does_not_block_the_join(self):
        g = fuse([logon("corp", "kobi")], [vpn("kobi")], log2=[vpn("kobi@partner.com", sev="info")])
        self.assertIn("external", accounts(g)["account:domain:corp\\kobi"].sources)

    def test_placeholder_names_never_join(self):
        g = fuse([logon("corp", "unknown")], [vpn("unknown")])
        self.assertNotIn("external", accounts(g)["account:domain:corp\\unknown"].sources)

    def test_row_counts_add_up_without_a_conflict(self):
        g = fuse([logon("corp", "kobi")], [vpn("kobi"), vpn("CORP\\kobi"), vpn("kobi")])
        kobi = accounts(g)["account:domain:corp\\kobi"]
        self.assertEqual(kobi.attrs.get("external_rows"), 3)
        self.assertNotIn("conflict", kobi.flags)

    def test_a_qualified_name_still_joins_as_before(self):
        g = fuse([logon("corp", "kobi")], [vpn("CORP\\kobi")])
        self.assertIn("external", accounts(g)["account:domain:corp\\kobi"].sources)


if __name__ == "__main__":
    unittest.main()
