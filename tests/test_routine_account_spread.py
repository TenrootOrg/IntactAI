"""People using their own servers every day are not lateral movement.

2026-10-07, a real case: 13 admin accounts used on both of their two servers
for one to two years were 13 medium "used across 2 hosts -- consistent with
lateral movement" rows. Pattern rule routine-account-spread (catalogue): a
spread seen for a long time with many observations is low; a new or rare one
stays as rated.
"""
import datetime as dt
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

ART = "Windows.EventLogs.CondensedAccountUsage"


def logon(user, host, day):
    t = (dt.datetime(2026, 1, 1) + dt.timedelta(days=day)).strftime("%Y-%m-%dT09:00:00Z")
    return {"UserName": user, "DomainName": "CORP", "IpAddress": "10.0.0.5", "Computer": host,
            "EventID": 4624, "LogonType": 10, "EventTime": t, "_hostname": host, "_client_id": f"C.{host}"}


def spread_findings(rows):
    ents, rels = map_agentic({ART: rows}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="informational")
    return {f.title: f for f in g.findings if f.kind == "cross_host" and f.title.startswith("Account")}


class RoutineSpread(unittest.TestCase):
    def test_daily_admin_work_on_two_servers_is_low(self):
        rows = [logon("alice.adm", h, d) for d in range(0, 60, 3) for h in ("SRV1", "SRV2")]
        fs = spread_findings(rows)
        self.assertEqual(len(fs), 1, list(fs))
        f = next(iter(fs.values()))
        self.assertEqual(f.severity, "low")
        self.assertIn("established pattern", f.summary)

    def test_a_rare_spread_stays_as_rated(self):
        rows = [logon("bob", "SRV1", 0), logon("bob", "SRV2", 1), logon("bob", "SRV1", 2)]
        fs = spread_findings(rows)
        self.assertEqual([f.severity for f in fs.values()], ["medium"])

    def test_condensed_rows_carry_their_count_and_last_time(self):
        # The artifact's default output (Aggregate=Y): one row per account,
        # host and source with Count and LastSeen. The same daily routine as
        # above arrives as two rows, and must still read as one.
        rows = []
        for h in ("SRV1", "SRV2"):
            r = logon("alice.adm", h, 0)
            r.update(Count=200, LastSeen="2026-03-01T09:00:00Z")
            rows.append(r)
        fs = spread_findings(rows)
        self.assertEqual([f.severity for f in fs.values()], ["low"], [f.summary for f in fs.values()])
        self.assertIn("400 observations", next(iter(fs.values())).summary)

    def test_a_condensed_rare_spread_stays_as_rated(self):
        rows = []
        for h in ("SRV1", "SRV2"):
            r = logon("bob", h, 0)
            r.update(Count=1, LastSeen=r["EventTime"])
            rows.append(r)
        fs = spread_findings(rows)
        self.assertEqual([f.severity for f in fs.values()], ["medium"])

    def test_the_same_row_twice_is_counted_once(self):
        r = logon("carol", "SRV1", 0)
        r.update(Count=500, LastSeen="2026-06-01T09:00:00Z")
        # The same run's rows merged twice (one evidence locator): counted once.
        ents, rels = map_agentic({ART: [r]}, run_id="r1")
        again, rels2 = map_agentic({ART: [dict(r)]}, run_id="r1")
        g = correlate.assemble("c", [(ents, rels), (again, rels2)], ["r1"], min_severity="informational")
        acct = next(e for e in g.entities.values() if e.type == "account" and "carol" in e.label)
        self.assertEqual(acct.attrs.get("logon_count"), 500)


if __name__ == "__main__":
    unittest.main()
