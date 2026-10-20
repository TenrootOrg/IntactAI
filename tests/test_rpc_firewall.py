"""RPC Firewall audits reach Sigma's 17 RPC Firewall rules (all high).

Zero Networks' RPC Firewall writes each audited call to the Windows Application log
(provider RPCFW, event 3: InterfaceUuid, OpNum, the caller). No row had the
rpc_firewall log source and nothing answered the rules' "EventLog: RPCFW"
(2026-10-20 severity audit). Rule body: SigmaHQ rpc_firewall_dcsync_attack.yml.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import sigma_eval as S  # noqa: E402

DCSYNC = S.compile_rule({
    "title": "Remote DCSync Attempt Via RPC", "id": "56fda488", "level": "high",
    "logsource": {"product": "rpc_firewall", "category": "application"},
    "detection": {"selection": {"EventLog": "RPCFW", "EventID": 3,
                                "InterfaceUuid": "e3514235-4b06-11d1-ab04-00c04fc2dcd2"},
                  "filter": {"OpNum": [0, 1, 12]},
                  "condition": "selection and not filter"}})


def audit(opnum, uuid="e3514235-4b06-11d1-ab04-00c04fc2dcd2", provider="RPCFW", eid=3):
    return {"EventID": eid, "Channel": "Application", "Provider": provider, "Computer": "DC01.corp.local",
            "InterfaceUuid": uuid, "OpNum": opnum, "Protocol": "ncacn_ip_tcp",
            "SourceNetworkAddress": "10.0.0.7", "ClientName": "WS07"}


def fires(row):
    return [r["title"] for r in S.evaluate(row, [DCSYNC])]


class RpcFirewall(unittest.TestCase):
    def test_dcsync_replication_call_fires(self):
        self.assertEqual(["Remote DCSync Attempt Via RPC"], fires(audit(3)))          # DRSGetNCChanges

    def test_the_rules_own_filter_holds(self):
        for op in (0, 1, 12):                                  # DRSBind / DRSUnbind / DRSCrackNames
            self.assertEqual([], fires(audit(op)), op)

    def test_only_rpcfw_audits_are_rpc_firewall_rows(self):
        self.assertEqual([], fires(audit(3, provider="Application Error")))
        self.assertNotIn(("rpc_firewall", "application", None),
                         S.profiles(S.Event(audit(3, provider="Application Error"))))


if __name__ == "__main__":
    unittest.main()
