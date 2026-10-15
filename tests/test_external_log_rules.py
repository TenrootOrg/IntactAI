"""Attached log data enters the fusion only as DETECTIONS.

The rules in config/external_log_rules.yaml read each product's OWN verdict
(threat flags, malicious classifications, an identity provider's risk events, an
IDS notice, a WAF attack score...) and a row's stated severity; a row nothing
marks stays out of the graph. Checked three ways: every rule's own examples,
the 63-product corpus (alert exports detect, pure telemetry stays quiet), and a
detect / benign pair per product for its native markers.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import yaml  # noqa: E402
from external_log_providers import SAMPLES, ATK, INT, T, H  # noqa: E402
from services.fusion import external_logs as X  # noqa: E402
from test_external_log_providers import read  # noqa: E402

ALERT = ("medium", "high", "critical")


def detections(text):
    return [r["n"] for r in read(text)[1] if r["n"].get("severity") in ALERT]


class EveryRuleProvesItself(unittest.TestCase):
    def test_fires_and_quiet_examples(self):
        with open(X.RULES_PATH) as f:
            doc = yaml.safe_load(f)
        self.assertTrue(doc["native"])
        for spec in doc["native"]:
            with self.subTest(spec["id"]):
                ex = spec.get("examples") or {}
                self.assertTrue(ex.get("fires") and ex.get("quiet"), "a rule needs fires AND quiet examples")
                for row in ex["fires"]:
                    self.assertIn(spec["id"], [h[0]["id"] for h in X.native_hits(row)], row)
                for row in ex["quiet"]:
                    self.assertNotIn(spec["id"], [h[0]["id"] for h in X.native_hits(row)], row)


# What a product's export IS decides whether it may detect: alert / threat exports
# must, telemetry (process, flow, DNS, web, logon events) must not -- that is for
# the Sigma and behaviour rules, not for the product's own verdict.
DETECTS = {
    "Microsoft Defender for Endpoint - alerts API", "CrowdStrike Falcon - Alerts API", "SentinelOne - threats API", "SentinelOne - unified alerts API", "ESET PROTECT - detections API", "Cisco Firepower (FTD) - intrusion syslog", "SonicWall - syslog",
    "VMware Carbon Black Cloud - alerts", "Palo Alto Cortex XDR - alerts", "Sophos Central - SIEM alerts",
    "Trend Micro Vision One - workbench alerts", "Cisco Secure Endpoint (AMP) - events", "Elastic Defend (ECS)",
    "Wazuh - alerts.json", "Symantec Endpoint Protection - CSV risk export", "ESET PROTECT - syslog JSON",
    "Trellix ePO - threat events CSV", "Microsoft Entra ID - sign-in logs",
    "Microsoft Entra ID Protection - risk detections", "Cisco Duo - authentication logs",
    "Palo Alto PAN-OS - threat CSV export", "Palo Alto PAN-OS - CEF", "Fortinet FortiGate - key=value",
    "Check Point - LEEF", "Sophos Firewall (XG) - syslog", "Suricata - eve.json alert", "Zscaler ZIA - NSS web log",
    "Netskope - alerts", "Cloudflare - HTTP requests (Logpush)", "Splunk - CSV export",
    "Elastic / Kibana - search export", "Microsoft Sentinel - KQL results CSV", "IBM QRadar - offense events CSV",
    "Google SecOps (Chronicle) - UDM", "ArcSight - CEF", "LogRhythm - alarm export CSV",
    "Proofpoint TAP - SIEM API", "Mimecast - TTP URL logs",
    "Cisco Umbrella - DNS logs CSV (no header)",          # Umbrella's own "Malware" category, read via its layout
}


class TheCorpus(unittest.TestCase):
    def test_alert_exports_detect_and_telemetry_stays_quiet(self):
        for name, _dt, text, _w in SAMPLES:
            with self.subTest(name):
                self.assertEqual(name in DETECTS, bool(detections(text)), detections(text)[:1])

    def test_a_detection_is_named_by_the_product_not_a_neighbour_column(self):
        for name, _dt, text, _w in SAMPLES:
            for n in detections(text):
                with self.subTest(name):
                    self.assertTrue(n.get("rule"), n)
                    self.assertNotIn(n.get("rule"), ("WS01", "ws01.corp.local", "jdoe"), n)


def _jl(*o):
    return "\n".join(json.dumps(x) for x in o)


# (product, rule it must hit, a row that is the product's detection, its benign twin)
PAIRS = [
    ("Okta - threat detected", "identity-provider-threat-event",
     {"published": f"{T}Z", "eventType": "security.threat.detected", "actor": {"alternateId": "jdoe@corp.com"},
      "client": {"ipAddress": ATK}, "displayMessage": "Request from suspicious actor"},
     {"published": f"{T}Z", "eventType": "user.session.start", "actor": {"alternateId": "jdoe@corp.com"},
      "client": {"ipAddress": ATK}, "displayMessage": "User login to Okta"}),
    ("Okta - threatSuspected", "threat-flag",
     {"published": f"{T}Z", "eventType": "user.authentication.sso", "actor": {"alternateId": "jdoe@corp.com"},
      "client": {"ipAddress": ATK}, "debugContext": {"debugData": {"threatSuspected": "true"}}},
     {"published": f"{T}Z", "eventType": "user.authentication.sso", "actor": {"alternateId": "jdoe@corp.com"},
      "client": {"ipAddress": ATK}, "debugContext": {"debugData": {"threatSuspected": "false"}}}),
    ("Google Workspace - suspicious login", "identity-provider-threat-event",
     {"id": {"time": f"{T}.000Z"}, "actor": {"email": "jdoe@corp.com"}, "ipAddress": ATK,
      "events": [{"type": "login", "name": "suspicious_login"}]},
     {"id": {"time": f"{T}.000Z"}, "actor": {"email": "jdoe@corp.com"}, "ipAddress": ATK,
      "events": [{"type": "login", "name": "login_success"}]}),
    ("Entra ID - risky sign-in state", "identity-risk-state",
     {"createdDateTime": f"{T}Z", "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK, "riskState": "atRisk",
      "riskLevelDuringSignIn": "none"},
     {"createdDateTime": f"{T}Z", "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK, "riskState": "none",
      "riskLevelDuringSignIn": "none"}),
    ("Auth0 - breached password", "identity-provider-threat-event",
     {"date": f"{T}.000Z", "type": "pwd_leak", "ip": ATK, "user_name": "jdoe@corp.com"},
     {"date": f"{T}.000Z", "type": "s", "ip": ATK, "user_name": "jdoe@corp.com"}),
    ("Duo - fraud", "identity-provider-threat-event",
     {"timestamp": 1790849100, "user": {"name": "jdoe"}, "access_device": {"ip": ATK}, "result": "fraud"},
     {"timestamp": 1790849100, "user": {"name": "jdoe"}, "access_device": {"ip": ATK}, "result": "success"}),
    ("Zeek - notice.log", "ids-notice",
     {"ts": 1790849100.1, "note": "Scan::Port_Scan", "src": ATK, "dst": INT, "msg": "scanned 120 ports"},
     {"ts": 1790849100.1, "uid": "C1", "id.orig_h": INT, "id.resp_h": ATK, "proto": "tcp"}),
    ("Cloudflare - WAF attack", "waf-attack-score",
     {"EdgeStartTimestamp": 1790849100000000000, "ClientIP": ATK, "ClientRequestHost": "portal.corp.com",
      "WAFAttackScore": 7},
     {"EdgeStartTimestamp": 1790849100000000000, "ClientIP": ATK, "ClientRequestHost": "portal.corp.com",
      "WAFAttackScore": 93}),
    ("Proofpoint - malware", "malicious-verdict",
     {"messageTime": f"{T}.000Z", "senderIP": ATK, "threatsInfoMap": [{"classification": "malware"}]},
     {"messageTime": f"{T}.000Z", "senderIP": ATK, "threatsInfoMap": [{"classification": "spam"}]}),
    ("Mimecast - malicious click", "malicious-verdict",
     {"date": f"{T}+0000", "userEmailAddress": "jdoe@corp.com", "userIpAddress": INT, "category": "Malicious"},
     {"date": f"{T}+0000", "userEmailAddress": "jdoe@corp.com", "userIpAddress": INT, "category": "Business"}),
    ("SentinelOne - suspicious", "suspicious-verdict",
     {"agentRealtimeInfo": {"agentComputerName": "WS01"}, "threatInfo": {"confidenceLevel": "suspicious",
      "createdAt": f"{T}Z", "sha256": H}},
     {"agentRealtimeInfo": {"agentComputerName": "WS01"}, "threatInfo": {"confidenceLevel": "n/a",
      "createdAt": f"{T}Z", "sha256": H}}),
    ("Zscaler - threat name", "named-threat",
     {"datetime": "Wed Oct 01 10:05:00 2026", "user": "jdoe@corp.com", "clientip": INT, "serverip": ATK,
      "threatname": "Win32.Backdoor.CobaltStrike", "action": "Blocked"},
     {"datetime": "Wed Oct 01 10:05:00 2026", "user": "jdoe@corp.com", "clientip": INT, "serverip": ATK,
      "threatname": "None", "action": "Allowed"}),
]
KV_PAIRS = [
    ("FortiGate - IPS attack", "named-threat",
     f'date=2026-10-01 time=10:05:00 type="utm" subtype="ips" srcip={INT} dstip={ATK} action="dropped" '
     'attack="Backdoor.Cobalt.Strike.Beacon"',
     f'date=2026-10-01 time=10:05:00 type="traffic" subtype="forward" srcip={INT} dstip={ATK} action="accept"'),
]
GUARDDUTY = ("AWS GuardDuty - finding",
             _jl({"createdAt": f"{T}.000Z", "type": "UnauthorizedAccess:EC2/SSHBruteForce", "severity": 8,
                  "title": "SSH brute force against i-0abc", "resource": {"instanceDetails": {"instanceId": "i-0abc"}},
                  "service": {"action": {"networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": ATK}}}}}),
             _jl({"createdAt": f"{T}.000Z", "type": "Recon:EC2/PortProbeUnprotectedPort", "severity": 2,
                  "title": "Unprotected port probed", "service": {"action": {"networkConnectionAction": {
                      "remoteIpDetails": {"ipAddressV4": ATK}}}}}))


class EachProductsOwnVerdict(unittest.TestCase):
    def _pair(self, name, rule, hit, quiet):
        d, q = detections(hit), detections(quiet)
        self.assertTrue(d, f"{name}: its own detection was missed")
        self.assertIn(rule, d[0].get("detected_by", []), d[0])
        self.assertFalse(q, f"{name}: a benign row became a detection: {q[:1]}")

    def test_json_products(self):
        for name, rule, hit, quiet in PAIRS:
            with self.subTest(name):
                self._pair(name, rule, _jl(hit, hit, hit), _jl(quiet, quiet, quiet))

    def test_key_value_products(self):
        for name, rule, hit, quiet in KV_PAIRS:
            with self.subTest(name):
                self._pair(name, rule, "\n".join([hit] * 3), "\n".join([quiet] * 3))

    def test_a_nested_blob_keeps_the_rules_and_condition(self):
        """Carbon Black's signer list is JSON in one column: a vendor NAME there
        is no stopped service unless the same blob says stopped."""
        row = {"device_timestamp": "2026-10-01T10:05:00Z", "device_name": "WS01", "type": "endpoint.event.filemod",
               "process_publisher": '[{"name": "Carbon Black", "state": "FILE_SIGNATURE_STATE_VERIFIED"}]'}
        self.assertEqual([], detections(_jl(row, row, row)))
        row["process_publisher"] = '[{"Name": "Sysmon64", "State": "stopped"}]'
        self.assertTrue(detections(_jl(row, row, row)))

    def test_a_name_alone_does_not_regrade_what_the_product_graded(self):
        """Sophos Central puts a threat name on events it grades low; with no
        stated severity, the name alone is still a detection."""
        row = {"when": "2026-10-01T10:05:00Z", "endpoint_id": "e1", "type": "Event::Endpoint::Threat",
               "threat": "Troj/Agent-AAA", "severity": "low", "source": "CORP\\jdoe"}
        self.assertEqual([], detections(_jl(row, row, row)))
        del row["severity"]
        self.assertEqual(["Troj/Agent-AAA"], sorted({d["rule"] for d in detections(_jl(row, row, row))}))

    def test_a_number_or_flag_is_titled_with_its_field(self):
        d = detections(_jl(*[{"EdgeStartTimestamp": 1790849100000000000, "ClientIP": ATK, "WAFAttackScore": 4}] * 3))
        self.assertEqual("WAFAttackScore = 4", d[0]["rule"])

    def test_a_stated_numeric_severity(self):
        name, hit, quiet = GUARDDUTY
        d = detections(hit + "\n" + quiet)
        self.assertEqual(["high"], [n["severity"] for n in d], "8 is high, 2 is no alert")
        self.assertEqual("SSH brute force against i-0abc", d[0]["rule"])


class TheBoxDecides(unittest.TestCase):
    def test_a_local_file_switches_a_rule_off(self):
        d = tempfile.mkdtemp()
        local = os.path.join(d, "local.yaml")
        with open(local, "w") as f:
            f.write("disable: [waf-attack-score]\n")
        row = {"WAFAttackScore": 5}
        self.assertTrue(X.native_hits(row))
        with mock.patch.object(X, "LOCAL_RULES", (local,)):
            self.assertFalse(X.native_hits(row))
        self.assertTrue(X.native_hits(row), "back on once the local file is gone")

    def test_a_broken_local_file_keeps_the_shipped_rules(self):
        d = tempfile.mkdtemp()
        local = os.path.join(d, "local.yaml")
        with open(local, "w") as f:
            f.write("native: [ {id: x, fields: [a], match: '(' } ]\n: : bad")
        with mock.patch.object(X, "LOCAL_RULES", (local,)):
            self.assertTrue(X.native_hits({"WAFAttackScore": 5}))


if __name__ == "__main__":
    unittest.main()
