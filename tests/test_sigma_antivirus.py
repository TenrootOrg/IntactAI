"""Sigma's antivirus rules fire on every AV / EDR product's detections.

SigmaHQ's category/antivirus rules -- password dumpers, ransomware, web shells,
exploitation frameworks; 6 of them CRITICAL -- match the threat name the product
gave (Signature) and the file (Filename). No row was ever an "antivirus" row, so
none of them could fire on an attached EDR export (2026-10-20 severity audit).
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

# SigmaHQ rules/category/antivirus/av_password_dumper.yml (selection shortened) and
# av_webshell.yml's Filename branch, as shipped.
DUMPER = S.compile_rule({
    "title": "Antivirus Password Dumper Detection", "id": "78cc2dd2", "level": "critical",
    "logsource": {"category": "antivirus"},
    "detection": {"selection": [{"Signature|startswith": "PWS"},
                                {"Signature|contains": ["Mimikatz", "DumpLsass", "Rubeus", "SafetyKatz"]}],
                  "condition": "selection"}})
WEBSHELL = S.compile_rule({
    "title": "Antivirus Web Shell Detection", "id": "fdf135a2", "level": "high",
    "logsource": {"category": "antivirus"},
    "detection": {"selection": [{"Signature|startswith": ["ASP.", "JSP."]},
                                {"Filename|endswith": [".aspx", ".jsp"]}],
                  "condition": "selection"}})


def fires(rule, row):
    return [r["title"] for r in S.evaluate(row, [rule])]


class AntivirusRows(unittest.TestCase):
    def test_each_products_threat_name_is_the_signature(self):
        rows = {
            "Windows Defender 1116": {"EventID": 1116, "Channel": "Microsoft-Windows-Windows Defender/Operational",
                                      "Threat Name": "HackTool:Win32/Mimikatz.D", "Path": "file:_C:\\t\\m.exe"},
            "Defender for Endpoint": {"Timestamp": "x", "DeviceName": "ws01", "ThreatName": "Trojan:Win32/DumpLsass.A"},
            "SentinelOne": {"threatInfo.threatName": "Rubeus.exe", "agentRealtimeInfo.agentComputerName": "ws01"},
            "ESET PROTECT": {"threat_name": "Win64/Riskware.Mimikatz.A", "hostname": "ws01"},
            "Symantec SEP": {"Risk_Name": "Hacktool.Mimikatz", "Computer_Name": "ws01"},
            "Trend Micro": {"VirusName": "PWS.Win32.Agent", "EndpointHost": "ws01"},
        }
        for name, row in rows.items():
            self.assertEqual(["Antivirus Password Dumper Detection"], fires(DUMPER, row), name)

    def test_the_file_is_the_filename(self):
        row = {"threat_name": "Backdoor.Generic", "file_path": "C:\\inetpub\\wwwroot\\cmd.aspx"}
        self.assertEqual(["Antivirus Web Shell Detection"], fires(WEBSHELL, row))

    def test_an_ids_signature_is_not_an_antivirus_detection(self):
        # Suricata's "signature" is its own rule name; Sigma's AV rules are not about it.
        row = {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4", "dest_port": 445,
               "alert.signature": "ET EXPLOIT Possible Mimikatz traffic"}
        self.assertEqual([], fires(DUMPER, row))
        self.assertNotIn((None, "antivirus", None), S.profiles(S.Event(row)))

    def test_a_clean_row_of_an_av_product_does_not_fire(self):
        self.assertEqual([], fires(DUMPER, {"ThreatName": "Adware:Win32/OpenCandy", "DeviceName": "ws01"}))

    def test_the_signer_of_a_loaded_image_stays_sysmons_own_field(self):
        # image_load rules read Sysmon's Signature (the code signer): the exact column wins.
        ev = S.Event({"EventID": 7, "Signature": "Microsoft Windows", "ThreatName": "x"})
        self.assertEqual("Microsoft Windows", ev.get("Signature"))


if __name__ == "__main__":
    unittest.main()
