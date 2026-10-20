"""FortiGate configuration changes and Windows file reads reach their medium SigmaHQ rules.

2026-10-20 severity audit, medium tier: FortiGate's "Object attribute configured" events
(new admin, firewall policy, SSL-VPN settings -- 7 rules) and Windows file_access (DPAPI
master keys, Credential Manager, browser and wallet files -- 6 rules, written for the
Kernel-File ETW provider) had no row with their log sources. Security 4663 and Elastic
Defend's file access carry the same facts. Rule bodies are SigmaHQ's.
"""
import json
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402

NEW_ADMIN = S.compile_rule({  # fortinet_fortigate_new_admin_account_created.yml
    "title": "FortiGate - New Administrator Account Created", "id": "cd0a4943", "level": "medium",
    "logsource": {"product": "fortigate", "service": "event"},
    "detection": {"selection": {"action": "Add", "cfgpath": "system.admin"}, "condition": "selection"}})
DPAPI = S.compile_rule({  # file_access_win_susp_dpapi_master_key_access.yml
    "title": "Access To Windows DPAPI Master Keys By Uncommon Applications", "id": "46612ae6", "level": "medium",
    "logsource": {"product": "windows", "category": "file_access"},
    "detection": {"selection": {"FileName|contains": ["\\Microsoft\\Protect\\S-1-5-18\\", "\\Microsoft\\Protect\\S-1-5-21-"]},
                  "filter_system_folders": {"Image|startswith": ["C:\\Program Files\\", "C:\\Windows\\system32\\"]},
                  "condition": "selection and not 1 of filter_*"}})
KEY = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1-2-3-1104\\0f5a0c4e-9f45"


def titles(raw, rules):
    return [h["title"] for h in S.evaluate(X.sigma_event(raw), rules)]


class FortiGate(unittest.TestCase):
    LINE = ('date=2026-10-20 time=10:05:00 devname="FGT1" devid="FGVM01TM00000001" logid="0100044547" type="event" '
            'subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="admin" '
            'ui="GUI(203.0.113.9)" action="{action}" cfgtid=1234 cfgpath="{path}" cfgobj="backdoor"')

    def row(self, action, path):
        _fmt, rows, _left = X.read(self.LINE.format(action=action, path=path))
        return rows[0]

    def test_a_new_admin_account(self):
        self.assertEqual(["FortiGate - New Administrator Account Created"],
                         titles(self.row("Add", "system.admin"), [NEW_ADMIN]))

    def test_an_ordinary_change_is_quiet(self):
        self.assertEqual([], titles(self.row("Edit", "system.admin"), [NEW_ADMIN]))
        self.assertEqual([], titles(self.row("Add", "firewall.schedule"), [NEW_ADMIN]))


class FileAccess(unittest.TestCase):
    def test_security_4663_reading_a_master_key(self):
        ev = {"EventID": 4663, "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
              "ObjectType": "File", "ObjectName": KEY, "ProcessName": "C:\\Users\\jdoe\\Downloads\\mimi.exe",
              "AccessMask": "0x1"}
        self.assertEqual(["Access To Windows DPAPI Master Keys By Uncommon Applications"], titles(ev, [DPAPI]))
        self.assertEqual([], titles({**ev, "ProcessName": "C:\\Windows\\System32\\lsass.exe"}, [DPAPI]),
                         "the rule's own filter: a system process")

    def test_elastic_defend_file_open(self):
        row = {"event.category": ["file"], "event.type": ["access"], "event.action": "open",
               "file.path": KEY, "process.executable": "C:\\Users\\jdoe\\Downloads\\mimi.exe"}
        self.assertEqual(["Access To Windows DPAPI Master Keys By Uncommon Applications"], titles(row, [DPAPI]))


if __name__ == "__main__":
    unittest.main()
