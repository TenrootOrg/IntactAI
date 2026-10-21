"""Router routing-protocol syslog and OneLogin events reach their low SigmaHQ rules.

2026-10-20 severity audit, low tier: 275 of 281 low rules had a row to run on; the six
left were BGP / LDP MD5 authentication failures on Cisco, Huawei and Juniper routers
(free-text syslog, matched by the router's own message) and OneLogin's Events API.
Rule bodies are SigmaHQ's.
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
    return S.compile_rule({"title": title, "id": title, "level": "low", "logsource": logsource,
                           "detection": detection})


RULES = [
    r("Cisco BGP Authentication Failures", {"product": "cisco", "service": "bgp"},
      {"keywords_bgp_cisco": {"|all": [":179", "IP-TCP-3-BADAUTH"]}, "condition": "keywords_bgp_cisco"}),
    r("Cisco LDP Authentication Failures", {"product": "cisco", "service": "ldp"},
      {"selection_protocol": ["LDP"], "selection_keywords": ["SOCKET_TCP_PACKET_MD5_AUTHEN_FAIL", "TCPMD5AuthenFail"],
       "condition": "selection_protocol and selection_keywords"}),
    r("Huawei BGP Authentication Failures", {"product": "huawei", "service": "bgp"},
      {"keywords_bgp_huawei": {"|all": [":179", "BGP_AUTH_FAILED"]}, "condition": "keywords_bgp_huawei"}),
    r("Juniper BGP Missing MD5", {"product": "juniper", "service": "bgp"},
      {"keywords_bgp_juniper": {"|all": [":179", "missing MD5 digest"]}, "condition": "keywords_bgp_juniper"}),
    r("OneLogin User Assumed Another User", {"product": "onelogin", "service": "onelogin.events"},
      {"selection": {"event_type_id": 3}, "condition": "selection"}),
]


def titles(text):
    _fmt, rows, left = X.read(text)
    rows = rows or [{"text": line} for line in left]
    return sorted({h["title"] for row in rows for h in S.evaluate(X.sigma_event(row), RULES)})


class Routers(unittest.TestCase):
    def test_cisco_bgp_bad_md5(self):
        self.assertEqual(["Cisco BGP Authentication Failures"], titles(
            "Oct 20 10:05:00 rtr1 1234: %TCP-6-BADAUTH: IP-TCP-3-BADAUTH Invalid MD5 digest from "
            "203.0.113.9(179) to 198.51.100.1(11000) tableid - 0 src 203.0.113.9:179"))

    def test_cisco_ldp(self):
        self.assertEqual(["Cisco LDP Authentication Failures"], titles(
            "Oct 20 10:05:00 rtr1 %LDP-4-SOCKET_TCP_PACKET_MD5_AUTHEN_FAIL: LDP peer 10.0.0.2 MD5 failure"))

    def test_huawei_and_juniper(self):
        self.assertEqual(["Huawei BGP Authentication Failures"], titles(
            "Oct 20 2026 10:05:00 R1 %%01SOCKET/4/TCP_MD5_FAIL BGP_AUTH_FAILED peer 10.0.0.2:179"))
        self.assertEqual(["Juniper BGP Missing MD5"], titles(
            "Oct 20 10:05:00 mx1 /kernel: tcp_auth_ok: Packet from 10.0.0.2:179 missing MD5 digest"))

    def test_an_ordinary_router_line_is_quiet(self):
        self.assertEqual([], titles("Oct 20 10:05:00 rtr1 %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Up"))


class OneLogin(unittest.TestCase):
    EV = {"id": 999, "created_at": "2026-10-20T10:05:00Z", "account_id": 1, "user_id": 42,
          "event_type_id": 3, "notes": None, "ipaddr": "203.0.113.9", "actor_user_id": 7,
          "user_name": "jdoe", "actor_user_name": "admin"}

    def test_user_assumed_another_user(self):
        self.assertEqual(["OneLogin User Assumed Another User"], titles(json.dumps(self.EV)))
        self.assertEqual([], titles(json.dumps({**self.EV, "event_type_id": 5})))


class FieldlessAll(unittest.TestCase):
    """'|all': [...] (every keyword somewhere in the event) was read as a field named "":
    17 SigmaHQ rules could never fire, 4 of them critical (2026-10-20)."""
    PROXYLOGON = S.compile_rule({  # win_exchange_proxylogon_oabvirtualdir.yml
        "title": "ProxyLogon MSExchange OabVirtualDirectory", "id": "550d3350", "level": "critical",
        "logsource": {"product": "windows", "service": "msexchange-management"},
        "detection": {"keywords_cmdlet": {"|all": ["OabVirtualDirectory", " -ExternalUrl "]},
                      "keywords_params": ["eval(request", "http://f/<script", '"unsafe"};', "function Page_Load()"],
                      "condition": "keywords_cmdlet and keywords_params"}})
    EV = {"EventID": 1, "Channel": "MSExchange Management", "Provider": "MSExchange CmdletLogs",
          "Data": "Set-OabVirtualDirectory -Identity 'OAB (Default Web Site)' -ExternalUrl "
                  "'http://f/<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request)}</script>'"}

    def test_proxylogon_webshell_written_through_the_oab_url(self):
        self.assertEqual(1, len(S.evaluate(self.EV, [self.PROXYLOGON])))

    def test_every_keyword_is_needed(self):
        ev = {**self.EV, "Data": self.EV["Data"].replace(" -ExternalUrl ", " -InternalUrl ")}
        self.assertEqual([], S.evaluate(ev, [self.PROXYLOGON]))



class SplunkWindowsText(unittest.TestCase):
    """Splunk's classic Windows event text (a timestamp line, then Key=Value lines) was
    read line by line, so an Exchange cmdlet never sat with its LogName. Splunk's own
    ProxyShell recording (T1059.001/exchange) gave 0 rows; read as records, 4 critical
    and 2 high SigmaHQ hits (2026-10-20). Rule body is SigmaHQ's."""
    EXPORT = S.compile_rule({  # win_exchange_proxyshell_mailbox_export.yml
        "title": "Mailbox Export to Exchange Webserver", "id": "516376b4", "level": "critical",
        "logsource": {"service": "msexchange-management", "product": "windows"},
        "detection": {"export_command": {"|all": ["New-MailboxExportRequest", " -Mailbox "]},
                      "export_params": ['-FilePath "\\\\', ".aspx"],
                      "role_assignment": {"|all": ["New-ManagementRoleAssignment", ' -Role "Mailbox Import Export"',
                                                   " -User "]},
                      "condition": "(export_command and export_params) or role_assignment"}})
    TEXT = """11/21/2022 08:08:51 PM
LogName=MSExchange Management
EventCode=1
EventType=4
ComputerName=win-dc-exch01.attackrange.local
SourceName=MSExchange CmdletLogs
Type=Information
RecordNumber=1893
Keywords=Classic
TaskCategory=General
OpCode=None
Message=Cmdlet suceeded. Cmdlet New-MailboxExportRequest, parameters -Name "dYbLTCleBT" -Mailbox "Administrator@attackrange.local" -IncludeFolders "#Drafts#" -ContentFilter "Subject -eq 'dYbLTCleBT'" -ExcludeDumpster "True" -FilePath "\\\\localhost\\c$\\inetpub\\wwwroot\\aspnet_client\\dYbLTCleBT.aspx".
11/21/2022 08:08:50 PM
LogName=MSExchange Management
EventCode=1
SourceName=MSExchange CmdletLogs
Message=Cmdlet suceeded. Cmdlet Get-Mailbox, parameters -Identity "Administrator"
 on two lines.
"""

    def test_records_not_lines(self):
        fmt, rows, left = X.read(self.TEXT)
        self.assertEqual(("wineventlog-text", 2, []), (fmt, len(rows), left))
        self.assertEqual("MSExchange Management", rows[0]["LogName"])
        self.assertTrue(rows[1]["Message"].endswith("on two lines."), "a Message runs on over lines")

    def test_proxyshell_mailbox_export(self):
        _fmt, rows, _left = X.read(self.TEXT)
        self.assertEqual(["Mailbox Export to Exchange Webserver"],
                         [h["title"] for h in S.evaluate(X.sigma_event(rows[0]), [self.EXPORT])])
        self.assertEqual([], S.evaluate(X.sigma_event(rows[1]), [self.EXPORT]))



class LowRulesLoad(unittest.TestCase):
    """SigmaHQ's low rules never ran: the loader took them from the bundled Splunk set only
    (2026-10-20). They load as context now, and never count toward a burst."""

    def test_a_low_rule_from_any_folder_loads(self):
        import tempfile
        import yaml
        d = tempfile.mkdtemp()
        for rid, title in (("11111111-0000-0000-0000-000000000001", "Some Low Rule"),
                           ("69aeb277-f15f-4d2d-b32a-55e883609563", "Windows Event Auditing Disabled")):
            with open(os.path.join(d, f"{rid}.yml"), "w") as f:
                yaml.safe_dump({"title": title, "id": rid, "level": "low",
                                "logsource": {"product": "windows", "service": "security"},
                                "detection": {"selection": {"EventID": 4719}, "condition": "selection"}}, f)
        S._CACHE["key"] = None
        got = {r["title"]: r for r in S.load(dirs=(d,))["rules"]}
        S._CACHE["key"] = None
        self.assertEqual(("low", False), (got["Some Low Rule"]["level"], got["Some Low Rule"]["burst"]),
                         "a SigmaHQ low rule is context: on the benign DC they made two bursts of admin work")
        self.assertFalse(got["Windows Event Auditing Disabled"]["burst"])


if __name__ == "__main__":
    unittest.main()
