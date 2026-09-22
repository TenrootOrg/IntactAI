"""Evidence lines in the report read as one consistent list of fields.

QA TASK-12671: one line mixed three styles and repeated a value —
"user=Administrator · Log: System ¦ User: Administrator" — because the mapper's
own fields used "key=value" while the collector's raw Details string (" ¦ "
delimited "Key: value") was pasted in verbatim.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402


def _graph(attrs):
    g = schema.FusionGraph(case_id="c")
    g.upsert(schema.Entity(id="asset:a", type="asset", label="HOSTA"))
    g.upsert(schema.Entity(id="ev:1", type="event", label="log cleared",
                           attrs=dict(attrs, _assets=["asset:a"])))
    f = schema.Finding(id="f1", title="SIGMA: Important Log File Cleared", severity="high",
                       confidence="high", summary="", entity_ids=["ev:1"], asset_ids=["asset:a"],
                       ts="2025-12-05T03:26:42Z")
    g.findings = [f]
    return g, f


class OneReadingOrder(unittest.TestCase):
    """Measured on a real case: only Hayabusa emits fields at all (3% of events),
    and WHICH fields vary per rule — proc on 73% of them, user on 42%, source IP on
    33%, service on 20%. So the set cannot be fixed, but the ORDER can: who, then
    what ran, then where, then hashes. They used to arrive in the collector's order,
    so two lines from the same detection listed the same facts differently."""

    def _line(self, attrs):
        g, f = _graph(attrs)
        return render._finding_evidence(g, f)[0]

    def test_the_fields_read_in_one_order_whatever_the_rule_emitted(self):
        line = self._line({"details": "Tgtip: 10.0.0.9 ¦ Proc: powershell.exe ¦ "
                                      "Sha256: abc123 ¦ User: ADATUMLAB\\srv"})
        for earlier, later in (("User:", "Process:"), ("Process:", "Target IP:"),
                               ("Target IP:", "SHA256:")):
            self.assertLess(line.index(earlier), line.index(later),
                            f"{earlier} must come before {later} — {line}")

    def test_the_cryptic_keys_are_spelled_out(self):
        line = self._line({"details": "Lid: 0x3e7 ¦ Pguid: {1-2} ¦ Tgtsid: S-1-5-18 ¦ "
                                      "Srcport: 4444 ¦ Tgtmachineid: DC01"})
        for word in ("Logon ID:", "Process GUID:", "Target SID:", "Source port:",
                     "Target machine ID:"):
            self.assertIn(word, line)
        for raw in ("Lid:", "Pguid:", "Tgtsid:", "Srcport:", "Tgtmachineid:"):
            self.assertNotIn(raw, line, "the capitalised raw key is not a title")

    def test_an_unknown_key_still_appears_at_the_end(self):
        line = self._line({"details": "Somethingnew: 42 ¦ User: bob"})
        self.assertIn("Somethingnew: 42", line, "never drop a field we have no name for")
        self.assertLess(line.index("User:"), line.index("Somethingnew:"))


class WhatWasDetectedIsNotOptional(unittest.TestCase):
    """A Defender alert read "User: NT AUTHORITY\\SYSTEM · Process: WmiPrvSE.exe"
    and nothing else: the threat name and the file it found were dropped because
    the event happened to name a process. Nobody can tell from that line why a
    Windows service process is a severe alert."""

    def _line(self, attrs):
        g, f = _graph(attrs)
        return render._finding_evidence(g, f)[0]

    def test_the_threat_and_the_file_survive_a_known_process(self):
        line = self._line({
            "ev_proc": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "ev_user": r"NT AUTHORITY\SYSTEM",
            "details": (r"Threat: Trojan:Win32/Bearfoos.B!ml ¦ Severity: Severe ¦ "
                        r"Type: Trojan ¦ User: NT AUTHORITY\SYSTEM ¦ "
                        r"Path: file:_C:\Temp\ThreadPoolWaitPurple.exe ¦ "
                        r"Proc: C:\Windows\System32\wbem\WmiPrvSE.exe")})
        self.assertIn("Threat: Trojan:Win32/Bearfoos.B!ml", line)
        self.assertIn(r"Path: C:\Temp\ThreadPoolWaitPurple.exe", line)
        self.assertEqual(1, line.count("WmiPrvSE.exe"), "and still no repeats")

    def test_defenders_own_resource_syntax_is_not_shown_to_the_analyst(self):
        self.assertEqual(r"C:\Temp\x.exe", render._clean_resource(r"file:_C:\Temp\x.exe"))
        self.assertEqual(
            r"C:\Users\srv\Desktop\mimikatz.exe",
            render._clean_resource(r"behavior:_process: C:\Users\srv\Desktop\mimikatz.exe, "
                                   r"pid:9924:68940583738923; process:_pid:9924,ProcessStart:1340292790"))

    def test_an_ordinary_path_is_left_exactly_as_it_is(self):
        for p in (r"C:\Windows\System32\svchost.exe",
                  r"%SystemRoot%\system32\svchost.exe -k print"):
            self.assertEqual(p, render._clean_resource(p))

    def test_a_line_with_no_process_still_carries_everything(self):
        line = self._line({"details": "Threat: X ¦ Severity: Severe ¦ Type: Trojan"})
        for w in ("Threat: X", "Rule severity: Severe", "Type: Trojan"):
            self.assertIn(w, line)


class OneConsistentShape(unittest.TestCase):
    def _line(self, attrs):
        g, f = _graph(attrs)
        return render._finding_evidence(g, f)[0]

    def test_the_collectors_fields_are_read_not_pasted(self):
        line = self._line({"ev_user": "Administrator",
                           "details": "Log: System ¦ User: Administrator ¦ Subject: Security"})
        self.assertNotIn("¦", line)
        self.assertNotIn("user=", line)
        self.assertEqual(line.count("Administrator"), 1, line)     # not twice
        self.assertIn("User: Administrator", line)
        self.assertIn("Log: System", line)

    def test_every_field_uses_label_colon_value(self):
        line = self._line({"ev_user": "srv", "ev_cmdline": "cmd.exe /c whoami",
                           "ev_tgtip": "10.0.0.5", "ev_sha256": "ab" * 32})
        for part in line.split(" · "):
            self.assertRegex(part, r"^[A-Z][A-Za-z0-9 ]+: ", part)
        self.assertIn("Command: cmd.exe /c whoami", line)
        self.assertIn("Target IP: 10.0.0.5", line)

    def test_prose_details_are_left_alone(self):
        line = self._line({"details": "The system log file was cleared."})
        self.assertEqual(line, "The system log file was cleared.")

    def test_abbreviations_are_spelled_out(self):
        line = self._line({"details": "Svc: PAExec ¦ Acct: LocalSystem ¦ Starttype: demand start"})
        self.assertIn("Service: PAExec", line)
        self.assertIn("Account: LocalSystem", line)
        self.assertIn("Start type: demand start", line)


if __name__ == "__main__":
    unittest.main()
