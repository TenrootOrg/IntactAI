"""The Timeline phase tag is the ATT&CK tactic, from the technique first.

Found in the audit (jev_test): 200 of 281 rows fell back to "Execution /
Injection" — Defender Disabled (T1562), Eventlog Cleared (T1070) included — and
"c2" matched as a substring, so ProcessHacker rows were Command & Control because
their HASH contained "c2".
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


def _p(title, mitre=()):
    return render._phase(schema.Finding(id="x", title=title, severity="high", confidence="m",
                                        summary="", mitre=list(mitre)))


class Tactics(unittest.TestCase):
    def test_technique_first(self):
        self.assertEqual(_p("SIGMA: T1562.001-Win Defender Disabled on H"), "Defense Evasion")
        self.assertEqual(_p("SIGMA: Security Eventlog Cleared on H", ["T1070.001"]), "Defense Evasion")
        self.assertEqual(_p("SIGMA: HackTool - Rubeus Execution on H"), "Credential Access")
        self.assertEqual(_p("Account 'bob' used across 2 hosts"), "Lateral Movement")

    def test_c2_is_a_word_not_a_substring_of_a_hash(self):
        self.assertNotEqual(_p("Known tool on disk: ProcessHacker.exe (sha256 1c2abc99…) on H"),
                            "Command & Control")
        self.assertEqual(_p("Cobalt Strike: trick_ryuk.profile on H"), "Command & Control")

    def test_unknown_is_said_not_defaulted(self):
        self.assertEqual(_p("Web: Archive Utilities — www.7-zip.org on H"), "Unclassified")


if __name__ == "__main__":
    unittest.main()
