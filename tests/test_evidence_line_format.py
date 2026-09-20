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
