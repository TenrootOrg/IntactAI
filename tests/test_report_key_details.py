"""The report's evidence lines are not for critical findings only.

The Szechuan test report said the RDP logon from a public IP had no source IP:
the finding was MEDIUM, and only critical findings sent their evidence lines,
though this one read 'Source IP: 194.61.24.102'.
"""
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render  # noqa: E402


def _f(i, title, sev, ts):
    return types.SimpleNamespace(id=f"f{i}", title=title, severity=sev, ts=ts)


class KeyFindingDetails(unittest.TestCase):
    def setUp(self):
        self._fd = render.finding_detail
        render.finding_detail = lambda g, f, max_details=2: {
            "evidence_details": [{"line": f"{f.id} detail {n}"} for n in range(max_details)]}

        self._fe = render._finding_evidence
        render._finding_evidence = lambda g, f: [f"{f.id} evidence line"]

    def tearDown(self):
        render.finding_detail = self._fd
        render._finding_evidence = self._fe

    def test_exposure_first_then_high_then_medium_capped(self):
        fs = [_f(1, "User Added To Local Admin Grp", "high", "2020-09-17"),
              _f(2, "SIGMA: External Remote RDP Logon from Public IP", "medium", "2020-09-19"),
              _f(3, "Password Reset By Admin", "medium", "2020-09-17"),
              _f(4, "Meterpreter Getsystem Service", "critical", "2020-09-19"),
              _f(5, "Low thing", "low", "2020-09-19")]
        out = render.critical_details(None, fs, extra=2)
        titles = [o["finding"] for o in out]
        self.assertEqual("Meterpreter Getsystem Service", titles[0])
        self.assertEqual(2, len(out[0]["evidence_details"]))             # critical keeps 2 lines
        self.assertEqual(["SIGMA: External Remote RDP Logon from Public IP", "User Added To Local Admin Grp"],
                         titles[1:])                                       # exposure, then high; capped at 2
        self.assertEqual(1, len(out[1]["evidence_details"]))
        self.assertNotIn("Low thing", titles)

    def test_extra_zero_is_the_old_behaviour(self):
        fs = [_f(1, "x", "high", "t"), _f(2, "y", "critical", "t")]
        self.assertEqual(["y"], [o["finding"] for o in render.critical_details(None, fs, extra=0)])


    def test_a_logon_finding_without_file_details_uses_its_evidence_line(self):
        render.finding_detail = lambda g, f, max_details=2: {}           # no file/user/command details
        fs = [_f(2, "SIGMA: External Remote RDP Logon from Public IP", "medium", "t")]
        out = render.critical_details(None, fs)
        self.assertEqual([{"evidence": "f2 evidence line"}], out[0]["evidence_details"])


    def test_the_total_is_capped_critical_first(self):
        fs = [_f(i, f"crit {i}", "critical", "t") for i in range(50)] + [_f(99, "External RDP", "medium", "t")]
        out = render.critical_details(None, fs, max_chars=2000)
        self.assertTrue(out and all(o["finding"].startswith("crit") for o in out))
        self.assertLessEqual(sum(len(__import__("json").dumps(o)) for o in out), 2000)


if __name__ == "__main__":
    unittest.main()
