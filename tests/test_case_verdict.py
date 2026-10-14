"""The report says whether the case IS an intrusion, deterministically.

2026-10-14: a clean Server 2022 domain controller and a clean Windows 10 client were
reported "Risk: HIGH" as uncontained intrusions. By finding counts they look like real
one-step attacks (a lone DCSync is one high finding); what the detections ARE separates
them. render.case_verdict decides; the AI report's Risk is held to it in code and its
Executive Summary opens with it; the offline report follows it too.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim, render, schema  # noqa: E402

TS = "2026-01-01T10:00:00Z"


def graph(*specs):
    """specs: (title, severity, mitre[, previous_name])"""
    g = schema.FusionGraph(case_id="t")
    g.upsert(schema.Entity(id="asset:h1", type="asset", label="H1"))
    for i, spec in enumerate(specs):
        title, sv, mitre = spec[:3]
        e = schema.Entity(id=f"ev:{i}", type="event", label=title, severity=sv, first_seen=TS,
                          attrs={"title": title, "_assets": ["asset:h1"]},
                          flags=["sigma"] + (["previous_name"] if len(spec) > 3 and spec[3] else []))
        g.upsert(e)
        g.findings.append(schema.Finding(id=f"f{i}", title=f"SIGMA: {title} on H1", severity=sv,
                                         confidence="medium", summary=title, ts=TS, mitre=list(mitre),
                                         entity_ids=[e.id], asset_ids=["asset:h1"]))
    return g


def verdict(*specs):
    g = graph(*specs)
    return render.case_verdict(g, g.findings)


class Levels(unittest.TestCase):
    def test_os_housekeeping_with_no_technique_is_no_attack_evidence(self):
        v = verdict(("Unusual File Deletion by Dns.exe", "high", []),
                    ("Potential PrintNightmare Exploitation Attempt", "high", []))
        self.assertEqual(("none", "low"), (v["level"], v["ceiling"]))

    def test_an_admin_change_is_suspicious_not_an_intrusion(self):
        v = verdict(("User Added To Local Admin Grp", "high", ["T1098"]),
                    ("Security Eventlog Cleared", "high", ["T1070.001"]))
        self.assertEqual(("suspicious", "medium"), (v["level"], v["ceiling"]))

    def test_one_credential_dumping_detection_is_enough(self):
        self.assertEqual("corroborated", verdict(("Mimikatz Use", "high", ["T1003.001"]))["level"])

    def test_an_offensive_tool_rule_is_enough(self):
        self.assertEqual("corroborated",
                         verdict(("HackTool - Empire PowerShell Launch Parameters", "high", ["T1059.001"]))["level"])

    def test_a_critical_finding_is_enough(self):
        self.assertEqual("corroborated", verdict(("Some Service Installation", "critical", []))["level"])

    def test_breadth_of_techniques_is_enough(self):
        v = verdict(("A", "high", ["T1059"]), ("B", "high", ["T1547"]), ("C", "high", ["T1027"]),
                    ("D", "high", ["T1082"]))
        self.assertEqual("corroborated", v["level"])

    def test_a_high_finding_spanning_hosts_is_enough(self):
        g = graph(("Shared suspicious binary seen on 3 hosts", "high", []))
        g.findings[0].kind = "cross_host"
        self.assertEqual("corroborated", render.case_verdict(g, g.findings)["level"])

    def test_activity_under_an_earlier_host_name_does_not_count(self):
        v = verdict(("Mimikatz Use", "high", ["T1003.001"], True))
        self.assertEqual("none", v["level"])


class Enforced(unittest.TestCase):
    def test_the_ai_report_risk_is_held_and_the_assessment_opens_the_summary(self):
        g = graph(("User Added To Local Admin Grp", "high", ["T1098"]))
        text = "## Executive Summary\nAn intrusion.\n\n**Risk: HIGH** — uncontained.\n"
        out = llm_sim._apply_verdict(text, g, None, "informational")
        self.assertIn("**Risk: MEDIUM _(the model said HIGH; held by the case assessment (suspicious", out)
        self.assertTrue(out.split("\n")[2].startswith("**Assessment:** suspicious activity"), out)

    def test_one_cap_one_note(self):
        """The strongest-finding cap and the verdict cap used to stack two notes."""
        g = graph(("User Added To Local Admin Grp", "high", ["T1098"]))
        out = llm_sim._apply_verdict("## Executive Summary\nx\n**Risk: CRITICAL** — y\n", g, None, "informational")
        self.assertEqual(1, out.count("_(the model said"), out)
        self.assertIn("**Risk: MEDIUM _(the model said CRITICAL; held by the case assessment", out)

    def test_a_corroborated_case_keeps_its_risk(self):
        g = graph(("Mimikatz Use", "high", ["T1003.001"]))
        out = llm_sim._apply_verdict("## Executive Summary\nx\n**Risk: HIGH** — y\n", g, None, "informational")
        self.assertIn("**Risk: HIGH** — y", out)
        self.assertIn("**Assessment:** corroborated attacker activity", out)

    def test_the_offline_report_does_not_call_a_suspicious_case_an_intrusion(self):
        g = graph(("User Added To Local Admin Grp", "high", ["T1098"]),
                  ("Security Eventlog Cleared", "high", ["T1070.001"]))
        md = render.narrative_md(g)
        self.assertIn("**Assessment:** suspicious activity", md)
        self.assertNotIn("hands-on-keyboard intrusion", md)
        self.assertNotIn("immediate containment", md)
        self.assertIn("**moderate**", md)


if __name__ == "__main__":
    unittest.main()
