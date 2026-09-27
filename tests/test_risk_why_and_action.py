"""Risk tab: "Why" shows what drives the score; "next action" discriminates.

Found in the audit (jev_test):
  * Why was sorted by severity then TITLE — "Account '…' used across N hosts"
    led four hosts' Why for starting with "A" — and deduped by exact title, so
    one detection appeared twice ("(+1 related)" and "(+2 related)");
  * next_action / 🔺 were identical on all 9 hosts ("Deep-dive now"): the flag
    was high+ and no memory/Timesketch, true everywhere on a Velociraptor case.
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


def _f(fid, title, host, sev="high", day=1, kind="single"):
    return schema.Finding(id=fid, title=f"{title} on {host}", severity=sev, confidence="m", summary="",
                          asset_ids=[f"asset:{host}"], ts=f"2026-06-{day:02d}T10:00:00Z", kind=kind)


def _table(findings):
    g = schema.FusionGraph(case_id="c")
    for h in sorted({a for f in findings for a in f.asset_ids}):
        g.upsert(schema.Entity(id=h, type="asset", label=h.split(":")[1]))
    g.findings = findings
    return {r["host"]: r for r in render.risk_table(g)}


class Why(unittest.TestCase):
    def test_strongest_contribution_first_one_line_per_detection(self):
        rows = _table([_f("a", "Account 'bob' used across 2 hosts", "H", kind="cross_host"),
                       _f("m", "SIGMA: Mimikatz", "H", sev="critical"),
                       _f("d1", "SIGMA: Defender Alert (Severe) (+1 related)", "H", sev="high", day=1),
                       _f("d2", "SIGMA: Defender Alert (Severe) (+2 related)", "H", sev="high", day=3)])
        why = rows["H"]["reasons"]
        self.assertEqual(why[0], "SIGMA: Mimikatz")
        self.assertEqual(sum(1 for w in why if w.startswith("SIGMA: Defender Alert")), 1)
        self.assertIn("SIGMA: Defender Alert (Severe) (×2 episodes)", why)


class NextAction(unittest.TestCase):
    def test_only_the_critical_band_is_deep_dive_now(self):
        rows = _table([_f("c", "SIGMA: Rubeus", "DC", sev="critical"),
                       _f("h1", "SIGMA: Encoded PowerShell", "WS1"),
                       _f("h2", "SIGMA: Encoded PowerShell", "WS2")])
        self.assertTrue(rows["DC"]["next_action"].startswith("Deep-dive now"))
        self.assertTrue(rows["DC"]["escalate"])
        self.assertEqual({rows["WS1"]["next_action"], rows["WS2"]["next_action"]}, {"Triage next"})

    def test_without_criticals_the_top_three_are(self):
        rows = _table([_f(f"h{i}", f"SIGMA: rule {j}", f"H{i}") for i in range(5) for j in range(i + 1)])
        deep = sorted(h for h, r in rows.items() if r["next_action"].startswith("Deep-dive"))
        self.assertEqual(deep, ["H2", "H3", "H4"])


if __name__ == "__main__":
    unittest.main()
