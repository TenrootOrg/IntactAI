"""Every phase is written into the report — with or without a model.

Asked 2026-09-27: "maybe in the case analysis each phase will be written in the
report itself". The AI report had a section per phase; the deterministic one —
the air-gapped default — was a single flat timeline while the Analysis tab
showed phase cards it never explained.
"""
import datetime as _d
import os
import re
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402


def _graph():
    """Four separate bursts, weeks apart, on two hosts — a broad case."""
    g = schema.FusionGraph(case_id="c")
    for h in ("WS1", "DC1"):
        g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h))
    fs = []
    for w in range(4):
        day = (_d.date(2026, 1, 1) + _d.timedelta(days=20 * w)).isoformat()
        h = "WS1" if w % 2 == 0 else "DC1"
        fs.append(schema.Finding(id=f"c{w}", title=f"SIGMA: Mimikatz Execution on {h}", severity="critical",
                                 confidence="m", summary="", asset_ids=[f"asset:{h}"], mitre=["T1003.001"],
                                 ts=f"{day}T10:00:00Z"))
        for k in range(3):
            fs.append(schema.Finding(id=f"h{w}{k}", title=f"SIGMA: Suspicious Service Path {k} on {h}",
                                     severity="high", confidence="m", summary="", asset_ids=[f"asset:{h}"],
                                     mitre=["T1543.003"], ts=f"{day}T10:0{k + 1}:00Z"))
    g.findings = fs
    return g


class DeterministicPhases(unittest.TestCase):
    def setUp(self):
        self.g = _graph()
        self.md = render.report(self.g, case_name="t", altitude_mode="macro",
                                validations=[{"finding_id": "c0", "status": "true_positive"},
                                             {"finding_id": "h00", "status": "false_positive"}])

    def test_each_phase_has_its_own_section(self):
        heads = re.findall(r"^### Phase (\d+) — (.+)$", self.md, re.M)
        self.assertGreaterEqual(len(heads), 2, heads)
        self.assertIn("## Phases at a glance", self.md)
        self.assertLess(self.md.index("## Phases at a glance"), self.md.index("### Phase 1 —"))
        # every phase names what it is, from the evidence
        self.assertTrue(all("Credential Access" in n or "Persistence" in n for _, n in heads), heads)

    def test_the_glance_table_names_each_phase_as_its_heading_does(self):
        for n, name in re.findall(r"^### Phase (\d+) — (.+)$", self.md, re.M):
            self.assertRegex(self.md, rf"\| {n} \| {re.escape(name)} \|")

    def test_a_phase_says_what_it_shows_and_what_you_decided(self):
        sec = self.md[self.md.index("### Phase 1 —"):]
        sec = sec[:sec.index("### Phase 2 —")] if "### Phase 2 —" in sec else sec
        self.assertIn("From the evidence — no AI narrative", sec)
        self.assertIn("**Rules matched", sec)
        self.assertIn("**Stages (ATT&CK):**", sec)
        self.assertIn("**Start here:**", sec)
        self.assertIn("**Timeline — this phase**", sec)
        # the analyst's verdicts, counted per phase
        self.assertIn("1 True Positive · 1 False Positive", sec)

    def test_counts_in_a_section_agree(self):
        for sec in self.md.split("### Phase ")[1:]:
            rows = int(re.search(r"distinct in (\d+) timeline rows", sec).group(1))
            tl = int(re.search(r"_(\d+) finding\(s\) in this phase", sec).group(1))
            self.assertEqual(rows, tl, sec[:300])

    def test_the_phases_are_not_repeated_in_a_case_wide_timeline(self):
        # the case timeline holds only what no phase covers — here, nothing
        self.assertNotIn("## Timeline of Events", self.md)
        self.assertEqual(self.md.count("SIGMA: Suspicious Service Path 1 `[T1543.003]` · WS1"), 2)  # 2 WS1 phases

    def test_the_brief_is_not_swallowed_into_the_last_bullet(self):
        self.assertRegex(self.md, r"critical\)\n\n_From the evidence")

    def test_a_focused_case_is_unchanged(self):
        md = render.report(self.g, case_name="t", altitude_mode="focused")
        self.assertNotIn("### Phase", md)


class People(unittest.TestCase):
    def test_a_person_marked_compromised_is_named_in_their_phase(self):
        g = _graph()
        g.upsert(schema.Entity(id="account:corp\\kobia", type="account", label="CORP\\kobia",
                               attrs={"_assets": ["asset:WS1"]}))
        g.relate(schema.Relationship("account:corp\\kobia", "c0", "executed"))
        g.findings[0].entity_ids = ["c0"]
        g.upsert(schema.Entity(id="c0", type="event", label="mimikatz"))
        g.identity_verdicts = [{"accounts": ["account:corp\\kobia"], "verdict": "compromised"}]
        md = render.report(g, case_name="t", altitude_mode="macro")
        self.assertIn("**kobia** (marked compromised)", md)


if __name__ == "__main__":
    unittest.main()
