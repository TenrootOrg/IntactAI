"""A rule that fires again later with other arguments is not reduced to "+1 occurrence".

APT29 Day 2 (2026-10-14 audit): a golden-ticket command (kerberos::golden ... /ptt) at
08:16 was detected at high, then folded into the 07:58 "Mimikatz Use" entity, whose
details were the 07:58 row's -- the report never saw it. The fold now keeps each burst
of a rule's hits (split relative to the rule's own rhythm) as a variant, and the report
evidence shows each one.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render  # noqa: E402
from services.fusion.mappers import agentic  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402


def row(ts, cmd, title="Tool Use", level="high"):
    return {"Timestamp": ts, "Computer": "WS1.corp.local", "Channel": "Security", "EID": 4688,
            "Level": level, "Title": title, "RecordID": 1,
            "Details": f"Cmdline: {cmd} ¦ Proc: C:\\t\\tool.exe ¦ User: CORP\\u1",
            "_hostname": "WS1", "_client_id": "C.1"}


def burst(start_min, cmd, n=5):
    return [row(f"2026-01-01T10:{start_min:02d}:{s:02d}Z", f"{cmd} {s}") for s in range(0, n * 2, 2)]


def entity(rows):
    ents, _ = map_agentic({"Windows.Hayabusa.Rules": rows}, run_id="r1", hostnames={"C.1": "WS1"})
    evs = [e for e in ents if e.type == "event" and "sigma" in (e.flags or [])]
    assert len(evs) == 1, [e.id for e in evs]
    return evs[0]


def finding_lines(*ents):
    from types import SimpleNamespace
    g = SimpleNamespace(entities={e.id: e for e in ents})
    return render._finding_evidence(g, SimpleNamespace(entity_ids=[e.id for e in ents]))


class FoldKeepsDistinctActivity(unittest.TestCase):
    def test_a_later_burst_with_other_arguments_is_kept(self):
        e = entity(burst(0, "tool.exe dump-creds") + burst(18, "tool.exe forge-ticket"))
        v = e.attrs.get("variants") or []
        self.assertEqual(2, len(v))
        self.assertIn("forge-ticket", v[1]["text"])
        self.assertTrue(v[1]["ts"].startswith("2026-01-01T10:18"))

    def test_one_steady_burst_has_no_variants(self):
        """The split is relative to the rule's own rhythm: an even cadence is one burst."""
        rows = [row(f"2026-01-01T10:{m:02d}:00Z", f"tool.exe poll {m}") for m in range(0, 50, 5)]
        self.assertNotIn("variants", entity(rows).attrs)

    def test_the_report_evidence_shows_the_later_burst(self):
        e = entity(burst(0, "tool.exe dump-creds") + burst(18, "tool.exe forge-ticket"))
        lines = finding_lines(e)
        self.assertTrue(any(l.startswith("Also at 2026-01-01T10:18") and "forge-ticket" in l for l in lines), lines)

    def test_a_routine_medium_rule_gets_no_variant_lines(self):
        """A medium rule repeats for ordinary reasons; its repeats are not new activity."""
        e = entity([dict(r, Level="medium") for r in burst(0, "a.exe x") + burst(18, "a.exe y")])
        self.assertEqual("medium", e.severity)
        self.assertFalse([l for l in finding_lines(e) if l.startswith("Also at")])

    def test_variants_never_push_out_another_detections_line(self):
        """APT29 Day 1: a burst's six slots filled with one rule's repeats and lost its
        screen-capture and WebDAV lines. Every detection's own line comes first."""
        noisy = entity(burst(0, "noisy.exe a") + burst(18, "noisy.exe b") + burst(36, "noisy.exe c"))
        others = []
        for i in range(5):
            o = entity([row("2026-01-01T11:00:00Z", f"other{i}.exe run", title=f"Rule {i}")])
            others.append(o)
        lines = finding_lines(noisy, *others)
        for i in range(5):
            self.assertTrue(any(f"other{i}.exe" in l for l in lines), (i, lines))

    def test_many_bursts_keep_the_first_and_the_last(self):
        rows = []
        for i in range(12):
            rows += burst(i * 4, f"tool.exe step{i:02d}", n=2)
        v = entity(rows).attrs["variants"]
        self.assertEqual(agentic.VARIANT_CAP, len(v))
        self.assertIn("step00", v[0]["text"])
        self.assertIn("step11", v[-1]["text"])


if __name__ == "__main__":
    unittest.main()
