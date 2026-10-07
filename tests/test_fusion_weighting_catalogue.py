"""The weighting catalogue proves itself: every rule's examples run here.

config/fusion_weighting.yaml decides what a detection is worth (2026-10-07: a
real admin case where 133 of 148 findings were HIGH -- installers, an agent's
updater, every visited site). Adding a pattern is a YAML rule with `examples:`;
this file runs every example and lints every rule, so a new rule needs no new
test -- and a rule without an example, a reason or a known check fails here.
It also pins the engine's guarantees: first match wins, a critical is never
lowered unless the rule says so, a broken rule is skipped, an unreadable
catalogue changes nothing, and a box's local rules come first and can switch
shipped ones off.
"""
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import yaml  # noqa: E402
from services.fusion import correlate, weighting  # noqa: E402,F401 -- correlate registers patterns
from services.fusion.schema import Entity, EvidenceRef  # noqa: E402
from services.fusion.severity import from_anomaly, LEVELS  # noqa: E402

DOC = yaml.safe_load(open(weighting.CATALOGUE, encoding="utf-8"))
CAT = weighting.load([weighting.CATALOGUE])


def entity(ex):
    anom = int(ex.get("anomaly", 40))
    return Entity(id="e1", type=ex.get("type", "event"), label="x", attrs=dict(ex.get("attrs") or {},
                  artifact=ex.get("artifact")), sources=["agentic"],
                  evidence=[EvidenceRef("agentic", "r1", f"{ex.get('artifact')}/row=0")],
                  anomaly=anom, severity=ex.get("severity") or from_anomaly(anom),
                  flags=list(ex.get("flags") or []))


class TheCatalogueIsSound(unittest.TestCase):
    def test_it_loads(self):
        self.assertIsNone(CAT["error"])
        self.assertTrue(CAT["entity_rules"])

    def test_every_rule_has_an_id_a_reason_and_examples(self):
        ids = [r.get("id") for r in DOC["entity_rules"] + DOC["pattern_rules"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule ids")
        for r in DOC["entity_rules"]:
            self.assertTrue(r.get("id") and r.get("reason"), r)
            self.assertTrue(r.get("examples"), f"{r['id']}: no examples")
        for r in DOC["pattern_rules"]:
            self.assertTrue(r.get("reason"), r)
            self.assertIn(r["pattern"], weighting._PATTERNS, f"{r['id']}: unknown pattern")

    def test_every_check_and_severity_exists(self):
        for r in DOC["entity_rules"]:
            w, t = r.get("when") or {}, r.get("then") or {}
            if "check" in w:
                self.assertIn(w["check"], weighting.CHECKS, r["id"])
            if "severity" in t:
                self.assertIn(t["severity"], LEVELS, r["id"])
            self.assertTrue("anomaly" in t or "severity" in t, f"{r['id']}: then sets nothing")


class EveryExampleHolds(unittest.TestCase):
    def test_examples(self):
        n = 0
        for r in DOC["entity_rules"]:
            for ex in r["examples"]:
                e = weighting.apply_entity(entity(ex), CAT)
                self.assertEqual(e.severity, ex["expect"], f"{r['id']}: {ex}")
                n += 1
        self.assertGreater(n, 10)


class TheEngine(unittest.TestCase):
    def rules(self, *rs):
        return {"entity_rules": list(rs), "pattern_rules": [], "error": None}

    def test_first_match_wins_and_the_change_is_stamped(self):
        e = weighting.apply_entity(entity({"type": "event", "attrs": {"category": "Archive"}}), self.rules(
            {"id": "a", "reason": "first", "when": {"attr_words": {"category": ["arch"]}}, "then": {"anomaly": 0}},
            {"id": "b", "reason": "second", "when": {"attr_words": {"category": ["arch"]}}, "then": {"anomaly": 50}}))
        self.assertEqual(e.severity, "informational")
        self.assertEqual(e.attrs["weighting"], {"rule": "a", "from": "high", "to": "informational", "reason": "first"})

    def test_a_critical_is_never_lowered_unless_the_rule_says_so(self):
        crit = {"anomaly": 120, "attrs": {"category": "x"}}
        rule = {"id": "a", "reason": "r", "when": {"attr_words": {"category": ["x"]}}, "then": {"anomaly": 0}}
        self.assertEqual(weighting.apply_entity(entity(crit), self.rules(rule)).severity, "critical")
        rule["allow_lower_critical"] = True
        self.assertEqual(weighting.apply_entity(entity(crit), self.rules(rule)).severity, "informational")

    def test_a_broken_rule_is_skipped_and_reported(self):
        errs = {}
        e = weighting.apply_entity(entity({"attrs": {"category": "x"}}), self.rules(
            {"id": "broken", "reason": "r", "when": {"check": "no_such_check"}, "then": {"anomaly": 0}}), errs)
        self.assertEqual(e.severity, "high")
        self.assertIn("broken", errs)

    def test_an_unreadable_catalogue_changes_nothing_and_says_so(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("entity_rules: [unclosed")
        try:
            cat = weighting.load([fh.name])
            self.assertTrue(cat["error"])
            self.assertEqual(weighting.apply_entity(entity({}), cat).severity, "high")
        finally:
            os.unlink(fh.name)

    def test_local_rules_come_first_and_can_disable_shipped_ones(self):
        with tempfile.TemporaryDirectory() as d:
            local, shipped = os.path.join(d, "local.yaml"), os.path.join(d, "shipped.yaml")
            yaml.safe_dump({"disable": ["shipped-off"], "entity_rules": [
                {"id": "site-backup-tool", "reason": "our backup agent", "when": {"attr_words": {"name": ["backupx"]}},
                 "then": {"anomaly": 0}}]}, open(local, "w"))
            yaml.safe_dump({"entity_rules": [
                {"id": "shipped-on", "reason": "r", "when": {"attr_words": {"name": ["backupx"]}}, "then": {"anomaly": 50}},
                {"id": "shipped-off", "reason": "r", "when": {"attr_words": {"name": ["zz"]}}, "then": {"anomaly": 0}}]},
                open(shipped, "w"))
            cat = weighting.load([local, shipped])
            self.assertEqual([r["id"] for r in cat["entity_rules"]], ["site-backup-tool", "shipped-on"])
            e = weighting.apply_entity(entity({"attrs": {"name": "backupx-agent.exe"}}), cat)
            self.assertEqual(e.attrs["weighting"]["rule"], "site-backup-tool")


if __name__ == "__main__":
    unittest.main()
