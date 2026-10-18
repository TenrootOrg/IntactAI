"""Hayabusa's severity floor reaches Velociraptor in a form it understands.

Windows.Sigma.Base looks RuleLevel up in its own table ("Critical, High, and
Medium" ...). We sent 'medium', which has no entry and matched EVERY level; hunts
sent nothing at all. A 69-client hunt then returned up to 10 M rows per machine
(95% low/informational) and took the backend and Velociraptor down. The default
is now medium and above, for agentic collections and every hunt builder alike.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.agentic.collectors._base import build_artifact_spec  # noqa: E402

HB = "Windows.Hayabusa.Rules"
CHOICES = ("Critical", "Critical and High", "Critical, High, and Medium",
           "Critical, High, Medium, and Low", "All")   # Windows.Sigma.Base's table


class RuleLevel(unittest.TestCase):
    def test_default_is_medium_and_above(self):
        self.assertIn("RuleLevel='Critical, High, and Medium'", build_artifact_spec([HB]))

    def test_every_severity_maps_to_a_real_choice(self):
        for sev in ("critical", "high", "medium", "low", "informational"):
            spec = build_artifact_spec([HB], {"min_severity": sev})
            self.assertTrue(any(f"RuleLevel='{c}'" in spec for c in CHOICES), (sev, spec))

    def test_a_run_asking_for_low_gets_low(self):
        self.assertIn("RuleLevel='Critical, High, Medium, and Low'",
                      build_artifact_spec([HB], {"min_severity": "low"}))

    def test_an_override_wins(self):
        spec = build_artifact_spec([HB], {"artifact_params": {HB: {"RuleLevel": "All"}}})
        self.assertIn("RuleLevel='All'", spec)

    def test_an_override_name_cannot_inject_vql(self):
        spec = build_artifact_spec([HB], {"artifact_params": {HB: {"x='1') , evil=(": "y"}}})
        self.assertNotIn("evil", spec)

    def test_other_artifacts_stay_bare(self):
        self.assertEqual("`Windows.Forensics.SAM`=dict()", build_artifact_spec(["Windows.Forensics.SAM"]))


class EveryHuntBuilderUsesIt(unittest.TestCase):
    def test_the_three_hunt_builders(self):
        routes = open(os.path.join(ROOT, "modules/backend/routes/velociraptor_routes.py")).read()
        service = open(os.path.join(ROOT, "modules/backend/services/velociraptor_service.py")).read()
        self.assertEqual(2, routes.count("spec_parts = build_artifact_spec("))
        self.assertNotIn('=dict()" for a in artifacts', routes)
        self.assertIn("spec=dict({_hunt_spec(artifact_name)})", service)


if __name__ == "__main__":
    unittest.main()
