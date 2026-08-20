"""The scenario catalogue is one list, and both sides must actually use it.

qa/scenarios.py is now the single source of truth: the workflow's resolve job
imports it, and qa/phases/upgrade.py asks it which route a scenario uses. That
removes the drift class rather than guarding it — two copies of anything drift,
and when the fusion allowlist and the Linux blueprint drifted exactly this way,
nine artefacts were collected and silently discarded for weeks.

What is still worth pinning: that neither side has quietly grown its own copy
again, that every route named has an implementation, and that the push fallback
matches the dispatch default — because a workflow_dispatch `default:` does not
apply to a push, and when those two disagreed a run tested one scenario while
the file advertised three.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github/workflows/e2e.yml")
PHASE = os.path.join(ROOT, "qa/phases/upgrade.py")


def _catalogue():
    """The rows the workflow can dispatch — straight from the shared module."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "qa_scenarios", os.path.join(ROOT, "qa/scenarios.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _phase_src():
    return open(PHASE, encoding="utf-8").read()


class TestScenarioCatalogue(unittest.TestCase):

    def setUp(self):
        self.mod = _catalogue()
        self.assertTrue(self.mod.SCENARIOS, "the catalogue is empty")

    def test_the_workflow_imports_the_shared_catalogue(self):
        """Not its own copy. A second list is how the last drift happened."""
        src = open(WORKFLOW, encoding="utf-8").read()
        self.assertIn("import scenarios as S", src,
                      "the workflow must import qa/scenarios.py rather than "
                      "carrying its own scenario list")
        self.assertNotIn('CATALOGUE = [', src,
                         "the workflow has grown its own catalogue again")

    def test_the_harness_asks_the_catalogue_for_routes(self):
        src = _phase_src()
        self.assertIn("scenarios.route_for(scenario)", src,
                      "the harness must ask the shared catalogue, not keep a "
                      "second route map")

    def test_every_route_named_is_implemented(self):
        unknown = sorted({s.get("route") for s in self.mod.SCENARIOS if s.get("route")}
                         - set(self.mod.ROUTES))
        self.assertFalse(unknown,
                         "route(s) with no description/implementation: "
                         + ", ".join(unknown))

    def test_every_module_set_is_one_the_workflow_can_apply(self):
        bad = sorted({s["modules"] for s in self.mod.SCENARIOS}
                     - set(self.mod.MODULE_SETS))
        self.assertFalse(bad, "unhandled module set(s): " + ", ".join(bad))

    def test_every_role_used_is_resolvable(self):
        """A typo'd role would silently resolve to an empty tag, and the
        scenario would install the branch instead of the old box it names."""
        used = set()
        for spec in self.mod.SCENARIOS:
            for key in ("install_from", "hop_via", "downgrade_from"):
                if spec.get(key):
                    used.add(spec[key])
        unknown = sorted(used - set(self.mod.ROLES))
        self.assertFalse(unknown, "unknown version role(s): " + ", ".join(unknown))

    def test_resolve_fills_every_field_the_matrix_needs(self):
        rows = self.mod.resolve([s["name"] for s in self.mod.SCENARIOS],
                                previous_tag="intact-19700101")
        needed = {"scenario", "install_from", "install_mode", "modules",
                  "upgrade_route", "upgrade_extra", "hop_via", "downgrade_tag"}
        for row in rows:
            missing = needed - set(row)
            self.assertFalse(missing,
                             f"{row.get('scenario')} is missing {missing}")

    def test_the_push_fallback_matches_the_dispatch_default(self):
        """A workflow_dispatch `default:` does not apply to a push.

        The push trigger carries no inputs at all, so the `||` fallback decides.
        When the two disagreed, a push ran ONE scenario while the file said
        three -- and a matrix that quietly shrinks reads as a pass.
        """
        src = open(WORKFLOW, encoding="utf-8").read()
        default = re.search(r"scenarios:(?:.|\n)*?default:\s*'([^']*)'", src)
        fallback = re.search(
            r"WANTED:\s*\$\{\{\s*github\.event\.inputs\.scenarios\s*\|\|\s*'([^']*)'",
            src)
        self.assertTrue(default, "could not find the scenarios input default")
        self.assertTrue(fallback, "could not find the push fallback")
        self.assertEqual(default.group(1), fallback.group(1),
                         "the dispatch default and the push fallback disagree")

    def test_the_narrowed_default_is_marked_temporary(self):
        """A subset that loses its marker becomes a permanent gap nobody
        remembers choosing."""
        src = open(WORKFLOW, encoding="utf-8").read()
        default = re.search(r"scenarios:(?:.|\n)*?default:\s*'([^']*)'", src)
        names = {n.strip() for n in default.group(1).split(",") if n.strip()}
        if names != {s["name"] for s in self.mod.SCENARIOS}:
            self.assertRegex(
                src, r"TEMPORARY \(\d{4}-\d{2}-\d{2}\)",
                "the scenario default is a subset but carries no TEMPORARY "
                "marker saying so")


if __name__ == "__main__":
    unittest.main(verbosity=2)
