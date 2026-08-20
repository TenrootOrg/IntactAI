"""The workflow's scenario list and the harness must describe the same thing.

Two files independently name the scenarios: the CATALOGUE inside
.github/workflows/e2e.yml decides which jobs run, and _route_for() in
qa/phases/upgrade.py decides which phases each one registers. Nothing at
runtime checks they agree.

If they drift, the failure is silent and expensive in exactly the way the
fusion/blueprint drift was: a scenario whose name the harness does not
recognise registers NO upgrade phases at all, so the job installs an appliance,
asserts nothing about any upgrade, and reports a clean pass. A green run that
tested nothing is worse than a red one.

Dependency-free by the usual rule — the suite runs on a dev box, in CI and on a
live appliance — so the catalogue is pulled out of the YAML by locating the
embedded program rather than by parsing the workflow.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github/workflows/e2e.yml")
PHASE = os.path.join(ROOT, "qa/phases/upgrade.py")


def _catalogue():
    """Every scenario row the workflow can dispatch."""
    src = open(WORKFLOW, encoding="utf-8").read()
    rows = []
    for m in re.finditer(r'\{"scenario":\s*"([^"]+)"(.*?)\}', src, re.S):
        name, body = m.group(1), m.group(2)
        route = re.search(r'"upgrade_route":\s*"([^"]*)"', body)
        modules = re.search(r'"modules":\s*"([^"]*)"', body)
        rows.append({
            "scenario": name,
            "upgrade_route": route.group(1) if route else "",
            "modules": modules.group(1) if modules else "",
        })
    return rows


def _harness_routes():
    """{scenario: route} from _route_for's return dict."""
    tree = ast.parse(open(PHASE, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_route_for":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    return {k.value: v.value
                            for k, v in zip(sub.keys, sub.values)
                            if isinstance(k, ast.Constant)
                            and isinstance(v, ast.Constant)}
    return {}


def _known_routes():
    src = open(PHASE, encoding="utf-8").read()
    m = re.search(r"UPGRADE_ROUTES\s*=\s*\{(.*?)\n\}", src, re.S)
    return set(re.findall(r'"([a-z_]+)":', m.group(1))) if m else set()


class TestScenarioCatalogue(unittest.TestCase):

    def setUp(self):
        self.catalogue = _catalogue()
        self.routes = _harness_routes()
        self.known = _known_routes()
        # A parser that silently returns nothing would make every assertion
        # below trivially true.
        self.assertTrue(self.catalogue, "no scenarios parsed from the workflow")
        self.assertTrue(self.routes, "_route_for did not parse")
        self.assertTrue(self.known, "UPGRADE_ROUTES did not parse")

    def test_every_upgrade_scenario_is_known_to_the_harness(self):
        """A scenario the harness does not recognise registers no upgrade
        phases, installs an appliance, asserts nothing, and passes."""
        missing = sorted(
            r["scenario"] for r in self.catalogue
            if r["upgrade_route"] and r["scenario"] not in self.routes)
        self.assertFalse(
            missing,
            "the workflow dispatches these but _route_for does not know them, "
            "so they would silently test nothing: " + ", ".join(missing))

    def test_the_two_files_agree_on_which_route_each_scenario_uses(self):
        wrong = []
        for row in self.catalogue:
            want = row["upgrade_route"]
            if not want:
                continue
            got = self.routes.get(row["scenario"])
            if got != want:
                wrong.append(f"{row['scenario']}: workflow={want} harness={got}")
        self.assertFalse(wrong, "; ".join(wrong))

    def test_install_only_scenarios_register_no_upgrade_route(self):
        """The inverse mistake: an install-only scenario that the harness
        thinks upgrades would try to upgrade to nothing."""
        wrong = [r["scenario"] for r in self.catalogue
                 if not r["upgrade_route"] and r["scenario"] in self.routes]
        self.assertFalse(
            wrong, "install-only scenario(s) mapped to an upgrade route: "
                   + ", ".join(wrong))

    def test_every_route_named_is_implemented(self):
        unknown = sorted(set(self.routes.values()) - self.known)
        self.assertFalse(unknown,
                         "route(s) with no implementation: " + ", ".join(unknown))

    def test_the_module_sets_are_ones_the_workflow_can_apply(self):
        """`all` and `backend-only` are transformed; `shipped` deliberately
        means "leave config.yaml as the release ships it". Anything else would
        be silently ignored and the box would not be what the scenario says."""
        allowed = {"all", "backend-only", "shipped", ""}
        bad = sorted({r["modules"] for r in self.catalogue} - allowed)
        self.assertFalse(bad, "unhandled module set(s): " + ", ".join(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
