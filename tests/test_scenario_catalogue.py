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

    def test_the_validator_runs_after_checkout(self):
        """It reads scenarios.py, so the repo has to be on disk first.

        As the job's first step -- where it originally sat -- `import
        scenarios` raises ModuleNotFoundError, the command substitution fails
        under `set -euo pipefail`, and EVERY scenario in the matrix dies at
        step one. A validator that rejects all valid input is worse than the
        hand-kept list it replaced."""
        wf = open(WORKFLOW, encoding="utf-8").read()
        job = wf.split("Validate the inputs")[0]
        tail = job.rsplit("steps:", 1)[-1]
        self.assertIn("actions/checkout", tail,
                      "the input validator imports the scenario catalogue but "
                      "runs before actions/checkout, so qa/ does not exist yet")

    def test_the_workflow_validator_accepts_every_module_set(self):
        """The guard that was missing.

        A previous version of this file checked the catalogue's module sets
        against MODULE_SETS -- the catalogue against itself, which cannot fail.
        Meanwhile the workflow's own input validator still hard-coded
        `all|lean` from an earlier design, so it refused `shipped` and
        `backend-only` and killed three scenarios before they installed
        anything. The validator must read the catalogue, not a hand-kept list.
        """
        src = open(WORKFLOW, encoding="utf-8").read()
        self.assertIn("import scenarios;print", src,
                      "the module_set validator must derive its allowed values "
                      "from qa/scenarios.py rather than hard-coding them")
        self.assertNotRegex(
            src, r'case "\$MODULE_SET" in [a-z|-]+\)',
            "the workflow still hard-codes the module_set list in a case "
            "statement; it will drift from the catalogue again")

    def test_the_harness_runs_from_the_workspace_not_the_appliance(self):
        """Old appliances have no qa/ directory.

        Under the two-tree model the appliance is an OLD release's tree.
        intact-20260615 carries no harness at all, so running the harness from
        there dies with ENOENT before a single phase executes -- and the step
        has continue-on-error, so it reports success while producing nothing.
        """
        src = open(WORKFLOW, encoding="utf-8").read()
        # To the next step, not to the first mention of run_qa.py -- the
        # explanatory comment names it too, and cutting there truncated the
        # block before the line this test exists to read.
        block = src[src.index("Run the QA harness"):]
        nxt = re.search(r"\n      - (name|uses):", block)
        block = block[:nxt.start()] if nxt else block
        self.assertIn('cd "${GITHUB_WORKSPACE}"', block,
                      "the harness must run from the workspace; the appliance "
                      "may be an old release with no qa/ directory")
        self.assertNotIn('cd "${APPLIANCE}"', block,
                         "the harness is being run from the appliance tree")

    def test_the_adopt_scenarios_install_from_a_package(self):
        """Package mode is what puts this ref's backend on the box.

        A backend-only install disables timesketch, timesketch ships its own
        nginx, and app.py's disabled-module prune reclaims the bare `nginx`
        repo -- which is where the PLATFORM's reverse proxy lives too. It is
        deleted between the backend starting and nginx being deployed, and the
        install dies on "No such image".

        The fix is in this tree, but the prune runs inside the backend
        CONTAINER, and on an online install that container is the release's
        image, which does not carry it. Only the package path lets the harness
        substitute this ref's build. Flipping either scenario back to online
        would bring the failure back with no hint as to why."""
        for name in ("ui-online-adopt", "ui-import-adopt"):
            row = next(r for r in _catalogue().SCENARIOS if r["name"] == name)
            self.assertEqual(
                row["install_mode"], "package",
                f"{name} must install from a package; an online install loads "
                f"the release's backend, which lacks the prune fix")

    def test_the_workflow_strips_the_package_backend(self):
        """The other half of the same coupling: package mode only helps if the
        release's own backend image is actually kept out of the way."""
        src = open(WORKFLOW, encoding="utf-8").read()
        self.assertIn("images/intact-backend-*.tar", src,
                      "nothing removes the package's backend image, so the "
                      "corrected pin still resolves to the release's build")
        self.assertIn('docker tag "intact-backend:${BACKEND_TAG}"', src,
                      "this ref's build is never given the tag the corrected "
                      "pin will look for")

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
        raw = default.group(1).strip()
        names = {n.strip() for n in raw.split(",") if n.strip()}
        # 'all' is not a subset -- it is the keyword the resolver expands to
        # every scenario. Treating it as one made this guard demand a TEMPORARY
        # marker on a default that hides nothing.
        narrowed = raw not in ("", "all") and \
            names != {s["name"] for s in self.mod.SCENARIOS}
        if narrowed:
            self.assertRegex(
                src, r"TEMPORARY \(\d{4}-\d{2}-\d{2}\)",
                "the scenario default is a subset but carries no TEMPORARY "
                "marker saying so")


if __name__ == "__main__":
    unittest.main(verbosity=2)
