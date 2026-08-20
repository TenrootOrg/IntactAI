"""Three descriptions of the Linux triage must agree.

The same artefact list is written down in three places, and they had silently
drifted apart:

  1. `agentic_linux_triage` in modules/backend/config/default_blueprints.yaml
     -- what a live collection gathers
  2. `LINUX_DEFAULT_ARTIFACTS` in services/offline_collector/constants.py
     -- what an offline collector gathers, and the fallback the OS filter
     substitutes when a blueprint has nothing OS-native
  3. `SUPPORTED_ARTIFACTS` in services/fusion/mappers/agentic.py
     -- what the case is willing to look at

Measured before the fix: of 17 artefacts collected, fusion accepted 8. Nine were
collected off the endpoint, transferred and stored, then dropped before reaching
the case -- including the kernel-module list, which is the rootkit check. In the
other direction seven artefacts had scoring branches in the mapper (LD_PRELOAD
persistence 70, memfd execution 80, uid-0 non-root account 60) that nothing ever
collected, so the highest-signal Linux detections the product can make were dead
code. The mapper's own comment still names a blueprint id that does not exist,
which is roughly when the two stopped agreeing.

Neither direction fails anything at runtime. A collection succeeds, a fusion
succeeds, and the result is quietly poorer than it should be -- which is why it
survived long enough to need a test.

Deliberately dependency-free: tests/run_tests.sh runs on a dev box, in CI and on
a live appliance, so this parses the flat YAML list by hand rather than
importing PyYAML.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLUEPRINTS = os.path.join(ROOT, "modules/backend/config/default_blueprints.yaml")
CONSTANTS = os.path.join(ROOT, "modules/backend/services/offline_collector/constants.py")
MAPPER = os.path.join(ROOT, "modules/backend/services/fusion/mappers/agentic.py")


def _blueprint_artifacts(blueprint_id):
    """The `artifacts:` list of one blueprint, by hand.

    The file is a flat list of `- Artifact.Name` under a fixed indent, so a
    scanner is enough and keeps this suite importable everywhere.
    """
    out, in_bp, in_list = [], False, False
    with open(BLUEPRINTS, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith("- id:"):
                in_bp = stripped.endswith(blueprint_id)
                in_list = False
                continue
            if not in_bp:
                continue
            if stripped == "artifacts:":
                in_list = True
                continue
            if in_list:
                if stripped.startswith("- "):
                    out.append(stripped[2:].strip())
                elif stripped and not stripped.startswith("#"):
                    break          # left the list
    return out


def _python_list(path, name):
    """A module-level list literal, read via the AST rather than imported."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return [e.value for e in node.value.elts
                    if isinstance(e, ast.Constant)]
    return []


def _supported_artifacts():
    src = open(MAPPER, encoding="utf-8").read()
    m = re.search(r"SUPPORTED_ARTIFACTS\s*=\s*frozenset\(\s*(\{|\[)(.*?)(\}|\])\s*\)",
                  src, re.S)
    return set(re.findall(r'"([^"]+)"', m.group(2))) if m else set()


class TestLinuxTriageAlignment(unittest.TestCase):

    def setUp(self):
        self.blueprint = _blueprint_artifacts("agentic_linux_triage")
        self.constants = _python_list(CONSTANTS, "LINUX_DEFAULT_ARTIFACTS")
        self.supported = _supported_artifacts()
        # Guard against the guard being vacuous: a parser that silently returns
        # nothing would make every assertion below trivially true.
        self.assertTrue(self.blueprint, "could not parse the blueprint artefacts")
        self.assertTrue(self.constants, "could not parse LINUX_DEFAULT_ARTIFACTS")
        self.assertTrue(self.supported, "could not parse SUPPORTED_ARTIFACTS")

    def test_the_live_and_offline_lists_are_the_same_triage(self):
        """One describes a live collection, the other an offline collector.

        They are meant to be the same triage; if they differ, an operator gets
        different evidence depending on which route they used, with nothing
        saying so."""
        self.assertEqual(
            sorted(self.blueprint), sorted(self.constants),
            "agentic_linux_triage and LINUX_DEFAULT_ARTIFACTS have drifted")

    def test_every_mapped_linux_artifact_is_actually_collected(self):
        """A mapper with no collector is dead detection logic.

        This is the direction that hurts: the mapper scores LD_PRELOAD
        persistence and memfd execution among the highest of any Linux signal,
        and nothing was gathering the evidence."""
        collected = {a.lower() for a in self.blueprint}
        linux_mapped = {s for s in self.supported if s.startswith("linux.")}
        orphaned = sorted(linux_mapped - collected)
        self.assertFalse(
            orphaned,
            "fusion maps these but no Linux blueprint collects them, so the "
            "scoring branches can never fire: " + ", ".join(orphaned))


if __name__ == "__main__":
    unittest.main(verbosity=2)
