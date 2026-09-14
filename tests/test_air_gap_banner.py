"""The Analysis tab's template-report banner, rendered for every situation.

Reported from QA as confusing: its three lines told two different stories. This
drives the REAL reportAirGap/airGapBanner from cases.html with the REAL backend
messages from llm_sim.py, for every reason code plus the connected and
no-live-answer cases, and fails if any banner contradicts itself, repeats the
retry instruction, or leaks internal wording. See tests/air_gap_banner.js.
"""

import ast
import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LLM_SIM = os.path.join(ROOT, "modules/backend/services/fusion/llm_sim.py")
HARNESS = os.path.join(ROOT, "tests", "air_gap_banner.js")


def _messages():
    """Every (problem, fix) the backend can send, lifted from llm_sim.py without
    importing it (it pulls the whole backend)."""
    tree = ast.parse(open(LLM_SIM, encoding="utf-8").read())
    ns = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in (
                    "LLM_PINNED", "LLM_NO_MODEL", "LLM_MISSING_KEY",
                    "_LLM_CONFIG_REASONS", "_LLM_ERR_MESSAGES") for t in node.targets):
            exec(compile(ast.Module(body=[node], type_ignores=[]), LLM_SIM, "exec"), ns)
    out = dict(ns["_LLM_ERR_MESSAGES"])
    out.update(ns["_LLM_CONFIG_REASONS"])          # what llm_status actually sends
    return out


class AirGapBanner(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_every_situation_tells_one_consistent_story(self):
        r = subprocess.run(["node", HARNESS, ROOT, json.dumps(_messages())],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout[-4000:] + r.stderr[-4000:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
