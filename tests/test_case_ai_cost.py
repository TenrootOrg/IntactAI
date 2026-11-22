"""Case Analysis: what a case's AI calls cost, and its AI-budget warning.

Drives the REAL _usd/_aiBudgetLine/_aiCostHtml from cases.html
(tests/case_ai_cost.js): the header warns from 80% of the budget and says plainly
when it is used up; the Configuration block shows the total, how much of it is
estimated, the budget and where it comes from, and the split by source and model.
"""
import os
import shutil
import subprocess
import unittest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "case_ai_cost.js")


class CaseAiCost(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_cost_block_and_budget_warning(self):
        r = subprocess.run(["node", HARNESS], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
        self.assertIn("ok", r.stdout)


if __name__ == "__main__":
    unittest.main()
