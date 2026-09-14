"""Auto-regenerate a template report when an AI model has since connected.

Asked for from QA: a report written while no model was usable should rewrite
itself with the model once one is connected -- but only for the case the
operator opens on the Analysis tab, never every case at once. tests/
auto_regen_report.js runs the real page functions against every rule; the
checks here pin the per-case off switch end to end (payload, save, page).
"""

import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class AutoRegenerateReport(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_trigger_rules(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "auto_regen_report.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_the_case_payload_carries_the_switch_default_on(self):
        self.assertIn('"auto_regen_report": bool(d.get("auto_regen_report", True))',
                      _src("modules/backend/routes/case_routes.py"))

    def test_saving_the_configuration_persists_the_switch(self):
        body = _src("modules/backend/services/fusion/store.py").split("def set_analysis_config")[1].split("\ndef ")[0]
        self.assertIn('patch["auto_regen_report"] = bool(cfg.get("auto_regen_report"))', body)

    def test_the_configuration_tab_shows_and_sends_the_switch(self):
        page = _src("modules/nginx/html/cases.html")
        self.assertIn('id="cf-autoregen"', page)
        self.assertRegex(page, r"auto_regen_report:\$\('#cf-autoregen'\)")

    def test_it_starts_as_soon_as_the_case_is_drawn(self):
        """Reported from QA: the banner said "connected" but regeneration only
        started ~10s later, after the live probe. It must also run the moment
        fresh case data is drawn."""
        page = _src("modules/nginx/html/cases.html")
        body = page.split("function showCase(")[1].split("\nfunction ")[0]
        self.assertIn("maybeAutoRegen();", body)
        self.assertNotIn("checked_live===true", page.split("function shouldAutoRegen(")[1].split("\n}")[0])

    def test_the_case_payload_carries_the_last_live_answer(self):
        self.assertIn("llm_sim.llm_status_known()", _src("modules/backend/routes/case_routes.py"))

    def test_it_is_checked_after_every_live_model_check(self):
        """The trigger needs a PROBED answer, which only arrives after the
        reachability refresh -- so both places that refresh must call it."""
        page = _src("modules/nginx/html/cases.html")
        self.assertEqual(2, len(re.findall(r"refreshLlmReachability\(\)\.then\([^\n]*maybeAutoRegen\(\)", page)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
