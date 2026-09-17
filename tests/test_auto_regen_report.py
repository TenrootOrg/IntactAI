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

    def test_it_waits_for_a_live_check(self):
        """QA TASK-12664: on an air-gapped box a saved key made the case payload say
        "available", so the page claimed "connected" and regenerated. It still runs
        as soon as the case is drawn, but only on a live check's answer."""
        page = _src("modules/nginx/html/cases.html")
        body = page.split("function showCase(")[1].split("\nfunction ")[0]
        self.assertIn("maybeAutoRegen();", body)
        self.assertIn("checked_live===true", page.split("function shouldAutoRegen(")[1].split("\n}")[0])

    def test_every_saved_report_is_stamped_with_its_settings(self):
        """The page compares the settings that WROTE the template with the
        settings now. Both save paths must stamp it, and the payload must carry it."""
        store = _src("modules/backend/services/fusion/store.py")
        regen = store.split("def regenerate_report(")[1].split("\ndef ")[0]
        self.assertIn('"report_config_id": report_cfg_id, "report_written_at": _now_iso()', regen)
        fuse = store.split("def _fuse_case_locked(")[1].split("\ndef ")[0]
        self.assertIn('"report_config_id": _report_cfg_id,', fuse)
        self.assertIn('"report_written_at": _report_written_at,', fuse)
        routes = _src("modules/backend/routes/case_routes.py")
        self.assertIn('"report_config_id": d.get("report_config_id")', routes)
        self.assertIn('"report_written_at": d.get("report_written_at")', routes)

    def test_the_case_payload_carries_the_last_live_answer(self):
        self.assertIn("llm_sim.llm_status_known()", _src("modules/backend/routes/case_routes.py"))

    def test_it_is_checked_after_every_live_model_check(self):
        """The trigger needs a PROBED answer, which only arrives after the
        reachability refresh -- so both places that refresh must call it."""
        page = _src("modules/nginx/html/cases.html")
        self.assertEqual(2, len(re.findall(r"refreshLlmReachability\(\)\.then\([^\n]*maybeAutoRegen\(\)", page)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
