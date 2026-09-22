"""Saving Agentic settings saves them. It does not start work on a case.

The operator: "When configuring in settings -> agentic -> save agentic settings.
Cancel the feature that trigger new report. it only need to save it."

Two things made a save do more than save:
  * the save reloaded the Case Analysis frame, and
  * that frame regenerated a report BECAUSE the AI settings had changed —
    shouldAutoRegen's trigger was literally `report_config_id !== ls.config_id`.
So typing an API key could start a full model run (minutes, real tokens) on every
case whose report was a template. The trigger was the whole feature, so the
feature is gone; Regenerate report is the way a report is written.
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class SavingSettingsStartsNothing(unittest.TestCase):

    def setUp(self):
        self.settings = _read("modules/nginx/html/js/stores/settings.js")
        self.page = _read("modules/nginx/html/cases.html")

    def test_the_save_does_not_reload_case_analysis(self):
        save = self.settings[self.settings.index("async saveAgentic()"):
                             self.settings.index("// Refresh the selected provider's model catalog")]
        self.assertIn("/api/config", save, "it must still save")
        self.assertNotIn("_refreshCaseAnalysis()", save,
                         "reloading Case Analysis is what kicked a report generation")

    def test_the_settings_change_trigger_is_gone(self):
        for gone in ("shouldAutoRegen", "maybeAutoRegen", "_autoRegenOnce", "_autoRegenTried"):
            self.assertNotIn(gone, self.page, f"{gone} regenerated on a settings change")

    def test_the_per_case_tick_for_it_is_gone_too(self):
        self.assertNotIn("cf-autoregen", self.page)
        self.assertNotIn("auto_regen_report", self.page)

    def test_the_backend_no_longer_stores_the_setting(self):
        for rel in ("modules/backend/services/fusion/store.py",
                    "modules/backend/routes/case_routes.py"):
            self.assertNotIn("auto_regen_report", _read(rel), rel)

    def test_regenerating_by_hand_still_exists(self):
        """Non-vacuous: the deliberate path must be untouched."""
        self.assertIn("function regenReport(id)", self.page)
        self.assertIn("Regenerate report", self.page)

    def test_the_model_catalog_refresh_survives(self):
        """That part of the save is about the model dropdown, not about reports."""
        save = self.settings[self.settings.index("async saveAgentic()"):
                             self.settings.index("// Refresh the selected provider's model catalog")]
        self.assertIn("refresh-openrouter-models", save)


if __name__ == "__main__":
    unittest.main(verbosity=2)
