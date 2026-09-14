"""The case log must say what the report generation actually did.

Reported live: a Codex subscription with the Model field blank (the plan's
default) logged "Report · LLM not configured — no model set — using the
deterministic narrator", and the same run then narrated with the model and
saved an AI report. Separately, a failed model call was logged "LLM responded":
the check looked for a "_Live LLM unavailable" note generate_report no longer
writes, so it never matched.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("/app", os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)
import _optional_deps  # noqa: F401,E402

from services.fusion import store  # noqa: E402

STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
NARRATED = "# Report\n\nbody\n\n---\n_Narrative by live LLM; fact tables deterministic._\n"
TEMPLATE = ("# Report\n\nbody\n\n---\n_Deterministic report — The AI provider rejected the "
            "API key. Enter a valid key in Settings ▸ Agentic, then try again._\n")


class TheOutcomeIsReadFromTheReport(unittest.TestCase):

    def test_a_narrated_report_is_a_success(self):
        self.assertEqual((True, ""), store._narration_outcome(NARRATED))

    def test_a_failed_call_is_a_failure_with_its_reason(self):
        ok, why = store._narration_outcome(TEMPLATE)
        self.assertFalse(ok, "a template report must never be logged as 'LLM responded'")
        self.assertTrue(why.startswith("The AI provider rejected the API key."), why)

    def test_anything_else_is_a_failure_not_a_success(self):
        for md in ("", None, "# Report\n\nno closing note at all\n"):
            self.assertFalse(store._narration_outcome(md)[0], repr(md))

    def test_a_blank_model_is_named_as_the_plans_default(self):
        self.assertEqual("the plan's default model", store._model_label(""))
        self.assertEqual("the plan's default model", store._model_label(None))
        self.assertEqual("gpt-5", store._model_label("gpt-5"))


class NoLogDecidesOnTheModelNameAlone(unittest.TestCase):
    """Source checks for the three places that log a model call."""

    def setUp(self):
        with open(STORE, encoding="utf-8") as f:
            self.src = f.read()

    def test_the_dead_marker_is_gone(self):
        self.assertNotIn('"_Live LLM unavailable"', self.src)

    def test_no_model_name_gate_is_left(self):
        for stale in ("if _narrate and _mdl", "if use_llm and model:", "if _cmdl:"):
            self.assertNotIn(stale, self.src, stale)

    def test_regenerate_uses_generate_reports_own_rule(self):
        body = self.src.split("def regenerate_report(")[1].split("\ndef ")[0]
        self.assertIn("llm_sim._use_real() or llm_sim._llm_available()", body)
        with open(os.path.join(ROOT, "modules/backend/services/fusion/llm_sim.py"), encoding="utf-8") as f:
            self.assertIn("if prefer_llm and (_use_real() or _llm_available()):", f.read(),
                          "the rule copied here must still be generate_report's")


if __name__ == "__main__":
    unittest.main(verbosity=2)
