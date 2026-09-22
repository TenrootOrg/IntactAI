"""A report generation the operator has moved on from cannot hang the case.

Reported live: "Sending case data to the model — running 10 min", with nothing
actually running towards it.

  13:20:15  Regenerate on DeepSeek via OpenRouter. The call never answered — its
            connection was still open 25 minutes later — so the worker never
            reached the `finally` that clears report_generating.
  13:33:33  The operator switched to Gemini and pressed Refusion. Each fuse
            re-stamped report_generating_started_at, restarting the banner's clock
            and pushing back the stale cut-off, so the stuck run could never be
            recognised as stuck.

Verified on the appliance by executing it (a generate_report stub that blocks):
a Refusion leaves the running generation's clock alone; saving different AI
settings clears the banner at once and a new generation is not refused as busy;
when the old call finally answers its result is discarded and the new model's
report stands; re-saving identical settings stops nothing.

These pin the shape, offline.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


STORE = read("modules/backend/services/fusion/store.py")
CONFIG = read("modules/backend/routes/config_routes.py")
CASES = read("modules/backend/routes/case_routes.py")


def body(src, signature):
    start = src.index(signature)
    nxt = re.search(r"\n(def |@|class )", src[start + 1:])
    return src[start:start + 1 + nxt.start()] if nxt else src[start:]


class EveryGenerationHasAnIdentity(unittest.TestCase):

    def test_the_async_start_stamps_one(self):
        self.assertIn('"report_generation_id": gen_id', body(STORE, "def regenerate_report_async("))

    def test_the_worker_passes_it_down(self):
        self.assertIn("gen_id=gen_id", body(STORE, "def regenerate_report_async("))

    def test_the_worker_only_clears_markers_that_are_still_its_own(self):
        worker = body(STORE, "def regenerate_report_async(")
        self.assertIn("if _generation_is_current(case_id, gen_id):", worker,
                      "a superseded run finishing late must not wipe the banner of "
                      "the generation that replaced it")


class ASupersededResultIsNeverWritten(unittest.TestCase):

    def test_the_narrative_write_is_gated(self):
        regen = body(STORE, "def regenerate_report(")
        gate = regen.index("if not _generation_is_current(case_id, gen_id):")
        # The write goes through write_report_for_scope now — a report belongs to
        # the timeframe it was generated for, whichever one is being read when it
        # lands. The guarantee asserted here is unchanged: check before writing.
        write = regen.index("write_report_for_scope(case_id, _gen_scope, _narrative_patch)")
        self.assertLess(gate, write, "check BEFORE writing, or the old model's report "
                                     "lands over the new one")

    def test_the_report_is_written_into_the_scope_it_was_generated_for(self):
        """Captured at the START of the run, not read back at the end: the operator
        is free to read another timeframe while it runs."""
        regen = body(STORE, "def regenerate_report(")
        self.assertLess(regen.index("_gen_scope = _active_scope_id(d)"),
                        regen.index("write_report_for_scope("))

    def test_the_discard_is_visible_in_the_case_log(self):
        self.assertIn('"Report · late result discarded"', body(STORE, "def regenerate_report("))


class ChangingTheAISettingsRetiresInFlightGenerations(unittest.TestCase):

    def test_supersede_clears_every_marker(self):
        # the work lives in _retire_generation, shared with the stuck-run watchdog
        self.assertIn("_retire_generation(", body(STORE, "def supersede_report_generations("))
        sup = body(STORE, "def _retire_generation(")
        for key in ("report_generating", "report_generating_started_at", "report_phase",
                    "report_phase_started_at", "report_generation_id"):
            self.assertIn(f'"{key}"', sup, f"{key} must be cleared")

    def test_supersede_replaces_the_lock_the_hung_thread_still_holds(self):
        self.assertIn("_REPORT_GEN_LOCKS[case_id] = threading.Lock()",
                      body(STORE, "def _retire_generation("),
                      "without a fresh lock every new generation is refused as busy "
                      "until the hung call returns — which may be never")

    def test_the_settings_save_calls_it_only_when_the_settings_changed(self):
        save = body(CONFIG, "def save_config(")
        self.assertIn("_before = llm_sim._config_id(", save)
        self.assertIn("!= _before", save, "re-saving identical settings must stop nothing")
        self.assertIn("store.supersede_report_generations(", save)

    def test_a_failure_to_retire_never_fails_the_save(self):
        save = body(CONFIG, "def save_config(")
        call = save.index("store.supersede_report_generations(")
        self.assertIn("try:", save[:call][-600:])
        self.assertIn("except Exception", save[call:call + 400])


class AFuseDoesNotRestartARunningGenerationsClock(unittest.TestCase):

    def test_the_stamp_is_guarded(self):
        self.assertIn("if _narrate and not report_generation_active(d):", STORE)


class ARestartClearsTheWholeGeneration(unittest.TestCase):

    def test_the_startup_sweep_clears_phase_and_id_too(self):
        start = CASES.index("interrupted by a backend restart")
        sweep = CASES[start - 900:start]
        for key in ("report_phase", "report_generation_id"):
            self.assertIn(f'"{key}": None', sweep,
                          f"{key} survived the restart, so the next banner showed a dead run")


if __name__ == "__main__":
    unittest.main(verbosity=2)
