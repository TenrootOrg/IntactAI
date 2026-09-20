"""The Configuration module ticks are the operator's choice, including "none".

QA TASK-12672: unticking Velociraptor dropped the results, but the tick was back
when Configuration was reopened -- an empty list was read as "never chosen" and
replaced by the default, so the case also fused what had been switched off.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402


class NormalizeModules(unittest.TestCase):
    def test_never_chosen_means_the_default(self):
        self.assertEqual(store.normalize_modules(None), list(store.FUSION_MODULES_DEFAULT))

    def test_no_modules_is_kept(self):
        self.assertEqual(store.normalize_modules([]), [])

    def test_legacy_names_still_map(self):
        self.assertEqual(store.normalize_modules(["velociraptor"]), ["velociraptor_agentic"])


class SavingTheChoice(unittest.TestCase):
    def _save(self, cfg):
        saved = {}
        with mock.patch.object(store, "get_case", return_value={"name": "c"}), \
             mock.patch.object(store, "_merge_case_details", side_effect=lambda cid, p: saved.update(p)), \
             mock.patch.object(store, "log_case_event"), mock.patch.object(store, "_log_config_changes"):
            store.set_analysis_config("c", cfg)
        return saved

    def test_unticking_everything_is_saved_as_nothing(self):
        self.assertEqual(self._save({"fusion_modules": []}).get("fusion_modules"), [])

    def test_a_real_choice_is_saved(self):
        self.assertEqual(self._save({"fusion_modules": ["memory"]}).get("fusion_modules"), ["memory"])

    def test_a_case_with_no_modules_fuses_nothing(self):
        self.assertEqual(store._enabled_run_types({"fusion_modules": []}), set())
        self.assertTrue(store._enabled_run_types({}))          # never chosen -> default


if __name__ == "__main__":
    unittest.main()
