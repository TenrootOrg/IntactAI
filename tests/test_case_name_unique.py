"""A case name is used once: creating or renaming to a name in use is refused.

Two cases both called "test2" could not be told apart in the case list or the
selector (2026-10-21). Case and surrounding spaces are ignored; the message says
to remove or rename the existing one. Import keeps its own rule ("x (imported)").
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

RUNS = [{"run_id": "case_1", "automation_type": store.CASE_TYPE, "details": {"name": "test2"}},
        {"run_id": "case_2", "automation_type": store.CASE_TYPE, "details": {"name": "Default", "is_default": True}},
        {"run_id": "run_9", "automation_type": "velociraptor_collection", "details": {"name": "test3"}}]


class Unique(unittest.TestCase):
    def setUp(self):
        ws = mock.Mock()
        ws.get_all_automation_runs.return_value = RUNS
        p = mock.patch.object(store, "_ws", return_value=ws)
        p.start()
        self.addCleanup(p.stop)

    def test_a_name_in_use_ignoring_case_and_spaces(self):
        self.assertEqual(("case_1", "test2"), store.case_named("  TEST2 "))
        self.assertIn('A case named "test2" already exists. Remove it or rename it first',
                      store.duplicate_name_error("Test2"))

    def test_a_free_name_and_non_case_rows(self):
        self.assertIsNone(store.case_named("test3"), "a run called test3 is not a case")
        self.assertIsNone(store.duplicate_name_error("brand new"))

    def test_the_built_in_names_are_taken_too(self):
        self.assertIsNotNone(store.duplicate_name_error("default"))

    def test_renaming_a_case_to_its_own_name_is_fine(self):
        self.assertIsNone(store.duplicate_name_error("test2", except_id="case_1"))

    def test_renaming_to_another_cases_name_is_refused(self):
        with mock.patch.object(store, "get_case", return_value={"name": "other"}), \
             mock.patch.object(store, "_merge_case_details") as merge:
            res = store.update_case_info("case_5", {"name": "TEST2"})
        self.assertIn("already exists", res.get("error", ""))
        merge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
