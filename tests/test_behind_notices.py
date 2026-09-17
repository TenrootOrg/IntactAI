"""The case says when what is on screen is behind the analyst's changes.

A verdict, manual event, identity decision or report setting marks the report
behind (it is not regenerated automatically: that spends tokens). Saved settings
that apply only through a Refusion are reported until one runs.
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


class RefusionNeeded(unittest.TestCase):
    def test_saved_settings_that_differ_from_the_fused_ones(self):
        d = {"time_window": {"start": "2025-01-01", "end": None}, "min_severity": "medium"}
        fused = dict(d, fused_settings_sig=store._settings_sig(d))
        self.assertFalse(store.refusion_needed(fused))
        self.assertTrue(store.refusion_needed(dict(fused, min_severity="high")))
        self.assertTrue(store.refusion_needed(dict(fused, excluded_hosts=["HOSTA"])))
        self.assertFalse(store.refusion_needed(dict(fused, master_prompt="x")))   # report-only setting

    def test_a_case_never_fused_under_this_code_says_nothing(self):
        self.assertFalse(store.refusion_needed({"min_severity": "high"}))


class ReportBehind(unittest.TestCase):
    def _marks(self, fn, *a):
        with mock.patch.object(store, "_merge_case_details") as merge, \
             mock.patch.object(store, "_mutate_list_field"), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "get_case", return_value={"dispositions": []}), \
             mock.patch.object(store, "load_graph", return_value=mock.Mock(findings=[])), \
             mock.patch.object(store, "clear_disposition"):
            fn(*a)
        return any(c.args[1:] == ({"report_dirty": True},) for c in merge.call_args_list)

    def test_a_true_positive_verdict(self):
        self.assertTrue(self._marks(store.validate_timeline, "c", "f1", "real"))

    def test_an_identity_decision(self):
        self.assertTrue(self._marks(store.split_account, "c", "account:x"))
        self.assertTrue(self._marks(store.undo_identity_decision, "c", "split:account:x"))

    def test_a_manual_event(self):
        self.assertTrue(self._marks(store.add_manual_timeline_event, "c", {"title": "GPO"}))


if __name__ == "__main__":
    unittest.main()
