"""A case with an auto (operator-unchosen) window DISPLAYS the detected-activity
span, not the wide ten-year default — so a one-minute attack is shown as a
one-minute window. The fuse BOUND stays wide (re-fusion never drops late data);
this is the view narrowing, and it flips off the moment the operator sets a window.

2026-10-08: on a lab APTSimulator case the displayed window was 2016→2026 for a
~45-minute attack. view_window now prefers the activity span when the window is
still the default.
"""

import os
import sys
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402


def _f(ts, occ_latest=None):
    return types.SimpleNamespace(ts=ts, occ_latest=occ_latest)


def _graph(*findings):
    return types.SimpleNamespace(findings=list(findings))


class ActivityWindowFromGraph(unittest.TestCase):
    def test_span_is_first_hit_to_last_padded(self):
        g = _graph(_f("2026-10-07T10:01:45Z"),
                   _f("2026-10-07T10:20:00Z", occ_latest="2026-10-07T10:45:16Z"))
        w = store._activity_window_from_graph(g, pad_seconds=120)
        self.assertEqual("2026-10-07T09:59:45", w["start"])   # 10:01:45 - 2 min
        self.assertEqual("2026-10-07T10:47:16", w["end"])     # 10:45:16 + 2 min

    def test_none_when_nothing_is_dated(self):
        self.assertIsNone(store._activity_window_from_graph(_graph(_f(None), _f(None))))
        self.assertIsNone(store._activity_window_from_graph(_graph()))


class WindowIsAuto(unittest.TestCase):
    def test_the_flag_wins_when_present(self):
        self.assertTrue(store._window_is_auto({"time_window_auto": True}))
        self.assertFalse(store._window_is_auto({"time_window_auto": False,
                                                "time_window": {"start": "2016-01-01T00:00:00",
                                                                "end": "2026-01-01T00:00:00"}}))

    def test_back_compat_detects_the_ten_year_default(self):
        # An older case with no flag: auto only if the window is the ~10y default.
        self.assertTrue(store._window_is_auto(
            {"time_window": {"start": "2016-10-08T09:42:34", "end": "2026-10-08T09:42:34"}}))
        self.assertFalse(store._window_is_auto(
            {"time_window": {"start": "2026-10-07T10:00:00", "end": "2026-10-07T11:00:00"}}))


class ViewWindow(unittest.TestCase):
    AW = {"start": "2026-10-07T09:59:45", "end": "2026-10-07T10:47:16"}
    BOUND = {"start": "2016-10-08T09:42:34", "end": "2026-10-08T09:42:34"}

    def test_auto_case_shows_the_activity_span(self):
        d = {"time_window_auto": True, "time_window": self.BOUND, "activity_window": self.AW}
        self.assertEqual(self.AW, store.view_window(d))

    def test_operator_set_window_is_shown_verbatim(self):
        d = {"time_window_auto": False, "time_window": self.BOUND, "activity_window": self.AW}
        self.assertEqual(self.BOUND, store.view_window(d))

    def test_auto_but_no_activity_yet_falls_back_to_the_bound(self):
        d = {"time_window_auto": True, "time_window": self.BOUND}
        self.assertEqual(self.BOUND, store.view_window(d))

    def test_a_selected_scope_still_wins(self):
        d = {"time_window_auto": True, "time_window": self.BOUND, "activity_window": self.AW,
             "active_scope": "s1",
             "scopes": [{"id": "s1", "window": {"start": "2026-10-07T10:04:00",
                                                "end": "2026-10-07T10:31:00"}}]}
        self.assertEqual({"start": "2026-10-07T10:04:00", "end": "2026-10-07T10:31:00"},
                         store.view_window(d))


if __name__ == "__main__":
    unittest.main()
