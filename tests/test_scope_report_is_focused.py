"""Auto report type: a selected scope gets ONE focused report from all of its data.

Live 2026-10-20: zoomed into a 143-finding / 9-host scope, Auto still applied the
whole-case volume rule (>150 findings or >12 hosts -> macro) and wrote "Phase 1" plus
a synthesis at summary depth. Zooming in is the operator asking for one explicit
report of that window; the model's budget step-down still bounds a scope that is
genuinely too large. A forced Macro or Focused setting wins as before.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

W = {"start": "2026-04-27T09:07:22", "end": "2026-06-21T14:35:13"}
SCOPES = [{"id": "full", "window": None}, {"id": "w1", "window": W}]


class AutoOnAScopeIsFocused(unittest.TestCase):
    def test_auto_with_a_scope_selected_is_focused(self):
        self.assertEqual("focused", store.report_altitude_mode({"scopes": SCOPES, "active_scope": "w1"}))
        self.assertEqual("focused", store.report_altitude_mode(
            {"scopes": SCOPES, "active_scope": "w1", "report_altitude": "auto"}))

    def test_the_whole_case_keeps_auto(self):
        for d in ({}, {"scopes": SCOPES}, {"scopes": SCOPES, "active_scope": "full"}):
            self.assertEqual("auto", store.report_altitude_mode(d), d)

    def test_a_forced_type_wins_on_a_scope(self):
        for mode in ("macro", "focused"):
            self.assertEqual(mode, store.report_altitude_mode(
                {"scopes": SCOPES, "active_scope": "w1", "report_altitude": mode}))

    def test_every_reader_of_the_setting_goes_through_it(self):
        src = open(store.__file__).read()
        self.assertEqual(4, src.count("report_altitude_mode(d)") - src.count("def report_altitude_mode(d)"),
                         "cards, call count, fuse report, regenerate")
        self.assertNotIn('d.get("report_altitude") or "auto"', src)


if __name__ == "__main__":
    unittest.main()
