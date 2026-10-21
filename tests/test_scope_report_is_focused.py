"""Auto report type on a selected scope: the scope's own shape decides.

2026-10-20: zoomed into a 143-finding / 9-host scope, Auto applied the whole-case
volume rule (>150 findings or >12 hosts -> macro) and wrote "Phase 1" plus a
synthesis at summary depth -- so every selected scope was made focused.
2026-10-21: that made Auto "always choose Scope": a scope as wide as the whole case
(names_test, 2024-05 -> 2026-06, several attack phases on 9 hosts) never segmented.
Now a scope is "auto-scope": ONE phase (or one host) inside it is focused, whatever
its volume; DISTINCT phases across hosts are macro. A forced Macro / Focused wins.
"""
import datetime as _dt
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema, store  # noqa: E402

W = {"start": "2026-04-27T09:07:22", "end": "2026-06-21T14:35:13"}
SCOPES = [{"id": "full", "window": None}, {"id": "w1", "window": W}]
T0 = _dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _graph(findings, n_hosts):
    ents = {f"asset:h{i}": schema.Entity(id=f"asset:h{i}", type="asset", label=f"H{i}") for i in range(n_hosts)}
    return schema.FusionGraph(case_id="T", entities=ents, findings=findings)


def _f(i, day, host, sev="high"):
    return schema.Finding(id=f"f{i}", title=f"F{i}", severity=sev, confidence="medium", summary="s",
                          asset_ids=[f"asset:h{host}"], ts=(T0 + _dt.timedelta(days=day, minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"))


class TheSetting(unittest.TestCase):
    def test_auto_with_a_scope_selected_lets_the_scope_decide(self):
        self.assertEqual("auto-scope", store.report_altitude_mode({"scopes": SCOPES, "active_scope": "w1"}))
        self.assertEqual("auto-scope", store.report_altitude_mode(
            {"scopes": SCOPES, "active_scope": "w1", "report_altitude": "auto"}))

    def test_the_whole_case_keeps_auto(self):
        for d in ({}, {"scopes": SCOPES}, {"scopes": SCOPES, "active_scope": "full"}):
            self.assertEqual("auto", store.report_altitude_mode(d), d)

    def test_a_forced_type_wins_on_a_scope(self):
        for mode in ("macro", "focused"):
            self.assertEqual(mode, store.report_altitude_mode(
                {"scopes": SCOPES, "active_scope": "w1", "report_altitude": mode}))

    def test_every_reader_of_the_setting_goes_through_it(self):
        with open(store.__file__) as fh:
            src = fh.read()
        self.assertEqual(4, src.count("report_altitude_mode(d)") - src.count("def report_altitude_mode(d)"),
                         "cards, call count, fuse report, regenerate")
        self.assertNotIn('d.get("report_altitude") or "auto"', src)


class TheScopesShape(unittest.TestCase):
    def test_one_big_phase_in_a_scope_is_one_focused_report(self):
        # 200 findings on 3 hosts within one day: the whole-case volume rule says macro
        g = _graph([_f(i, 0, i % 3) for i in range(200)], 3)
        self.assertEqual("macro", render._resolve_altitude(g, mode="auto")[0], "the whole case: too big to narrate")
        self.assertEqual("focused", render._resolve_altitude(g, mode="auto-scope")[0], "a phase zoomed into: one chunk")

    def test_a_scope_with_distinct_phases_across_hosts_is_segmented(self):
        # two bursts a month apart, on different hosts, each well above the substantial bar
        g = _graph([_f(i, 0, 0) for i in range(6)] + [_f(10 + i, 30, 1) for i in range(6)], 2)
        alt, why = render._resolve_altitude(g, mode="auto-scope")
        self.assertEqual("macro", alt, why)

    def test_one_host_in_a_scope_stays_one_story(self):
        g = _graph([_f(i, 0, 0) for i in range(6)] + [_f(10 + i, 30, 0) for i in range(6)], 1)
        self.assertEqual("focused", render._resolve_altitude(g, mode="auto-scope")[0])


if __name__ == "__main__":
    unittest.main()
