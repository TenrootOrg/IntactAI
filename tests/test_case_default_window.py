"""A new investigation case defaults its scope to [creation-10y, creation].

Why: an OPEN default let a freshly-collected case be dominated by months-old
staged events (a lab image's December log-wipe), and — combined with event-time
scoping — made "scope to last 24h" look like the case had vanished. A bounded,
concrete default keeps a case reproducible (the 'until' bound does not drift with
wall-clock time) and never empty-by-default.

Rules under test:
  - start  = 10 years before creation, and can never be cleared to empty.
  - end    = the creation time.
  - system / default catch-all cases keep an OPEN window.

The real functions are lifted out of store.py and exec'd (store.py itself pulls
the whole backend and can't be imported in this stdlib-only suite), mirroring
tests/test_stale_detection.py — so this can't drift from what ships.
"""

import ast
import os
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")

WANTED = ("_case_created_dt", "_default_window", "create_case")


def _load():
    with open(STORE, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    picked = {n.name: ast.get_source_segment(src, n)
              for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in WANTED}
    missing = [w for w in WANTED if w not in picked]
    if missing:
        raise AssertionError("not found in store.py: %s" % ", ".join(missing))

    ns = {}
    # Capture what create_case would persist, without a database.
    ns["_state"] = {"created_details": None, "case": {}}

    class _WS:
        def create_automation_run(self, *, automation_type, name, case_id, details):
            ns["_state"]["created_details"] = details
            return "case_1788079605210"       # a real-shaped id (ms epoch)
    ns["_ws"] = lambda: _WS()
    ns["CASE_TYPE"] = "case"
    ns["get_case"] = lambda cid: ns["_state"]["case"]

    for name in WANTED:
        exec(compile(picked[name], STORE, "exec"), ns)
    return ns


class TestDefaultWindow(unittest.TestCase):
    def setUp(self):
        self.ns = _load()

    def test_default_window_is_ten_years_up_to_creation(self):
        created = datetime(2026, 8, 30, 8, 46, 45, tzinfo=timezone.utc)
        w = self.ns["_default_window"](created)
        self.assertEqual(w["end"], "2026-08-30T08:46:45")
        self.assertEqual(w["start"], "2016-08-30T08:46:45")   # exactly 10 calendar years
        s = datetime.fromisoformat(w["start"]); e = datetime.fromisoformat(w["end"])
        self.assertEqual(e.year - s.year, 10)
        self.assertEqual((e.month, e.day, e.hour), (s.month, s.day, s.hour))

    def test_created_dt_comes_from_the_case_id(self):
        got = self.ns["_case_created_dt"]("case_1788079605210")
        self.assertEqual(got.year, 2026)
        self.assertEqual((got.month, got.day), (8, 30))

    def test_created_dt_falls_back_when_id_has_no_epoch(self):
        got = self.ns["_case_created_dt"]("not-an-id")
        self.assertIsInstance(got, datetime)     # now(), not a crash

    def test_new_case_gets_a_bounded_window(self):
        self.ns["create_case"]("my case")
        tw = self.ns["_state"]["created_details"]["time_window"]
        self.assertTrue(tw.get("start"), "start must be set")
        self.assertTrue(tw.get("end"), "end must be set")
        s = datetime.fromisoformat(tw["start"]); e = datetime.fromisoformat(tw["end"])
        self.assertEqual(e.year - s.year, 10)

    def test_caller_supplied_bounds_are_respected(self):
        self.ns["create_case"]("scoped", time_window={"start": "2026-01-01T00:00:00",
                                                       "end": "2026-01-02T00:00:00"})
        tw = self.ns["_state"]["created_details"]["time_window"]
        self.assertEqual(tw["start"], "2026-01-01T00:00:00")
        self.assertEqual(tw["end"], "2026-01-02T00:00:00")

    def test_system_and_default_cases_stay_open(self):
        for kw in ({"is_system": True}, {"is_default": True}):
            with self.subTest(**kw):
                self.ns["_state"]["created_details"] = None
                self.ns["create_case"]("sys", **kw)
                tw = self.ns["_state"]["created_details"]["time_window"]
                self.assertEqual(tw, {}, "system/default cases keep an open window")

    def test_the_empty_start_fallback_value_is_creation_minus_10y(self):
        """set_analysis_config replaces an empty 'from' with exactly this value.
        (The wiring inside set_analysis_config is integration-verified on the box;
        that function pulls in the whole backend and can't exec standalone here —
        this pins the fallback VALUE it computes.)"""
        start = self.ns["_default_window"](
            self.ns["_case_created_dt"]("case_1788079605210"))["start"]
        self.assertEqual(start, "2016-08-30T08:46:45")


if __name__ == "__main__":
    unittest.main()
