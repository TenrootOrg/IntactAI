"""The case time window must judge event times as INSTANTS, across the timestamp
formats real artifacts emit — Windows and Linux.

Two bugs motivated this:

1. `in_window` string-compared the window bounds (a 19-char, no-`Z` picker value)
   against entity `first_seen` values that carry a trailing `Z` and up to
   nanosecond fractional seconds. Lexicographically
   `"2026-08-30T12:00:00Z" > "2026-08-30T12:00:00"`, so an event AT the window end
   sorted as *after* it and a freshly-collected row was dropped from the graph.

2. `keys.to_utc_dt` (the new comparison primitive) rejected FLOAT epoch
   (`"1788079621.57"` from Linux stat Mtime and some Velociraptor plugins) because
   the old branch guarded on `str.isdigit()`. Those rows fell to None.

Design guarantee under test: a format we cannot parse returns None and is KEPT
(never dropped) — a format gap degrades window precision, it never loses evidence.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUSION = os.path.join(ROOT, "modules/backend/services/fusion")
KEYS = os.path.join(FUSION, "keys.py")
CORRELATE = os.path.join(FUSION, "correlate.py")


def _exec(path, module):
    with open(path, encoding="utf-8") as fh:
        exec(compile(fh.read(), path, "exec"), module.__dict__)
    return module


def _load_keys():
    """keys.py is stdlib-only with no intra-fusion imports (see its docstring)."""
    return _exec(KEYS, types.ModuleType("keys_under_test"))


def _load_in_window(keys_mod):
    """Load the REAL in_window from correlate.py (not a copy — a copy could pass
    while the shipped comparator regressed). correlate imports `.schema`,
    `.severity` and `.keys`; stub the first two, inject the real keys, exec it as
    a member of a throwaway package so its relative imports resolve."""
    pkg = types.ModuleType("_fuse_pkg")
    pkg.__path__ = []
    sys.modules["_fuse_pkg"] = pkg
    sys.modules["_fuse_pkg.keys"] = keys_mod
    schema = types.ModuleType("_fuse_pkg.schema")
    for name in ("FusionGraph", "Finding", "EvidenceRef"):
        setattr(schema, name, type(name, (), {}))
    sys.modules["_fuse_pkg.schema"] = schema
    sys.modules["_fuse_pkg.severity"] = types.ModuleType("_fuse_pkg.severity")
    mod = types.ModuleType("_fuse_pkg.correlate")
    mod.__package__ = "_fuse_pkg"
    _exec(CORRELATE, mod)
    return mod.in_window


keys = _load_keys()
in_window = _load_in_window(keys)


class TestToUtcDtCoversRealArtifactFormats(unittest.TestCase):
    """Every timestamp CLASS Velociraptor emits for a time column (Windows and
    Linux) plus the raw epoch forms must parse to the same instant."""

    # ISO / string forms that all name the SAME wall-second 2026-08-30T10:44:00.
    WALLCLOCK = {
        "RFC3339 Z":          "2026-08-30T10:44:00Z",
        "RFC3339Nano Z":      "2026-08-30T10:44:00.570740699Z",
        "RFC3339 offset":     "2026-08-30T10:44:00+00:00",
        "RFC3339 offset ncln":"2026-08-30T10:44:00+0000",
        "no-Z (norm_ts out)": "2026-08-30T10:44:00",
        "space separated":    "2026-08-30 10:44:00",
        "space + Z":          "2026-08-30 10:44:00Z",
        "space + offset":     "2026-08-30 10:44:00 +0000",
    }
    # Epoch forms — a different instant (08:47:01Z), so asserted on their own.
    EPOCH = {
        "epoch seconds int":  "1788079621",
        "epoch millis int":   "1788079621179",
        "epoch seconds float":"1788079621.570741",   # Linux stat Mtime
        "epoch millis float": "1788079621179.0",
    }

    def test_wallclock_forms_parse_to_the_same_instant(self):
        for name, val in self.WALLCLOCK.items():
            with self.subTest(fmt=name):
                dt = keys.to_utc_dt(val)
                self.assertIsNotNone(dt, f"{name} ({val!r}) must parse")
                self.assertEqual(str(dt.tzinfo), "UTC")
                self.assertTrue(dt.isoformat().startswith("2026-08-30T"))
                self.assertEqual((dt.hour, dt.minute, dt.second), (10, 44, 0))

    def test_epoch_forms_parse_to_their_instant(self):
        for name, val in self.EPOCH.items():
            with self.subTest(fmt=name):
                dt = keys.to_utc_dt(val)
                self.assertIsNotNone(dt, f"{name} ({val!r}) must parse")
                self.assertEqual((dt.hour, dt.minute, dt.second), (8, 47, 1))

    def test_date_only_parses_to_midnight(self):
        dt = keys.to_utc_dt("2026-08-30")
        self.assertIsNotNone(dt)
        self.assertEqual((dt.hour, dt.minute, dt.second), (0, 0, 0))

    def test_float_epoch_regression(self):
        """The exact class that used to fall to None."""
        self.assertIsNotNone(keys.to_utc_dt("1788079621.57"))

    def test_unparseable_returns_none_so_the_row_is_kept(self):
        # Ambiguous / non-Velociraptor formats we deliberately DON'T guess at
        # (guessing risks a WRONG date, worse than undated). None -> in_window
        # keeps the row; a format gap never drops evidence.
        for val in ("8/30/2026 10:44:00 PM", "Mon Aug 30 10:44:00 2026",
                    "not-a-time", "", None):
            with self.subTest(val=val):
                self.assertIsNone(keys.to_utc_dt(val))


class TestInWindowComparesInstantsNotStrings(unittest.TestCase):
    """The shipped comparator, loaded for real."""

    def test_event_at_the_end_boundary_with_Z_is_kept(self):
        """The original data-loss bug: a picker end bound is 19-char/no-Z; an
        event at that same instant carries a Z, so string compare said ts>end."""
        w = {"start": "2026-08-29T00:00:00", "end": "2026-08-30T12:00:00"}
        self.assertTrue(in_window("2026-08-30T12:00:00Z", w))
        self.assertTrue(in_window("2026-08-30T12:00:00.000000000Z", w))

    def test_genuinely_after_end_is_excluded(self):
        w = {"start": "2026-08-29T00:00:00", "end": "2026-08-30T12:00:00"}
        self.assertFalse(in_window("2026-08-30T12:00:01Z", w))

    def test_before_start_excluded_after_start_kept(self):
        w = {"start": "2026-08-29T12:00:00", "end": None}
        self.assertFalse(in_window("2026-08-28T10:50:00Z", w))   # QA's 006 case
        self.assertTrue(in_window("2026-08-29T13:00:00Z", w))

    def test_float_epoch_event_is_windowed(self):
        w = {"start": "2026-08-30T00:00:00", "end": "2026-08-30T23:59:59"}
        self.assertTrue(in_window("1788079621.57", w))            # 08-30 08:47Z

    def test_undated_and_unparseable_are_kept(self):
        w = {"start": "2026-08-29T12:00:00", "end": None}
        self.assertTrue(in_window(None, w))                      # structural / undated
        self.assertTrue(in_window("Mon Aug 30 10:44:00 2026", w))  # unparseable -> kept

    def test_degenerate_window_is_open(self):
        w = {"start": "2026-05-01T12:00:00", "end": "2026-05-01T12:00:00"}
        self.assertTrue(in_window("2020-01-01T00:00:00Z", w))

    def test_no_window_keeps_everything(self):
        self.assertTrue(in_window("2026-08-30T10:44:00Z", None))


if __name__ == "__main__":
    unittest.main()
