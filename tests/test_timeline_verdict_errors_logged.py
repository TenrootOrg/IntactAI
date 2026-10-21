"""A verdict is in the case Log only once it is saved; a failure is in the Log too.

2026-10-21: "marked …" was written BEFORE the write, so a failed save still read as
done in the Log, and the route answered a bare 500. Now: a failed write logs
nothing as marked (the route logs "NOT saved: …" as an error); a write that worked
but whose follow-up (suppression / re-fuse) failed says "the verdict is saved, but
applying it … failed".
"""
import os
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid):
    return Finding(id=fid, title=f"T on {fid}", severity="high", confidence="medium",
                   summary="", occ_count=1, occ_latest="2026-06-01T10:00:00Z")


class Logged(unittest.TestCase):
    def run_it(self, write_fails=False, fuse_fails=False):
        state = {"timeline_validations": [], "dispositions": []}
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: fn(state)

        def mut(cid, field, fn):
            if write_fails:
                raise OSError("database is locked")
            state[field] = fn(list(state.get(field) or []))
        logs = []
        g = types.SimpleNamespace(findings=[_f("a"), _f("b")])
        with mock.patch.object(store, "get_case", side_effect=lambda cid: dict(state)), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_mutate_list_field", side_effect=mut), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(store, "_report_behind"), \
             mock.patch.object(store, "ack_rows"), \
             mock.patch.object(store, "log_case_event", side_effect=lambda cid, a, s, d, **k: logs.append((s, d))), \
             mock.patch.object(store, "fuse_case", side_effect=RuntimeError("fuse lock busy") if fuse_fails else None):
            try:
                res = store.validate_timeline_many("c1", ["a", "b"], "false_positive")
            except OSError as e:
                res = e
        return res, logs, state

    def test_saved_then_logged(self):
        res, logs, state = self.run_it()
        self.assertEqual(2, len(state["timeline_validations"]))
        self.assertIn(("info", "a, b marked false_positive (2 rows)"), logs)

    def test_a_failed_write_is_never_logged_as_marked(self):
        res, logs, _ = self.run_it(write_fails=True)
        self.assertIsInstance(res, OSError, "the route gets the error and logs NOT saved")
        self.assertFalse([d for _s, d in logs if "marked" in d], logs)

    def test_saved_but_not_applied_says_so(self):
        res, logs, state = self.run_it(fuse_fails=True)
        self.assertEqual(2, len(state["timeline_validations"]), "the verdict itself is kept")
        self.assertIn("re-fuse the case", res.get("warning", ""))
        self.assertTrue(any(s == "error" and "the verdict is saved, but applying it to the analysis failed" in d
                            and "fuse lock busy" in d for s, d in logs), logs)


if __name__ == "__main__":
    unittest.main()
