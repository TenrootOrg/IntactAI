"""C4: the auto-fuse's retries must not lose the report or give up quietly.

  - a busy retry that finds the graph already caught up (store._FUSE_OWED rebuilds
    the graph only) must still regenerate the report it was owed;
  - a fresh arming with nothing stale stays a silent no-op;
  - a long import does not use up the busy-retry budget;
  - giving up on a run stuck "running" names that run in the case log.

Reuses test_autofuse's fake store and fast real timers.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_autofuse as base  # noqa: E402
from test_autofuse import autofuse  # noqa: E402


class TestBusyRetryCatchUpStillRefreshesReport(base._Base):

    def test_owed_catch_up_fused_the_graph_report_is_still_regenerated(self):
        # First fuse is busy; by the retry another fuse (the _FUSE_OWED catch-up)
        # has rebuilt the graph, so nothing is stale — but the report is behind.
        orig = self.store.fuse_case

        def busy_then_caught_up(cid, **kw):
            self.store.fuses.append(kw)
            self.store._per_case[cid] = []       # the catch-up fuse cleared it
            raise base.FusionBusy("busy")
        self.store.fuse_case = busy_then_caught_up
        self.store.report_behind = True
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.store.fuse_case = orig
        self.assertEqual(len(self.store.fuses), 1, "the graph is current: no second fuse")
        self.assertEqual(self.store.report_kinds(), ["locked"],
                         "the report this data was owed must still be written")

    def test_retry_with_report_current_does_nothing(self):
        self.store._stale = []
        self.store.report_behind = False
        autofuse._fire("case_1", "x", 0, 1)
        self.assertEqual(self.store.reports, [])
        self.assertEqual(self.store.fuses, [])

    def test_fresh_arming_with_nothing_stale_stays_silent(self):
        self.store._stale = []
        self.store.report_behind = True
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.reports, [], "attempt 0 is a no-op, never a billed report")
        self.assertEqual(self.store.events, [])

    def test_a_broken_report_probe_is_not_a_fuse_failure(self):
        self.store._stale = []

        def boom(*a, **k):
            raise RuntimeError("db")
        self.store.report_stale_runs = boom
        autofuse._fire("case_1", "x", 3, 0)
        self.assertNotIn("Refusion failed", self.store.actions())


class TestImportWaitAndBusyRetryCountSeparately(base._Base):

    def test_busy_after_a_long_import_still_retries(self):
        autofuse.MAX_BUSY_RETRIES = 3
        self.store.busy_times = 1
        # As if 50 importing polls already happened: the busy budget is untouched.
        autofuse._fire("case_1", "x", 50, 0)
        self.settle(2.0)
        self.assertEqual(len(self.store.fuses), 2, "a busy hit must retry, not give up")
        self.assertNotIn("Refusion skipped", self.store.actions())
        deferred = [d for a, _s, d in self.store.events if a == "Refusion deferred"]
        self.assertTrue(deferred and "1/3" in deferred[0], deferred)


class TestStuckRunGiveUpIsNamed(base._Base):

    def test_give_up_names_the_stuck_run(self):
        self.store.members = ["hunt_H.123"]
        self.store.member_status = "running"
        autofuse._fire("case_1", "x", autofuse.MAX_IMPORTING_RETRIES - 1, 0)
        skipped = [(s, d) for a, s, d in self.store.events if a == "Refusion skipped"]
        self.assertEqual(len(skipped), 1)
        status, detail = skipped[0]
        self.assertEqual(status, "warning")
        self.assertIn("hunt_H.123", detail)
        self.assertIn("NOT in the graph", detail)
        self.assertEqual(self.store.fuses, [])


if __name__ == "__main__":
    unittest.main()
