"""A change saved while the case is fusing is fused as soon as that fuse ends.

Found on "qa test" (2026-09-28): a Refusion writing the AI report held the case's
fuse lock for minutes; ~20 Timeline verdicts made meanwhile each got "deferred —
a fuse is already running" and nothing ever ran them. Risk did not go down, the
identities and Jev did not move, and Regenerate report wrote from the stale graph.
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import jev, store  # noqa: E402


class Owed(unittest.TestCase):
    def setUp(self):
        self.cid = "case_owed_%d" % id(self)
        self.calls, self.release = [], threading.Event()
        store._FUSE_OWED.discard(self.cid)

        def body(case_id, **kw):
            self.calls.append(kw.get("trigger"))
            if len(self.calls) == 1:
                self.release.wait(5)              # the long first fuse (a report being written)
            return mock.Mock()
        for target, attr, value in ((store, "_fuse_case_locked", body), (store, "log_case_event", mock.Mock()),
                                    (store, "_report_behind", mock.Mock()), (store, "_track_rows", mock.Mock()),
                                    (jev, "after_fuse", mock.Mock())):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _wait(self, cond, t=5):
        end = time.time() + t
        while time.time() < end and not cond():
            time.sleep(0.02)
        return cond()

    def test_a_turned_away_change_is_fused_when_the_running_fuse_ends(self):
        first = threading.Thread(target=store.fuse_case, args=(self.cid,), kwargs={"trigger": "refusion"})
        first.start()
        self.assertTrue(self._wait(lambda: len(self.calls) == 1))
        with self.assertRaises(store.FusionBusy):
            store.fuse_case(self.cid, trigger="a verdict")
        with self.assertRaises(store.FusionBusy):
            store.fuse_case(self.cid, trigger="another verdict")
        self.assertIn(self.cid, store._FUSE_OWED)
        self.release.set()
        first.join(5)
        self.assertTrue(self._wait(lambda: len(self.calls) == 2), self.calls)
        time.sleep(0.2)
        self.assertEqual(self.calls, ["refusion", store.TRIGGER_CATCH_UP])     # ONE catch-up for both
        self.assertNotIn(self.cid, store._FUSE_OWED)

    def test_a_dry_run_does_not_pay_the_debt_but_frees_the_lock_for_it(self):
        store._FUSE_OWED.add(self.cid)
        self.release.set()
        store.fuse_case(self.cid, _record=False)        # a probe: saves nothing
        self.assertTrue(self._wait(lambda: len(self.calls) == 2), self.calls)
        self.assertEqual(self.calls[1], store.TRIGGER_CATCH_UP)   # the owed fuse still ran
        self.assertTrue(self._wait(lambda: self.cid not in store._FUSE_OWED))

    def test_a_dry_run_that_is_turned_away_owes_nothing(self):
        first = threading.Thread(target=store.fuse_case, args=(self.cid,))
        first.start()
        self.assertTrue(self._wait(lambda: len(self.calls) == 1))
        with self.assertRaises(store.FusionBusy):
            store.fuse_case(self.cid, _record=False)
        self.assertNotIn(self.cid, store._FUSE_OWED)
        self.release.set()
        first.join(5)

    def test_the_report_waits_for_a_fuse_that_is_owed(self):
        store._FUSE_OWED.add(self.cid)
        done = threading.Event()
        threading.Thread(target=lambda: (store._wait_for_fuses(self.cid, timeout=5), done.set())).start()
        time.sleep(0.3)
        self.assertFalse(done.is_set())                 # owed: the graph is about to change
        store._FUSE_OWED.discard(self.cid)
        self.assertTrue(done.wait(3))

    def test_waiting_from_inside_the_fuse_does_not_wait_on_itself(self):
        lk = store._fuse_lock(self.cid)
        with lk:
            store._FUSE_OWED.add(self.cid)
            t0 = time.time()
            self.assertTrue(store._wait_for_fuses(self.cid, timeout=5))
            self.assertLess(time.time() - t0, 1)
        store._FUSE_OWED.discard(self.cid)


if __name__ == "__main__":
    unittest.main()
