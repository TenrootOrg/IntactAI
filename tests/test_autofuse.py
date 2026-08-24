"""The debounced auto-fuse: what it must do, and everything it must not.

A fuse rebuilds the whole case graph — measured on a live appliance at 29s for
one 9-host capture, 53s for two — because its cost is O(all data in the case).
Anything that fuses per landing run would turn a 20-host hunt into twenty full
rebuilds. So the whole design is a debounce, and almost every rule below exists
to stop the automatic path doing damage the manual one cannot:

  - it must never call the model (that is billed, and it rewrites the narrative
    an analyst is reading);
  - it must never drop data on a collision — the previous background path used
    `except: pass` and a fuse could vanish, leaving the graph stale with nothing
    in the log;
  - it must stop the moment an operator opts out, or the case is deleted;
  - it must be a no-op when there is nothing new, so a stray timer costs nothing.

autofuse imports its collaborators lazily through _store(), so the REAL module
runs here against a fake store with no backend import. Timings are module-level
and reduced to milliseconds, so these drive real threading.Timer objects rather
than mocking the clock — the concurrency is genuinely exercised.
"""

import os
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules/backend/services/fusion"))

import autofuse  # noqa: E402 — near-leaf by design; see its docstring


class FusionBusy(RuntimeError):
    pass


class FakeStore:
    """Stands in for services.fusion.store. Records everything, so a test can
    assert on what was NOT done as easily as what was."""

    FusionBusy = FusionBusy
    TRIGGER_AUTOMATIC_RUN_LANDED = "AUTOMATIC — a member run finished"
    CASE_TYPE = "case"

    def __init__(self, case=None, stale=None):
        # store.get_case returns {} for "no such case" (see its early return), so a
        # REAL case always carries details. A fake handing back {} would be claiming
        # the case was deleted, which is a different test.
        self.case = {"name": "QA case"} if case is None else case
        self._stale = ["run_1"] if stale is None else stale
        self._per_case = {}
        self.all_runs = []
        self.merges = []
        self.fuses = []          # kwargs of every fuse_case call
        self.events = []         # (action, status, detail)
        self.busy_times = 0      # raise FusionBusy this many times, then succeed
        self.raise_always = None
        self.lock = threading.Lock()

    def get_case(self, cid):
        return self.case

    # --- what catch_up() reaches for --------------------------------------
    def _ws(self):
        return self

    def get_all_automation_runs(self):
        return list(self.all_runs)

    def _stale_for(self, cid):
        # Staleness is PER CASE in the real store; sharing one list here let one
        # case's fuse silently satisfy another's, which looked like a scheduler bug.
        return self._per_case.setdefault(cid, list(self._stale))

    def stale_member_runs(self, cid, d=None):
        return list(self._stale_for(cid))

    def fuse_case(self, cid, **kw):
        with self.lock:
            self.fuses.append(kw)
            if self.raise_always:
                raise self.raise_always
            if self.busy_times > 0:
                self.busy_times -= 1
                raise FusionBusy("a fuse is already running for this case")
            self._per_case[cid] = []          # a real fuse clears THIS case
        return object()

    def _merge_case_details(self, cid, patch):
        with self.lock:
            self.case.update(patch)
            self.merges.append(dict(patch))

    def log_case_event(self, cid, action, status="ok", detail="", **kw):
        with self.lock:
            self.events.append((action, status, detail))

    def actions(self):
        return [a for a, _s, _d in self.events]


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        autofuse._store = lambda: self.store
        # real timers, just fast ones
        self._orig = (autofuse.QUIET_SECONDS, autofuse.BUSY_RETRY_SECONDS,
                      autofuse.MAX_BUSY_RETRIES)
        autofuse.QUIET_SECONDS = 0.05
        autofuse.BUSY_RETRY_SECONDS = 0.02
        for cid in list(autofuse._TIMERS):
            autofuse.cancel(cid)

    def tearDown(self):
        for cid in list(autofuse._TIMERS):
            autofuse.cancel(cid)
        (autofuse.QUIET_SECONDS, autofuse.BUSY_RETRY_SECONDS,
         autofuse.MAX_BUSY_RETRIES) = self._orig

    def settle(self, seconds=2.0):
        """Wait for quiescence: no timer pending AND no new fuse/log for a beat.

        Watching _TIMERS alone races — _fire() removes its timer BEFORE calling the
        store, so the registry can be empty while the fuse is still being recorded.
        """
        deadline = time.time() + seconds
        stable = 0
        last = None
        while time.time() < deadline:
            now = (len(autofuse._TIMERS), len(self.store.fuses), len(self.store.events))
            if now == last and not autofuse._TIMERS:
                stable += 1
                if stable >= 5:
                    return
            else:
                stable = 0
            last = now
            time.sleep(0.02)


class TestItFusesOnce(_Base):

    def test_a_landing_run_eventually_fuses(self):
        autofuse.schedule("case_1", "run finished")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_it_does_not_fuse_before_the_quiet_period(self):
        """Arming must not fuse inline — schedule() is called under a lock."""
        autofuse.schedule("case_1")
        self.assertEqual(self.store.fuses, [])

    def test_twenty_runs_landing_together_produce_one_fuse(self):
        """The reason this is a debounce at all: a 20-host hunt."""
        for i in range(20):
            autofuse.schedule("case_1", "run %d" % i)
            time.sleep(0.005)          # they trickle in, as a real hunt does
        self.settle()
        self.assertEqual(len(self.store.fuses), 1,
                         "each landing run must re-arm, not queue another fuse")

    def test_a_later_run_extends_the_wait(self):
        autofuse.schedule("case_1")
        time.sleep(0.03)
        autofuse.schedule("case_1")     # re-arms the full quiet period
        time.sleep(0.03)
        self.assertEqual(self.store.fuses, [], "the timer should have been re-armed")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_separate_cases_do_not_share_a_timer(self):
        autofuse.schedule("case_1")
        autofuse.schedule("case_2")
        self.settle()
        self.assertEqual(len(self.store.fuses), 2)

    def test_scheduling_reports_whether_it_armed(self):
        self.assertTrue(autofuse.schedule("case_1"))
        self.assertFalse(autofuse.schedule(None), "no case, nothing to arm")
        self.assertFalse(autofuse.schedule(""))


class TestItNeverCallsTheModel(_Base):

    def test_the_fuse_forbids_the_llm(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses[0].get("allow_llm"), False,
                         "an automatic fuse must never be billed or rewrite the narrative")

    def test_it_does_not_force_a_report_rebuild(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertNotEqual(self.store.fuses[0].get("force_report"), True)

    def test_it_labels_itself_automatic(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertIn("AUTOMATIC", self.store.fuses[0].get("trigger", ""))


class TestItIsANoOpWhenNothingIsNew(_Base):

    def test_nothing_stale_means_no_fuse(self):
        self.store._stale = []; self.store._per_case.clear()
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "someone already fused it — do not rebuild for nothing")

    def test_a_deleted_case_is_not_fused(self):
        self.store.case = {}          # store.get_case's "no such case" answer
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_no_log_noise_when_there_is_nothing_to_do(self):
        self.store._stale = []; self.store._per_case.clear()
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.events, [],
                         "a quiet no-op must not write to the case activity log")


class TestTheOperatorCanStopIt(_Base):

    def test_an_explicit_opt_out_prevents_the_fuse(self):
        self.store.case = {"name": "QA case", "auto_fuse": False}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_absent_reads_as_on(self):
        """Off-by-default would mean the feature does nothing until every existing
        case is visited and ticked."""
        self.store.case = {"name": "QA case"}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_explicit_true_is_on(self):
        self.store.case = {"name": "QA case", "auto_fuse": True}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_cancel_stops_a_pending_fuse(self):
        autofuse.schedule("case_1")
        self.assertTrue(autofuse.pending("case_1"))
        self.assertTrue(autofuse.cancel("case_1"))
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_cancelling_nothing_is_harmless(self):
        self.assertFalse(autofuse.cancel("case_never_scheduled"))

    def test_cancel_only_affects_the_named_case(self):
        autofuse.schedule("case_1")
        autofuse.schedule("case_2")
        autofuse.cancel("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)


class TestCollisionsAreNeverDropped(_Base):
    """The previous background path swallowed FusionBusy with `except: pass`, so
    an automatic fuse could vanish and leave the graph stale with no explanation."""

    def test_a_busy_case_is_retried(self):
        self.store.busy_times = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertEqual(len(self.store.fuses), 2, "it must try again, not give up")
        self.assertEqual(self.store._stale_for("case_1"), [],
                         "the retry must actually have fused")

    def test_the_deferral_is_recorded(self):
        self.store.busy_times = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertIn("Refusion deferred", self.store.actions())

    def test_it_gives_up_after_a_bounded_number_of_tries(self):
        autofuse.MAX_BUSY_RETRIES = 3
        self.store.busy_times = 99
        autofuse.schedule("case_1")
        self.settle(3.0)
        self.assertEqual(len(self.store.fuses), 3, "retries must be bounded")
        self.assertIn("Refusion skipped", self.store.actions())

    def test_giving_up_says_what_to_do(self):
        autofuse.MAX_BUSY_RETRIES = 2
        self.store.busy_times = 99
        autofuse.schedule("case_1")
        self.settle(3.0)
        detail = [d for a, _s, d in self.store.events if a == "Refusion skipped"]
        self.assertTrue(detail and "Refusion" in detail[0],
                        "the operator must be told a manual Refusion is needed")


class TestFailuresAreLoggedNotSwallowed(_Base):

    def test_a_fuse_error_is_recorded(self):
        self.store.raise_always = RuntimeError("disk full")
        autofuse.schedule("case_1")
        self.settle()
        self.assertIn("Refusion failed", self.store.actions())
        self.assertTrue(any("disk full" in d for _a, _s, d in self.store.events))

    def test_a_fuse_error_does_not_kill_the_scheduler(self):
        self.store.raise_always = RuntimeError("boom")
        autofuse.schedule("case_1")
        self.settle()
        self.store.raise_always = None
        autofuse.schedule("case_2")
        self.settle()
        self.assertEqual(len(self.store.fuses), 2)

    def test_a_broken_store_does_not_raise_out_of_the_timer(self):
        """A timer thread dying with a traceback helps nobody."""
        class Exploding:
            FusionBusy = FusionBusy
            TRIGGER_AUTOMATIC_RUN_LANDED = "x"
            def get_case(self, cid):
                raise RuntimeError("database gone")
            def log_case_event(self, *a, **k):
                raise RuntimeError("log gone too")
        autofuse._store = lambda: Exploding()
        autofuse.schedule("case_1")
        self.settle()      # the assertion is simply that nothing propagated


class TestBookkeeping(_Base):

    def test_the_timer_is_forgotten_once_it_fires(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertFalse(autofuse.pending("case_1"),
                         "a fired timer must not leak into the registry")

    def test_re_arming_does_not_leak_timers(self):
        for _ in range(50):
            autofuse.schedule("case_1")
        self.assertEqual(len(autofuse._TIMERS), 1)
        self.settle()
        self.assertEqual(len(autofuse._TIMERS), 0)

    def test_timers_are_daemon_threads(self):
        """A pending auto-fuse must never hold up a backend shutdown."""
        autofuse.schedule("case_1", delay=5)
        t = autofuse._TIMERS["case_1"]
        self.assertTrue(t.daemon)
        autofuse.cancel("case_1")

    def test_concurrent_scheduling_is_safe(self):
        """update_run_status can fire from many worker threads at once."""
        threads = [threading.Thread(target=autofuse.schedule, args=("case_1",))
                   for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertLessEqual(len(autofuse._TIMERS), 1)
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)


class TestCrashLoopBreaker(_Base):
    """A fuse can die where no `except` will ever see it: a big case OOMs the
    process (measured — five 547 MB member runs peaked at 5.6 GB and the kernel
    killed it). Automatic retry then becomes fuse-die-restart-fuse-die."""

    def test_a_flag_is_set_before_the_fuse_and_cleared_after(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual([m.get("auto_fuse_incomplete") for m in self.store.merges],
                         [True, False],
                         "the marker must be written BEFORE the fuse and cleared after")

    def test_a_case_left_marked_is_not_retried(self):
        """This is the loop being broken."""
        self.store.case = {"name": "QA case", "auto_fuse_incomplete": True}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "a case whose last automatic fuse vanished must stand down")

    def test_standing_down_tells_the_operator_what_to_do(self):
        self.store.case = {"name": "QA case", "auto_fuse_incomplete": True}
        autofuse.schedule("case_1")
        self.settle()
        detail = [d for a, _s, d in self.store.events if a == "Refusion skipped"]
        self.assertTrue(detail and "Refusion" in detail[0],
                        "it must point at the manual path, not just go quiet")

    def test_a_busy_collision_does_not_leave_the_case_marked(self):
        """Nothing was attempted, so nothing is incomplete."""
        self.store.busy_times = 99
        autofuse.MAX_BUSY_RETRIES = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertFalse(self.store.case.get("auto_fuse_incomplete"))

    def test_a_raised_failure_does_not_leave_the_case_marked(self):
        """It raised rather than vanished — the next run may as well try."""
        self.store.raise_always = RuntimeError("transient")
        autofuse.schedule("case_1")
        self.settle()
        self.assertFalse(self.store.case.get("auto_fuse_incomplete"))

    def test_catch_up_also_respects_the_marker(self):
        self.store.all_runs = [{"run_id": "case_1", "automation_type": "case",
                                "details": {"name": "c", "auto_fuse_incomplete": True}}]
        self.store.case = {"name": "c", "auto_fuse_incomplete": True}
        autofuse.catch_up(stagger=0.01)
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "a restart must not resume the fuse that caused it")


class TestStartupCatchUp(_Base):
    """Timers live in memory. Data that landed in the minute before a restart
    would otherwise wait for the NEXT run to arrive — leaving the operator to
    click, which is the manual step this feature exists to remove."""

    def _case(self, cid, **det):
        det.setdefault("name", "QA case")
        return {"run_id": cid, "automation_type": "case", "details": det}

    def test_a_case_with_unfused_data_is_armed(self):
        self.store.all_runs = [self._case("case_1")]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 1)
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_a_current_case_is_not_armed(self):
        self.store.all_runs = [self._case("case_1")]
        self.store._stale = []
        self.store._per_case.clear()
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_an_opted_out_case_is_not_armed(self):
        self.store.all_runs = [self._case("case_1", auto_fuse=False)]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_non_case_rows_are_ignored(self):
        self.store.all_runs = [{"run_id": "velociraptor_upload_1",
                                "automation_type": "velociraptor_upload", "details": {}}]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_several_cases_are_staggered_not_simultaneous(self):
        """Ten graphs rebuilding at once on a box that has just come up is worse
        than the problem being solved."""
        self.store.all_runs = [self._case("case_%d" % i) for i in range(4)]
        autofuse.catch_up(stagger=0.05)
        delays = sorted(t.interval for t in autofuse._TIMERS.values())
        self.assertEqual(len(delays), 4)
        self.assertTrue(all(b > a for a, b in zip(delays, delays[1:])),
                        "each case must be armed further out than the last: %r" % delays)
        for cid in list(autofuse._TIMERS):
            autofuse.cancel(cid)

    def test_one_broken_case_does_not_stop_the_rest(self):
        bad = {"run_id": "case_bad", "automation_type": "case", "details": None}
        self.store.all_runs = [bad, self._case("case_ok")]
        armed = autofuse.catch_up(stagger=0.01)
        self.assertGreaterEqual(armed, 1)

    def test_a_store_that_cannot_be_read_returns_zero(self):
        class Broken:
            CASE_TYPE = "case"
            def _ws(self):
                raise RuntimeError("db down")
        autofuse._store = lambda: Broken()
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_catch_up_arms_nothing_when_there_are_no_cases(self):
        self.store.all_runs = []
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
