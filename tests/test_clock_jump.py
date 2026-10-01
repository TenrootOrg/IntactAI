"""A paused machine must not time out a report call.

Seen on the appliance (a VM): a report call went out at 19:30, the VM was paused
overnight, and on resume at 07:19 the wall clock had jumped 12 hours. The call's
deadline and the stuck-run watchdog both measured on the wall clock, so the run was
ended with "took too long" in the first second after waking -- and the model's
answer, which arrived a minute later, was discarded. Durations are now counted on
the monotonic clock, which does not advance while the machine is not running.
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim, store  # noqa: E402

REAL_TIME = time.time
TWELVE_HOURS = 12 * 3600


class Deadline(unittest.TestCase):
    def test_a_wall_clock_jump_does_not_end_a_call_that_is_still_inside_its_time(self):
        calls = []

        def jumped():                               # the first read is "now"; every later one is 12 h on
            calls.append(1)
            return REAL_TIME() + (TWELVE_HOURS if len(calls) > 1 else 0)
        with mock.patch.object(llm_sim.time, "time", jumped), \
                mock.patch.object(llm_sim, "_hedge_seconds", lambda: 0):
            out = llm_sim._with_deadline(lambda: (time.sleep(0.2), "the answer")[1], 30, "test")
        self.assertEqual(out, "the answer")

    def test_a_call_that_really_is_too_slow_still_times_out(self):
        with mock.patch.object(llm_sim, "_hedge_seconds", lambda: 0):
            with self.assertRaises(llm_sim.LLMUnavailable):
                llm_sim._with_deadline(lambda: time.sleep(2), 0.2, "test")


class Watchdog(unittest.TestCase):
    def run_it(self, seconds, since_age):
        """The watchdog for `seconds`, with the stored stamp reading `since_age(n)` old."""
        retired, n = [], [0]

        def age(_):
            n[0] += 1
            return since_age(n[0])
        stop = threading.Event()
        with mock.patch.object(store, "_watchdog_limits", lambda: (0.05, 0.6)), \
                mock.patch.object(store, "get_case", lambda cid: {"report_generating_started_at": "2026-09-30T19:30:08"}), \
                mock.patch.object(store, "seconds_since", age), \
                mock.patch.object(store, "log_case_event", lambda *a, **k: None), \
                mock.patch.object(store, "_retire_generation", lambda *a, **k: retired.append(a[1])):
            t = threading.Thread(target=store._report_watchdog, args=("c1", "model", stop), daemon=True)
            t.start()
            t.join(seconds)
            stop.set()
            t.join(1)
        return retired

    def test_a_stamp_that_suddenly_reads_twelve_hours_old_is_not_a_stuck_run(self):
        # The wall clock jumped; 0.3 s of real time passed. Not stuck.
        self.assertEqual(self.run_it(0.3, lambda n: TWELVE_HOURS), [])

    def test_real_silence_is_still_written_off(self):
        self.assertEqual(self.run_it(1.5, lambda n: 0.0), ["Report · written off as stuck"])


if __name__ == "__main__":
    unittest.main()
