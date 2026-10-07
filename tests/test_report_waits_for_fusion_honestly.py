"""A report that is waiting for a fuse says so -- not "the model has not answered".

2026-10-07, a migrated appliance with NO AI configured: a hunt brought 233k
rows, the case re-fused for 15+ minutes, and every Regenerate waited on that
fuse while the Log said "the plan's default model (claude) has not answered for
4 min". No model was being called. The report now records which step it is on
(waiting_for_fusion -> preparing -> narrative | writing) and the watchdog
speaks to that step; a fuse wait is never written off as a stuck model call.
"""
import os
import sys
import threading
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

FUSING = "Refusion · building case graph"


def watch(phase, seconds=1.2):
    """The real watchdog for `seconds` (heartbeat 0.05 s, stuck after 0.6 s)."""
    logged, retired = [], []
    case = {"report_generating_started_at": "2026-10-07T06:42:51", "report_phase": phase,
            "activity_log": [{"action": FUSING}, {"action": "Regenerate report"}]}
    stop = threading.Event()
    with mock.patch.object(store, "_watchdog_limits", lambda: (0.05, 0.6)), \
            mock.patch.object(store, "get_case", lambda cid: case), \
            mock.patch.object(store, "seconds_since", lambda _s: 0.0), \
            mock.patch.object(store, "log_case_event", lambda cid, a, s, d="": logged.append((a, d))), \
            mock.patch.object(store, "_retire_generation", lambda *a, **k: retired.append(a[1])):
        t = threading.Thread(target=store._report_watchdog,
                             args=("c1", "the plan's default model (claude)", stop), daemon=True)
        t.start()
        t.join(seconds)
        stop.set()
        t.join(1)
    return logged, retired


class TheWatchdogNamesTheRealWait(unittest.TestCase):
    def test_a_fuse_wait_is_logged_as_one_and_never_written_off(self):
        logged, retired = watch("waiting_for_fusion")
        titles = {a for a, _ in logged}
        self.assertEqual(titles, {"Report · waiting for the case fusion"})
        self.assertIn(FUSING, logged[0][1])                 # names where the fuse is
        self.assertEqual(retired, [])                       # 1.2 s > the 0.6 s stuck limit
        self.assertFalse(any("claude" in d for _, d in logged))

    def test_with_no_ai_it_says_it_is_writing_the_offline_report(self):
        logged, _ = watch("writing", seconds=0.4)
        self.assertTrue(logged)
        self.assertTrue(all(a == "Report · still writing" for a, _ in logged))
        self.assertFalse(any("claude" in d or "model" in a for a, d in logged))

    def test_a_real_model_call_still_reports_the_model_and_is_written_off(self):
        logged, retired = watch("narrative")
        self.assertIn("Report · still waiting on the model", {a for a, _ in logged})
        self.assertEqual(retired, ["Report · written off as stuck"])


class TheReportRecordsItsSteps(unittest.TestCase):
    def test_it_is_waiting_for_fusion_while_it_waits_then_preparing(self):
        steps = []

        class Stop(Exception):
            pass

        def boom(_cid):
            raise Stop()
        with mock.patch.object(store, "_set_report_phase", lambda cid, gid, ph: steps.append(ph)), \
                mock.patch.object(store, "_wait_for_fuses", lambda cid: steps.append("<fuse wait>") or True), \
                mock.patch.object(store, "get_case", boom):   # stop right after the waits
            with self.assertRaises(Stop):
                store.regenerate_report("c1", use_llm=True, gen_id="g1")
        self.assertEqual(steps, ["waiting_for_fusion", "<fuse wait>", "preparing"])


if __name__ == "__main__":
    unittest.main()
