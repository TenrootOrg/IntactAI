"""A Stop stays a Stop (QA items A4, D1, D2, implicit-state-machines 2026-11-09).

  A4  save_workflow overwrote status blindly, so any unlocked read-modify-save
      that read the run just before a Stop wrote it back as 'running'.
  D1  the agentic _update_phase tick (every collection poll) was such a save.

Real workflow_service + SQLite in a temp dir. D2 is test_lifecycle2_stream_stop.py
(its harness replaces services.* in sys.modules, so it needs its own process).
"""
import os
import sys
import tempfile
import unittest

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-lc2-")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), "modules", "backend"), HERE]

import _optional_deps  # noqa: F401,E402
from services.storage import delete_workflow, get_workflow, init_storage, save_workflow  # noqa: E402

init_storage()
from services import workflow_service as ws  # noqa: E402
from services.agentic.pipeline._helpers import _update_phase  # noqa: E402


def _wf(status, rid="r1", **extra):
    delete_workflow(rid)
    ws.unregister_cancel(rid)
    save_workflow({"run_id": rid, "status": status,
                   "automation_type": "agentic_pipeline", "logs": [], **extra})
    return rid


class CancelledSticksInStorage(unittest.TestCase):

    def test_stale_save_after_stop_keeps_cancelled_and_reason(self):
        _wf("running")
        stale = get_workflow("r1", with_logs=False)
        ws.request_stop("r1", reason="Watchdog: over budget")
        stale["progress"] = 42
        save_workflow(stale)
        row = get_workflow("r1", with_logs=False)
        self.assertEqual(row["status"], "cancelled")
        self.assertEqual(row["error"], "Watchdog: over budget")
        self.assertEqual(row["progress"], 42)   # the rest of the save still lands

    def test_cancelled_to_cancelled_and_normal_moves_still_write(self):
        _wf("cancelled")
        save_workflow({**get_workflow("r1", with_logs=False), "error": "new reason"})
        self.assertEqual(get_workflow("r1")["error"], "new reason")
        _wf("running")
        save_workflow({**get_workflow("r1", with_logs=False), "status": "completed"})
        self.assertEqual(get_workflow("r1")["status"], "completed")
        # A deleted-and-recreated row is a fresh insert, not an overwrite.
        _wf("cancelled")
        _wf("pending")
        self.assertEqual(get_workflow("r1")["status"], "pending")


class PhaseTickNeverReopens(unittest.TestCase):

    def test_tick_on_a_running_run_updates_phase(self):
        _wf("running")
        _update_phase("r1", "collecting", 30)
        row = get_workflow("r1")
        self.assertEqual((row["status"], row["phase"], row["progress"]),
                         ("running", "collecting", 30))

    def test_tick_after_stop_or_finish_writes_nothing(self):
        for end in ("cancelled", "completed", "failed"):
            _wf(end, phase="x", progress=7)
            _update_phase("r1", "collecting", 30)
            row = get_workflow("r1")
            with self.subTest(end=end):
                self.assertEqual((row["status"], row["phase"], row["progress"]),
                                 (end, "x", 7))


if __name__ == "__main__":
    unittest.main()
