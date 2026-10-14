"""The workflow service's in-memory per-run state does not grow forever.

`jobs` (flow id -> Timesketch hand-off) and the per-run lock registry each gained
one entry per run or flow and never lost one -- at fleet scale, a slow leak for
the life of the backend (fleet-scale audit, "in-memory dicts never pruned").

Real SQLite in a temp dir, created by init_storage().
"""

import gc
import os
import sys
import tempfile
import threading
import time
import unittest

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-wfmem-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import init_storage  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402


class Jobs(unittest.TestCase):

    def test_a_finished_runs_flow_jobs_are_dropped(self):
        for status in ("completed", "failed", "cancelled"):
            with self.subTest(status=status):
                rid = ws.create_automation_run("timesketch", "t", case_id="c1")
                other = ws.create_automation_run("timesketch", "t", case_id="c1")
                ws.add_job("F.1", {"run_id": rid})
                ws.add_job("F.2", {"run_id": rid})
                ws.add_job("F.3", {"run_id": other})
                ws.update_run_status(rid, "running")
                self.assertIn("F.1", ws.get_jobs(), "still running: kept")
                ws.update_run_status(rid, status)
                self.assertNotIn("F.1", ws.get_jobs())
                self.assertNotIn("F.2", ws.get_jobs())
                self.assertIn("F.3", ws.get_jobs(), "another run's job is untouched")
                ws.get_jobs().clear()


class Locks(unittest.TestCase):

    def test_the_registry_empties_once_nobody_holds_a_lock(self):
        rids = [ws.create_automation_run("maintenance", "m") for _ in range(50)]
        for rid in rids:
            ws.update_run_status(rid, "running")
            ws.mutate_run_details(rid, lambda d: d.update(x=1))
        gc.collect()
        self.assertEqual(len(ws._RUN_LOG_LOCKS), 0)

    def test_it_still_excludes_while_held_and_while_waited_on(self):
        """The point of the lock: a holder and a waiter must see the SAME lock,
        even though nothing but them references it."""
        inside, overlap = [0], [False]

        def critical():
            with ws._get_run_log_lock("same_run"):
                inside[0] += 1
                if inside[0] > 1:
                    overlap[0] = True
                time.sleep(0.01)
                inside[0] -= 1
        threads = [threading.Thread(target=critical) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(overlap[0])

    def test_no_lost_details_update_under_contention(self):
        rid = ws.create_automation_run("maintenance", "m")

        def bump():
            for _ in range(20):
                ws.mutate_run_details(rid, lambda d: d.__setitem__("n", d.get("n", 0) + 1))
        threads = [threading.Thread(target=bump) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(ws.get_automation_run(rid)["details"]["n"], 160)


if __name__ == "__main__":
    unittest.main()
