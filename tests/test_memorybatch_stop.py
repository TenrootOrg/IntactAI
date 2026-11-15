"""Stop on a scheduled memory batch also stops the host being captured, and no
further host starts.

Stop flipped only the batch row to 'cancelled': the current host's memory run
kept acquiring and analysing for up to an hour, and its row had to be found and
stopped by hand (D4). Uses the real cancel/cleanup/request_stop machinery with
the run store stubbed.
"""
import os
import sys
import threading
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import importlib.util  # noqa: E402

# executor.py on its own: the scheduler package's __init__ needs apscheduler.
_spec = importlib.util.spec_from_file_location(
    "memorybatch_executor", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                         "modules/backend/services/scheduler/executor.py"))
executor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(executor)
from services import workflow_service  # noqa: E402
from services.memory import pipeline as memory_pipeline  # noqa: E402
from services.storage import blueprint_store  # noqa: E402


class MemoryBatchStop(unittest.TestCase):
    def setUp(self):
        self.status, self.logs, self.started, self.ids = {}, [], [], []
        self.capturing = threading.Event()
        self.child_done = threading.Event()

        def create(**kw):
            rid = "%s_%d" % (kw["automation_type"], len(self.ids))
            self.ids.append(rid)
            self.status[rid] = "pending"
            return rid

        def update(rid, st, **kw):
            if self.status.get(rid) == "cancelled":     # cancelled is terminal, as in the real store
                return False
            self.status[rid] = st
            return True

        def pipeline(run_id, client_id, **kw):
            self.started.append(client_id)
            ev = workflow_service.register_cancel_event(run_id)
            self.capturing.set()
            ev.wait(5)                                  # a capture runs until its run is stopped
            self.child_done.set()

        patches = [
            mock.patch.object(workflow_service, "create_automation_run", create),
            mock.patch.object(workflow_service, "update_run_status", update),
            mock.patch.object(workflow_service, "add_log_to_run",
                              lambda rid, m, l="info", force=False: self.logs.append((rid, m))),
            mock.patch.object(workflow_service, "file_get_workflow",
                              lambda rid, with_logs=False: {"status": self.status.get(rid)}),
            mock.patch.object(memory_pipeline, "run_memory_pipeline", pipeline),
            mock.patch.object(blueprint_store, "get_memory_blueprint", lambda bid: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_stop_stops_the_current_host_and_starts_no_other(self):
        executor.run_memory_scheduled({"id": "job-1", "name": "Nightly"}, ["C.1", "C.2", "C.3"])
        self.assertTrue(self.capturing.wait(5))
        batch, child = self.ids[0], self.ids[1]

        workflow_service.request_stop(batch)

        self.assertTrue(self.child_done.wait(2), "the host's capture was not told to stop")
        self.assertEqual("cancelled", self.status[child])
        self.assertEqual("cancelled", self.status[batch])
        # The batch thread exits (unregisters) without starting C.2.
        for _ in range(100):
            if batch not in workflow_service._cancel_events:
                break
            threading.Event().wait(0.02)
        self.assertEqual(["C.1"], self.started)
        self.assertEqual(2, len(self.ids))
        self.assertTrue(any(rid == batch and "stopping host 1/3" in m and "2 host(s) not started" in m
                            for rid, m in self.logs), self.logs)


if __name__ == "__main__":
    unittest.main()
