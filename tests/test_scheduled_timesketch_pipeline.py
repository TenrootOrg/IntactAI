"""Scheduled Timesketch runs go through the shared bounded pipeline (F6).

run_timesketch_pipeline took each client through KAPE, wait, export and Plaso
before starting the next, inside the APScheduler thread, and its Plaso ran
outside the start-multi limit. An offline host held the queue for the full
10,000 s monitor timeout.
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
import importlib.util  # noqa: E402

# executor.py on its own: the scheduler package's __init__ needs apscheduler.
_spec = importlib.util.spec_from_file_location(
    "scheduled_ts_executor", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                          "modules/backend/services/scheduler/executor.py"))
executor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(executor)
from services import kape_service, velociraptor_service, workflow_service, file_storage_service  # noqa: E402

NOW_US = time.time() * 1e6
H = 3600e6
FLEET = [
    {"client_id": "C.0000000000000001", "hostname": "ONLINE", "last_seen_at": NOW_US - 60e6},
    {"client_id": "C.0000000000000002", "hostname": "GONE-3D", "last_seen_at": NOW_US - 72 * H},
    {"client_id": "C.0000000000000003", "hostname": "UNKNOWN-SEEN", "last_seen_at": 0},
]


class ScheduledTimesketch(unittest.TestCase):
    def setUp(self):
        self.logs, self.statuses, self.calls = [], [], []
        self.release = threading.Event()
        self.started = threading.Event()

        def pipeline(run_id, clients, kape_args, ts_settings, monitor_timeout, cancel_event):
            self.calls.append((run_id, [c["client_id"] for c in clients], kape_args, ts_settings, monitor_timeout))
            self.started.set()
            self.release.wait(10)

        patches = [
            mock.patch.object(kape_service, "run_kape_timesketch_pipeline", pipeline),
            mock.patch.object(velociraptor_service, "get_clients_from_snapshot", lambda include_offline=False: FLEET),
            mock.patch.object(workflow_service, "create_automation_run", lambda **kw: "run-%d" % len(self.calls)),
            mock.patch.object(workflow_service, "add_log_to_run", lambda rid, m, l="info": self.logs.append((rid, l, m))),
            mock.patch.object(workflow_service, "update_run_status", lambda rid, st, **k: self.statuses.append(st)),
            mock.patch.object(workflow_service, "register_cancel_event", lambda rid: threading.Event()),
            mock.patch.object(file_storage_service, "get_timesketch_blueprint",
                              lambda bid: {"name": "BP", "settings": {"collection_timeout": 777}}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.release.set)
        self.addCleanup(executor._TIMESKETCH_ACTIVE.clear)

    def fire(self, job_id="job-1"):
        executor.run_timesketch_pipeline({"id": job_id, "name": "Nightly", "blueprint_id": "bp"},
                                         [c["client_id"] for c in FLEET])

    def test_offline_clients_are_skipped_and_the_rest_share_the_bounded_pipeline(self):
        t0 = time.monotonic()
        self.fire()
        self.assertLess(time.monotonic() - t0, 1.0)            # not in the scheduler thread
        self.assertTrue(self.started.wait(5))

        self.assertEqual(len(self.calls), 1)                   # ONE run, not one per client
        run_id, cids, kape_args, ts_settings, monitor_timeout = self.calls[0]
        self.assertEqual(cids, ["C.0000000000000001", "C.0000000000000003"])   # unknown last-seen kept
        self.assertEqual(monitor_timeout, 777)
        self.assertEqual(kape_args["timeout_seconds"], 777)
        self.assertNotIn("client_name", ts_settings)
        skip = [m for _, l, m in self.logs if "Skipped 1 client" in m]
        self.assertTrue(skip, self.logs)
        self.assertIn("GONE-3D", skip[0])
        self.assertIn("TIMESKETCH_OFFLINE_SKIP_HOURS", skip[0])

    def test_a_firing_while_the_previous_run_is_still_going_is_skipped_visibly(self):
        self.fire()
        self.assertTrue(self.started.wait(5))
        self.fire()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(any("skipped: this run is still in progress" in m for _, _, m in self.logs))

    def test_skip_threshold_zero_never_skips(self):
        with mock.patch("config.TIMESKETCH_OFFLINE_SKIP_HOURS", 0):
            self.fire()
        self.assertTrue(self.started.wait(5))
        self.assertEqual(len(self.calls[0][1]), 3)


if __name__ == "__main__":
    unittest.main()
