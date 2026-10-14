"""Memory and Timesketch work goes one after another, never side by side.

Operator decision 2026-10-14: one memory run and one Timesketch run at a time;
a run may cover many hosts, taken one after another. Executed, not asserted
about: the real pipeline / scheduler code runs with Velociraptor, Plaso,
VolWeb and the workflow store faked out.
"""
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import kape_service as ks  # noqa: E402
from services import kape_upload_service as kus  # noqa: E402
from services import workflow_service  # noqa: E402
from services.memory import pipeline as pm  # noqa: E402
from services.storage import blueprint_store  # noqa: E402
import importlib.util  # noqa: E402

# executor.py on its own: the scheduler package's __init__ needs apscheduler.
_spec = importlib.util.spec_from_file_location(
    "one_after_another_executor", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                               "modules/backend/services/scheduler/executor.py"))
executor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(executor)


def _wait(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


class Timesketch(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, True)
        self.lock = threading.Lock()
        self.logs, self.status, self.events = [], {}, []
        self.in_flight, self.peak_in_flight = 0, 0
        self.hold = {}                       # run_id -> Event the fake upload waits on

        def dispatch(cid, **_k):
            with self.lock:
                self.in_flight += 1
                self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
                self.events.append(("kape", cid))
            return "F." + cid[2:]

        def export(cid, fid, path, logger=None):
            open(path, "w").close()
            with self.lock:
                self.in_flight -= 1          # this host's collection has left Velociraptor
            return True

        def upload(zip_path, original_filename, settings, run_id=None, cleanup_zip=True,
                   suppress_status_writes=False, on_plaso_done=None):
            os.remove(zip_path)
            on_plaso_done()
            self.hold.get(run_id, threading.Event()).wait(10) if run_id in self.hold else None
            return {"status": "completed", "sketch_id": 1, "timeline_id": 2}

        for name, value in {
            "PLASO_OUTPUT_DIR": self.out,
            "TIMESKETCH_EXPORT_MIN_FREE_GB": 0,
            "add_log_to_run": lambda rid, m, l="info": self.logs.append((rid, m)),
            "update_run_status": lambda rid, st, **k: self.status.__setitem__(rid, st),
            "add_job": lambda *a, **k: None,
            "update_job": lambda *a, **k: None,
            "unregister_cancel": lambda rid: None,
            "cleanup_flow_export": lambda *a, **k: None,
            "run_kape_collection_grpc": dispatch,
            "monitor_flow_completion": lambda *a, **k: "FINISHED",
            "export_flow_to_zip": export,
        }.items():
            p = mock.patch.object(ks, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(kus, "process_kape_upload", upload)
        p.start()
        self.addCleanup(p.stop)

    def run_pipeline(self, run_id, hosts, cancel=None):
        clients = [{"client_id": f"C.{run_id[-1]}{i:015x}", "client_name": f"{run_id}-H{i}"} for i in range(hosts)]
        ks.run_kape_timesketch_pipeline(run_id, clients, {"kape_target": "_KapeTriage"},
                                        {"sketch_name": "S"}, 100, cancel or threading.Event())

    def test_hosts_inside_a_run_collect_one_after_another_by_default(self):
        self.assertEqual(ks.TIMESKETCH_MAX_COLLECTORS, 1)
        self.run_pipeline("run-1", 12)
        self.assertEqual(self.peak_in_flight, 1)       # KAPE was not started on every host up front
        self.assertEqual(len([e for e in self.events if e[0] == "kape"]), 12)
        self.assertEqual(self.status["run-1"], "completed")

    def test_a_second_run_waits_until_the_first_has_finished(self):
        self.hold["run-a"] = threading.Event()
        a = threading.Thread(target=self.run_pipeline, args=("run-a", 2))
        a.start()
        self.assertTrue(_wait(lambda: len(self.events) == 2))
        b = threading.Thread(target=self.run_pipeline, args=("run-b", 2))
        b.start()
        self.assertTrue(_wait(lambda: any(r == "run-b" and m.startswith("Queued") for r, m in self.logs)))
        self.assertEqual(len(self.events), 2)          # run-b started nothing while queued
        self.hold["run-a"].set()
        a.join(10)
        b.join(10)
        self.assertEqual(self.status, {"run-a": "completed", "run-b": "completed"})
        self.assertEqual(len(self.events), 4)

    def test_a_queued_run_can_be_stopped_before_it_starts_anything(self):
        stop = threading.Event()
        with ks._ONE_TIMESKETCH_RUN:                    # another run is in progress
            t = threading.Thread(target=self.run_pipeline, args=("run-q", 3, stop))
            t.start()
            self.assertTrue(_wait(lambda: any(m.startswith("Queued") for _r, m in self.logs)))
            stop.set()
            t.join(10)
        self.assertEqual(self.status["run-q"], "cancelled")
        self.assertEqual(self.events, [])


class ScheduledMemory(unittest.TestCase):
    def setUp(self):
        self.lock = threading.Lock()
        self.calls, self.status, self.logs = [], {}, []
        self.live, self.peak = 0, 0
        self.n = 0
        self.stop = threading.Event()
        self.during = None                    # called inside the fake pipeline

        def create(**kw):
            with self.lock:
                self.n += 1
                return f"{kw['automation_type']}-{self.n}"

        def status(rid, st, **_k):
            self.status.setdefault(rid, []).append(st)

        def pipeline(run_id, client_id, **_k):
            with self.lock:
                self.live += 1
                self.peak = max(self.peak, self.live)
                self.calls.append((run_id, client_id))
            if self.during:
                self.during(client_id)
            time.sleep(0.02)
            with self.lock:
                self.live -= 1

        for target, name, value in (
                (workflow_service, "create_automation_run", create),
                (workflow_service, "update_run_status", status),
                (workflow_service, "add_log_to_run", lambda rid, m, l="info": self.logs.append((rid, m))),
                (workflow_service, "register_cancel_event", lambda rid: self.stop),
                (workflow_service, "unregister_cancel", lambda rid: None),
                (pm, "run_memory_pipeline", pipeline),
                (blueprint_store, "get_memory_blueprint", lambda _id: None)):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)

    def batch_status(self):
        return self.status.get("memory_batch-1", [])

    def test_hosts_are_captured_one_after_another_each_in_its_own_run(self):
        executor.run_memory_scheduled({"id": "job", "name": "Nightly"}, ["C.1", "C.2", "C.3", "C.4"])
        self.assertTrue(_wait(lambda: "completed" in self.batch_status()))
        self.assertEqual(self.peak, 1)
        self.assertEqual([c for _r, c in self.calls], ["C.1", "C.2", "C.3", "C.4"])
        self.assertEqual(len({r for r, _c in self.calls}), 4)
        self.assertTrue(all(r.startswith("memory-") for r, _c in self.calls))

    def test_stopping_the_batch_stops_after_the_current_host(self):
        self.during = lambda cid: self.stop.set() if cid == "C.2" else None
        executor.run_memory_scheduled({"id": "job", "name": "Nightly"}, ["C.1", "C.2", "C.3", "C.4"])
        self.assertTrue(_wait(lambda: "cancelled" in self.batch_status()))
        self.assertEqual([c for _r, c in self.calls], ["C.1", "C.2"])
        st = self.batch_status()
        self.assertNotIn("running", st[st.index("cancelled"):])   # not flipped back after the stop


class MemoryLimit(unittest.TestCase):
    def test_one_memory_run_at_a_time_by_default(self):
        self.assertEqual(pm.MAX_CONCURRENT_RUNS_DEFAULT, 1)

    def test_a_long_wait_keeps_saying_it_is_queued(self):
        """The orphan sweep fails a run silent for 10 h; a queued run says so once an hour."""
        logs, clock = [], {"t": 0.0}

        def fake_time():
            clock["t"] += 1801.0                 # each check is half an hour later
            return clock["t"]

        with mock.patch.object(pm, "_max_concurrent_runs", lambda: 1), \
                mock.patch.object(pm, "_runs_active", 1), \
                mock.patch.object(pm.time, "time", fake_time), \
                mock.patch.object(pm._RUN_SLOTS, "wait", lambda timeout=None: None):
            with self.assertRaises(RuntimeError):
                pm._take_run_slot(lambda: len(logs) >= 3, lambda m, l="info": logs.append(m))
        self.assertEqual(len(logs), 3)
        self.assertTrue(all("queued" in m for m in logs))


if __name__ == "__main__":
    unittest.main()
