"""Memory run states and what a Stop or a crash leaves behind.

QA D3 / A1 / A2 (implicit-state-machines, 2026-11):
  * a run waiting for a memory slot showed 'running 1%' for hours;
  * flow_id and the dump path were recorded only after the up-to-90-minute
    acquire, so a restart in it left the reaper nothing to clean;
  * the upload route's ZIP extract ran before the pipeline registered its
    cancel event, so a Stop during it was lost;
  * Stop cleanup ran on the HTTP thread and in the worker's except at once;
  * the memory Stop route turned a finished run into 'cancelled'.
Executed against the real pipeline with Velociraptor/VolWeb/the store faked.
"""
import ast
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import acquire as acq  # noqa: E402
from services.memory import pipeline as pm  # noqa: E402

GiB = 1024 ** 3
ROUTES = os.path.join(ROOT, "modules/backend/routes/memory_routes.py")


class _Client:
    def __init__(self, **_kw): pass


def _fakes(**over):
    f = {"add_log_to_run": lambda *a, **k: None,
         "update_run_status": lambda *a, **k: None,
         "mutate_run_details": lambda *a, **k: None,
         "register_cleanup": lambda *a, **k: None,
         "unregister_cancel": lambda *a, **k: None,
         "cleanup_after_run": lambda **k: None,
         "register_cancel_event": lambda rid: threading.Event(),
         "_estimate_client_memory_bytes": lambda _c: 1 * GiB,
         "VolWebClient": _Client}
    f.update(over)
    return f


def _patched(**over):
    d = tempfile.mkdtemp()
    return d, [mock.patch.multiple(pm, **_fakes(**over)),
               mock.patch.dict(os.environ, {"MEMORY_MAX_CONCURRENT_RUNS": "1"}),
               mock.patch.object(pm, "_limit_cache", [float("-inf"), 1]),
               mock.patch.object(pm.traceback, "print_exc"),
               mock.patch.object(acq.shutil, "disk_usage",
                                 return_value=mock.Mock(free=1000 * GiB))]


def _run(patches, **kw):
    for p in patches:
        p.start()
    try:
        pm.run_memory_pipeline(mode="plugin", **kw)
    finally:
        for p in reversed(patches):
            p.stop()


class WaitingRunIsPending(unittest.TestCase):
    def tearDown(self):
        self.assertEqual(pm._runs_active, 0)
        acq._DISK_RESERVED.clear()

    def test_a_run_behind_another_is_pending_then_running(self):
        statuses, lock = {}, threading.Lock()

        def status(rid, st, progress=None, **_k):
            with lock:
                statuses.setdefault(rid, []).append((st, progress))

        def fake_acquire(client_id, **kw):
            time.sleep(0.4)
            raise acq.AcquisitionError("test stops here")

        d, patches = _patched(update_run_status=status, acquire_memory_dump=fake_acquire)
        for p in patches:
            p.start()
        try:
            ts = [threading.Thread(target=pm.run_memory_pipeline,
                                   kwargs={"run_id": f"r{i}", "client_id": f"C.{i}",
                                           "mode": "plugin", "dumps_dir": d})
                  for i in range(2)]
            ts[0].start()
            time.sleep(0.1)
            ts[1].start()
            for t in ts:
                t.join(30)
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertNotIn("pending", [s for s, _ in statuses["r0"]], "r0 never waited")
        r1 = [s for s, _ in statuses["r1"]]
        self.assertIn(("pending", 0), statuses["r1"], statuses["r1"])
        self.assertIn("running", r1[r1.index("pending"):],
                      "taking the slot must set it running again")


class FlowRecordedAtDispatch(unittest.TestCase):
    def test_acquire_reports_flow_and_path_before_the_poll(self):
        order = []
        with mock.patch.multiple(
                acq,
                _client_hostname=lambda c: "HOST",
                _preflight_capacity=lambda *a, **k: None,
                _dispatch_acquisition=lambda *a, **k: "F.ABC",
                monitor_flow_completion=lambda *a, **k: order.append("poll") or "ERROR",
                cancel_flow=lambda *a, **k: None,
                _velo_query=lambda *a, **k: []):
            with self.assertRaises(acq.AcquisitionError):
                acq.acquire_memory_dump(
                    "C.0123456789abcdef", dumps_dir=tempfile.mkdtemp(prefix="d"),
                    on_dispatched=lambda f, p: order.append((f, os.path.basename(p))))
        self.assertEqual(order, [("F.ABC", "HOST-F.ABC.raw"), "poll"])

    def test_pipeline_persists_and_cleans_up_what_was_dispatched(self):
        persisted, cleaned, cbs = {}, [], []

        def fake_acquire(client_id, *, on_dispatched, **kw):
            on_dispatched("F.1", "/data/memory_dumps/h-F.1.raw")
            raise acq.AcquisitionError("backend died during the acquire")

        d, patches = _patched(
            acquire_memory_dump=fake_acquire,
            _persist_cleanup_state=lambda rid, **f: persisted.update(f),
            cleanup_after_run=lambda **k: cleaned.append(k))
        _run(patches, run_id="a1", client_id="C.1", dumps_dir=d)
        acq._DISK_RESERVED.clear()
        self.assertEqual(persisted.get("flow_id"), "F.1", "the boot reaper replays this")
        self.assertEqual(persisted.get("host_path"), "/data/memory_dumps/h-F.1.raw")
        self.assertEqual((cleaned[-1]["flow_id"], cleaned[-1]["host_path"]),
                         ("F.1", "/data/memory_dumps/h-F.1.raw"))


class EarlyStopIsSeen(unittest.TestCase):
    def test_an_event_set_before_the_pipeline_starts_stops_it(self):
        ev, entered, cleaned = threading.Event(), [], []
        ev.set()                                     # Stop landed during the ZIP extract
        d, patches = _patched(
            register_cancel_event=lambda rid: self.fail("must reuse the caller's event"),
            acquire_memory_dump=lambda *a, **k: entered.append(1),
            cleanup_after_run=lambda **k: cleaned.append(k))
        _run(patches, run_id="u1", client_id="", dumps_dir=d, cancel_event=ev,
             from_upload_path=os.path.join(d, "up.raw"))
        self.assertEqual(entered, [])
        self.assertEqual(cleaned[-1]["host_path"], os.path.join(d, "up.raw"),
                         "the uploaded image must still be reclaimed")

    def test_the_upload_route_registers_before_the_extract(self):
        with open(ROUTES, encoding="utf-8") as fh:
            src = fh.read()
        body = src[src.index("def upload_memory_dump"):src.index("def _payload_path")]
        self.assertLess(body.index("register_cancel_event(run_id)"),
                        body.index("extract_memory_from_upload("))
        self.assertIn("cancel_event=cancel_event", body)


class CleanupNeverOverlaps(unittest.TestCase):
    def test_stop_and_worker_cleanup_are_serialised(self):
        cbs, live, peak, lock = [], [0], [0], threading.Lock()

        def slow_cleanup(**_k):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.2)
            with lock:
                live[0] -= 1

        d, patches = _patched(
            register_cleanup=lambda rid, fn: cbs.append(fn),
            _take_run_slot=mock.Mock(side_effect=RuntimeError("stop here")),
            cleanup_after_run=lambda **k: None)
        _run(patches, run_id="c1", client_id="C.1", dumps_dir=d)
        with mock.patch.object(pm, "cleanup_after_run", slow_cleanup):
            ts = [threading.Thread(target=cbs[0]) for _ in range(2)]  # HTTP thread + worker
            for t in ts:
                t.start()
            for t in ts:
                t.join(5)
        self.assertEqual(peak[0], 1)


def _load_stop_route(status):
    with open(ROUTES, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "stop_memory_run")
    stopped = []
    ns = {"_get_run": lambda rid: {"run_id": rid, "status": status},
          "_run_visible_in_active_workspace": lambda r: True,
          "request_stop": stopped.append,
          "jsonify": lambda d: d}
    exec(compile(ast.get_source_segment(src, fn), ROUTES, "exec"), ns)
    return ns["stop_memory_run"], stopped


class StopRouteLeavesFinishedRunsAlone(unittest.TestCase):
    def test_finished_runs_are_refused(self):
        for st in ("completed", "failed", "cancelled"):
            fn, stopped = _load_stop_route(st)
            resp = fn("m1")
            self.assertEqual(resp[1], 409, st)
            self.assertEqual(stopped, [], st)

    def test_live_runs_are_stopped(self):
        for st in ("running", "pending"):
            fn, stopped = _load_stop_route(st)
            self.assertEqual(fn("m1"), {"ok": True})
            self.assertEqual(stopped, ["m1"])


if __name__ == "__main__":
    unittest.main()
