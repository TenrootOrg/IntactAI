"""POST /api/timesketch/start-multi returns at once; KAPE starts in the background (F3).

The handler used to start KAPE on every selected client inside the request: one
gRPC call, docker exec and log write each, 5-8 min at 1,000 clients. nginx cuts
/api/ off at 300 s, so the browser got a 504 while the loop kept running, and a
retry dispatched every collection again. The run name also joined every
hostname.

flask is not installed outside the container, so a minimal stand-in is enough:
the handler only uses Blueprint.route, request.get_json and jsonify.
"""
import importlib.util
import os
import sys
import threading
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), "modules/backend")
for _p in (HERE, BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

if "flask" not in sys.modules:
    try:
        import flask  # noqa: F401
    except ImportError:
        _flask = types.ModuleType("flask")

        class _Blueprint:
            def __init__(self, *_a, **_k):
                pass

            def route(self, *_a, **_k):
                return lambda fn: fn

        _flask.Blueprint = _Blueprint
        _flask.jsonify = lambda *a, **k: a[0] if a else k
        _flask.request = None
        sys.modules["flask"] = _flask

# Load the blueprint file alone: routes/__init__ imports every blueprint.
_spec = importlib.util.spec_from_file_location(
    "timesketch_routes_under_test", os.path.join(BACKEND, "routes/timesketch_routes.py"))
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)
import services.container_status as container_status  # noqa: E402
from services import kape_service  # noqa: E402

N = 1000


def body(resp):
    return resp[0] if isinstance(resp, tuple) else resp


class StartMultiReturnsImmediately(unittest.TestCase):
    def test_1000_clients_return_under_a_second_and_dispatch_in_background(self):
        payload = {"clients": [{"client_id": f"C.{i:016x}", "client_name": f"HOST-{i}"} for i in range(N)]}
        dispatched = []
        finished = threading.Event()
        names = []

        def slow_dispatch(client_id, *_a, **_k):
            time.sleep(0.002)            # 2 s for 1,000 clients if it ran in the request
            dispatched.append(client_id)
            return None                  # nothing started -> the background run ends quickly

        def status(run_id, st, **_k):
            if st in ("failed", "completed", "cancelled"):
                finished.set()

        def create_run(**kw):
            names.append(kw["name"])
            return "run-1"

        patches = [
            mock.patch.object(tr, "request", types.SimpleNamespace(get_json=lambda **_k: payload)),
            mock.patch.object(container_status, "require_velociraptor", lambda *_a: (None, None)),
            mock.patch.object(tr, "validate_automation_prerequisites", lambda: (True, "ok")),
            mock.patch.object(tr, "create_automation_run", create_run),
            mock.patch.object(tr, "add_log_to_run", lambda *a, **k: None),
            mock.patch.object(tr, "update_run_status", status),
            # The background pipeline lives in kape_service (shared with scheduled runs).
            mock.patch.object(kape_service, "add_log_to_run", lambda *a, **k: None),
            mock.patch.object(kape_service, "update_run_status", status),
            mock.patch.object(kape_service, "add_job", lambda *a, **k: None),
            mock.patch.object(kape_service, "unregister_cancel", lambda *a: None),
            mock.patch.object(kape_service, "run_kape_collection_grpc", slow_dispatch),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        t0 = time.monotonic()
        resp = tr.start_multi_client_timesketch()
        elapsed = time.monotonic() - t0

        out = body(resp)
        self.assertLess(elapsed, 1.0)
        self.assertEqual(out.get("run_id"), "run-1")
        self.assertEqual(out.get("status"), "processing")
        self.assertNotIn("error", out)
        self.assertEqual(len(out["clients"]), N)
        self.assertLess(len(dispatched), N)          # the request did not wait for dispatch

        self.assertTrue(finished.wait(30), "background dispatch never finished")
        self.assertEqual(len(dispatched), N)         # every client dispatched exactly once
        self.assertEqual(len(set(dispatched)), N)
        self.assertEqual(names, [f"TimeSketch Automation - {N} clients"])


if __name__ == "__main__":
    unittest.main()
