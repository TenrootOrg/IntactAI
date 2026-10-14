"""/api/clients at fleet scale (audit 2026-10-14).

F27: offline-collection imports (no agent name, never interrogated, no version)
were listed as clients in every picker and counted on the dashboard.

flask is a container dependency, so the route runs here against a minimal stand-in
for the few flask names client_routes uses; the service runs for real against a
scripted gRPC stub.
"""
import importlib.util
import json
import os
import sys
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402


class _Args(dict):
    def get(self, key, default=None, type=None):
        v = dict.get(self, key, default)
        if type is not None and v is not None:
            try:
                return type(v)
            except ValueError:
                return default
        return v


def _fake_flask():
    try:
        import flask  # noqa: F401
        return None                                    # the real one is here: use it
    except ImportError:
        pass

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda fn: fn

    mod = types.ModuleType("flask")
    mod.Blueprint = Blueprint
    mod.jsonify = lambda body=None, **k: body if body is not None else k
    mod.send_file = lambda *a, **k: None
    mod.request = types.SimpleNamespace(args=_Args())
    sys.modules["flask"] = mod
    return mod


FAKE_FLASK = _fake_flask()
from services import velociraptor_service as vs  # noqa: E402
# routes/__init__.py imports every blueprint (and more of flask): load this one alone.
_spec = importlib.util.spec_from_file_location(
    "client_routes_under_test", os.path.join(ROOT, "modules/backend/routes/client_routes.py"))
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

NOW_US = int(time.time() * 1e6)


def row(cid, host, agent="velociraptor", interrogated="F.1", version="0.77.1", seen_ago_s=30):
    return {"client_id": cid, "hostname": host, "os": "windows", "os_version": "10",
            "labels": [], "last_seen_at": NOW_US - int(seen_ago_s * 1e6), "last_ip": "",
            "agent": agent, "version": version, "interrogated": interrogated}


class _Stub:
    def __init__(self, rows):
        self.rows = rows
        self.queries = 0

    def Query(self, req, timeout=None):
        self.queries += 1
        yield types.SimpleNamespace(Response=json.dumps(self.rows))


class FleetRouteCase(unittest.TestCase):
    rows = []

    def setUp(self):
        if FAKE_FLASK is None:
            self.skipTest("real flask present: this suite drives the route without an app")
        self.stub = _Stub(self.rows)
        self.saved = (vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub)
        vs.setup_velociraptor_connection = lambda: types.SimpleNamespace(close=lambda: None)
        vs.api_pb2_grpc.APIStub = lambda ch: self.stub
        reset = getattr(cr, "_FLEET_CACHE", None)
        if reset is not None:
            reset.update(at=0.0, rows=None)

    def tearDown(self):
        vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub = self.saved
        FAKE_FLASK.request.args = _Args()

    def get(self, **args):
        FAKE_FLASK.request.args = _Args({k: str(v) for k, v in args.items()})
        return cr.get_clients()


class ImportsAreNotClients(FleetRouteCase):
    rows = [row("C.agent1", "PC-1"),
            row("C.import1", "ADATUM-DC", agent="", interrogated="", version="", seen_ago_s=10**6),
            # enrolled but not interrogated yet: still an agent (it has a name)
            row("C.fresh", "PC-2", interrogated="", version="")]

    def test_imports_left_out_of_items_and_total(self):
        body = self.get(include_offline="true")
        self.assertEqual({"C.agent1", "C.fresh"}, {c["client_id"] for c in body["items"]})
        self.assertEqual(2, body["total"])
        self.assertEqual(1, body["imported"])

    def test_service_keeps_them_marked_for_os_mapping_callers(self):
        got = {c["client_id"]: c["imported"] for c in vs.get_clients_from_snapshot(include_offline=True)}
        self.assertEqual({"C.agent1": False, "C.import1": True, "C.fresh": False}, got)


if __name__ == "__main__":
    unittest.main()
