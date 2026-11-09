"""Offline collector builds: Stop stops them, and each run gets its own file (E6).

Stop used to be invisible to the build: the generator looked the cancel Event
up by run_id, and request_stop had already dropped it, so the build ran on and
left a ZIP. Every build of one blueprint/OS also wrote the same
OfflineCollector_<name>_<os>.zip, so an older run's Download served the newest
build (wrong password/scheme) and concurrent builds deleted each other's file.

Drives the real generate_collector with Velociraptor (docker exec / gRPC)
faked out at the subprocess and pyvelociraptor boundary.
"""
import json
import os
import sys
import tempfile
import threading
import types
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import services.offline_collector.generator as gen  # noqa: E402
import services.offline_collector.constants as consts  # noqa: E402

API_CONFIG = ("ca_certificate: x\nclient_private_key: x\nclient_cert: x\n"
              "api_connection_string: 127.0.0.1:8001\n")
COLLECTOR_IN_CONTAINER = "/var./clients/server/collections/F.1/uploads/Collector_X.zip"


class _Done:
    def __init__(self, stdout="", rc=0):
        self.stdout, self.stderr, self.returncode = stdout, "", rc


def _fake_run(cmd, *a, **k):
    if "api.config.yaml" in cmd:
        return _Done(API_CONFIG)
    if ".json.db" in cmd:
        return _Done(json.dumps({"state": "FINISHED"}))
    if " find " in cmd:
        return _Done(COLLECTOR_IN_CONTAINER + "\n")
    if cmd.startswith("docker cp"):
        with open(cmd.split()[-1].strip("'"), "wb") as f:
            f.write(b"collector-config")
        return _Done()
    return _Done(rc=1)


class _Stub:
    def __init__(self, _channel):
        pass

    def Query(self, req, timeout=None):
        vql = req.Query[0].VQL
        if "collect_client" in vql:
            row = [{"Collection": {"flow_id": "F.1"}}]
            return iter([types.SimpleNamespace(log="", Response=json.dumps(row))])
        return iter([])


def _fake_velo_modules():
    grpc = types.ModuleType("grpc")
    grpc.RpcError = type("RpcError", (Exception,), {})
    grpc.ssl_channel_credentials = lambda **k: None
    grpc.secure_channel = lambda *a, **k: types.SimpleNamespace(close=lambda: None)
    api_pb2 = types.ModuleType("api_pb2")
    api_pb2.VQLRequest = lambda VQL: types.SimpleNamespace(VQL=VQL)
    api_pb2.VQLCollectorArgs = lambda Query, **k: types.SimpleNamespace(Query=Query)
    api_pb2_grpc = types.ModuleType("api_pb2_grpc")
    api_pb2_grpc.APIStub = _Stub
    pkg = types.ModuleType("pyvelociraptor")
    pkg.api_pb2, pkg.api_pb2_grpc = api_pb2, api_pb2_grpc
    return {"grpc": grpc, "pyvelociraptor": pkg,
            "pyvelociraptor.api_pb2": api_pb2, "pyvelociraptor.api_pb2_grpc": api_pb2_grpc}


class CollectorBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        out = self.tmp.name
        velo = os.path.join(out, "velo.exe")
        with open(velo, "wb") as f:
            f.truncate(2 * 1024 * 1024)            # sparse, passes the 1 MB floor
        self.sleep = mock.Mock()
        for p in (
            mock.patch.dict(sys.modules, _fake_velo_modules()),
            mock.patch.object(gen, "COLLECTOR_OUTPUT_DIR", out),
            mock.patch.object(consts, "COLLECTOR_OUTPUT_DIR", out),
            mock.patch.object(gen, "VELO_CLIENT_PATHS", {"windows": velo, "linux": velo, "darwin": velo}),
            mock.patch.object(gen, "get_blueprint_as_config",
                              lambda _id: {"config_name": "Triage", "artifacts": ["Windows.Sys.Users"]}),
            mock.patch.object(gen.subprocess, "run", _fake_run),
            mock.patch.object(gen.time, "sleep", self.sleep),
            # Run logs would go to the box's SQLite; keep the test off it.
            mock.patch("services.workflow_service.add_log_to_run", lambda *a, **k: None),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def zips(self):
        return sorted(f for f in os.listdir(self.tmp.name) if f.endswith(".zip"))

    def test_rebuild_of_same_blueprint_and_os_keeps_both_files(self):
        a = gen.generate_collector("bp1", "windows")
        b = gen.generate_collector("bp1", "windows")
        self.assertTrue(a["success"] and b["success"], (a, b))
        self.assertNotEqual(a["file_id"], b["file_id"])
        self.assertNotEqual(a["file_path"], b["file_path"])
        self.assertEqual(2, len(self.zips()))
        # The download route resolves each run's id to that run's own ZIP.
        self.assertEqual(a["file_path"], consts.get_collector_file(a["file_id"]))
        self.assertEqual(b["file_path"], consts.get_collector_file(b["file_id"]))
        with zipfile.ZipFile(a["file_path"]) as zf:
            self.assertIn("collector_config", zf.namelist())

    def test_stop_during_the_wait_loop_cancels_with_no_registry_entry(self):
        ev = threading.Event()
        self.sleep.side_effect = lambda *_: ev.set()   # Stop lands mid-wait
        # run_id has no registry entry: what request_stop left behind.
        r = gen.generate_collector("bp1", "windows", run_id="velociraptor_offline_collector_1",
                                   cancel_event=ev)
        self.assertTrue(r.get("cancelled"), r)
        self.assertFalse(r.get("success"))
        self.assertEqual([], self.zips())
        self.assertEqual([], [d for d in os.listdir(self.tmp.name) if d.startswith("bundle_")])


if __name__ == "__main__":
    unittest.main()
