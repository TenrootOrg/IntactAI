"""Offline-collection import over the multipart API route (fleet-scale audit F22).

1. The route imported inline: the importer may wait 900 s for the flow, nginx cuts
   /api/ at 300 s, so a real hunt export answered 504 while the import ran on.
   It now answers 202 + run_id at once and imports in a thread.
2. The ZIP was copied into the Velociraptor container as
   /tmp/offline_import_<epoch seconds>.zip: two imports in the same second
   overwrote each other's file. It is a uuid now, and removed even on failure.

Both are executed, not grepped: the route function is lifted out by AST (flask is
a container dependency, not a test one) and run against fakes; import_results runs
for real with subprocess and the run log mocked.
"""
import ast
import io
import os
import sys
import tempfile
import traceback
import types
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import services.workflow_service as ws  # noqa: E402
from services.offline_collector import importer  # noqa: E402

ROUTES = os.path.join(ROOT, "modules/backend/routes/velociraptor_offline_routes.py")


class _Upload:
    def __init__(self, name, data):
        self.filename, self._b = name, io.BytesIO(data)

    def seek(self, *a):
        return self._b.seek(*a)

    def tell(self):
        return self._b.tell()

    def save(self, path):
        with open(path, "wb") as fh:
            fh.write(self._b.getvalue())


class _Thread:
    started = []

    def __init__(self, target, daemon=None):
        self.target = target

    def start(self):
        _Thread.started.append(self.target)


def _route(**fakes):
    with open(ROUTES, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "import_offline_results")
    ns = {"os": os, "traceback": traceback, "threading": types.SimpleNamespace(Thread=_Thread),
          "jsonify": lambda d: d, "secure_filename": os.path.basename}
    ns.update(fakes)
    exec(compile(ast.get_source_segment(src, fn), ROUTES, "exec"), ns)
    return ns["import_offline_results"]


class RouteRunsInBackground(unittest.TestCase):
    def setUp(self):
        _Thread.started.clear()
        self.calls, self.status = [], []
        self.req = types.SimpleNamespace(files={"file": _Upload("host.zip", b"PK")}, form={})

    def _fn(self, import_results):
        return _route(request=self.req, import_results=import_results,
                      create_automation_run=lambda *a, **k: "velociraptor_offline_import_1",
                      add_log_to_run=lambda *a, **k: None,
                      update_run_status=lambda rid, st, **k: self.status.append(st))

    def test_answers_202_with_run_id_before_importing(self):
        def imp(path, name, run_id=None, password=None):
            self.calls.append((path, name, run_id))
            self.assertTrue(os.path.exists(path))
        body, code = self._fn(imp)()
        self.assertEqual(code, 202)
        self.assertEqual(body["run_id"], "velociraptor_offline_import_1")
        self.assertEqual(self.calls, [])                 # nothing imported inside the request
        self.assertEqual(len(_Thread.started), 1)
        _Thread.started[0]()                             # the worker
        path, name, rid = self.calls[0]
        self.assertEqual((name, rid), ("host.zip", "velociraptor_offline_import_1"))
        self.assertFalse(os.path.exists(os.path.dirname(path)))   # temp dir removed

    def test_worker_crash_fails_the_run_and_cleans_up(self):
        seen = []

        def imp(path, *a, **k):
            seen.append(path)
            raise RuntimeError("boom")
        self._fn(imp)()
        _Thread.started[0]()
        self.assertEqual(self.status[-1], "failed")
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])))

    def test_oversize_points_at_tus(self):
        self.req.files["file"] = _Upload("big.zip", b"x")
        up = self.req.files["file"]
        up.tell = lambda: 501 * 1024 * 1024
        body, code = self._fn(lambda *a, **k: None)()
        self.assertEqual(code, 413)
        self.assertIn("/api/uploads/", body["error"])


class ContainerTempName(unittest.TestCase):
    def _import_once(self, zpath):
        calls = []

        def run(cmd, *a, **k):
            calls.append(cmd)
            # docker cp fails -> the importer's error path; the copy must still be removed
            return types.SimpleNamespace(returncode=1, stdout="", stderr="no such container")
        grpc = sys.modules["grpc"]
        with mock.patch.object(importer.subprocess, "run", side_effect=run), \
                mock.patch.object(ws, "add_log_to_run"), mock.patch.object(ws, "update_run_status"), \
                mock.patch.object(grpc, "RpcError", type("RpcError", (Exception,), {}), create=True):
            res = importer.import_results(zpath, "host.zip", run_id="r1")
        self.assertFalse(res["success"])
        cp = next(c for c in calls if isinstance(c, str) and c.startswith("docker cp"))
        target = cp.rsplit(":", 1)[1]
        self.assertRegex(target, r"^/tmp/offline_import_[0-9a-f]{32}\.zip$")
        rm = [c for c in calls if isinstance(c, list) and c[-3:-1] == ["rm", "-f"]]
        self.assertEqual([c[-1] for c in rm], [target])  # removed in `finally`, even on failure
        return target

    def test_same_second_imports_do_not_share_a_path(self):
        d = tempfile.mkdtemp()
        paths = []
        for i in range(2):
            z = os.path.join(d, f"c{i}.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("collection_context.json", "{}")
            with mock.patch.object(importer.time, "time", return_value=1_800_000_000):
                paths.append(self._import_once(z))
        self.assertNotEqual(*paths)


if __name__ == "__main__":
    unittest.main()
