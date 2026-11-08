"""Large artifact results are fetched in small gRPC parts, never as one message.

VQLCollectorArgs.max_row is the rows per RESPONSE PART. It was 200,000, so an
imported 144,890-row Hayabusa collection (~640 MB) came as one message, hit the
channel's 100 MB limit (RESOURCE_EXHAUSTED) and the case silently got none of it.
"""
import json
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.agentic.collectors import _base  # noqa: E402


class _Stub:
    def __init__(self, parts=None, fail=None):
        self.parts, self.fail, self.requests = parts or [], fail, []

    def Query(self, req, timeout=None):
        self.requests.append(req)
        if self.fail:
            raise self.fail
        for p in self.parts:
            yield types.SimpleNamespace(Response=json.dumps(p), log="")


class _FlowStub:
    """A server holding one flow on C.1 whose every source() read is empty and
    carries only a VQL log line -- what Velociraptor sends when the plugin fails."""
    def __init__(self, sources, log):
        self.sources, self.log = sources, log

    def Query(self, req, timeout=None):
        vql = req["Query"][0]
        if "FROM clients()" in vql:
            yield types.SimpleNamespace(Response=json.dumps([{"LocCid": "C.1", "LocHost": "HOST1"}]), log="")
        elif "artifacts_with_results" in vql:
            yield types.SimpleNamespace(Response=json.dumps([{"artifacts_with_results": self.sources}]), log="")
        elif "FROM source(" in vql:
            yield types.SimpleNamespace(Response="", log=self.log)


class FetchInBatches(unittest.TestCase):
    def setUp(self):
        self._pb = _base.api_pb2
        _base.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=lambda **kw: kw, VQLRequest=lambda VQL: VQL)

    def tearDown(self):
        _base.api_pb2 = self._pb

    def test_parts_are_small_and_all_collected(self):
        stub = _Stub(parts=[[{"n": i} for i in range(1000)], [{"n": i} for i in range(1000)], [{"n": 1}]])
        rows = _base.query_artifact_results(stub, "C.1", "F.1", "Windows.Hayabusa.Rules")
        self.assertEqual(2001, len(rows))
        self.assertLessEqual(stub.requests[0]["max_row"], 5000)

    def test_a_failed_fetch_is_logged(self):
        with self.assertLogs(_base.logger, level="WARNING") as cm:
            rows = _base.query_artifact_results(_Stub(fail=RuntimeError("RESOURCE_EXHAUSTED")),
                                                "C.1", "F.1", "Windows.Hayabusa.Rules")
        self.assertEqual([], rows)
        self.assertIn("Windows.Hayabusa.Rules", cm.output[0])

    def test_a_failed_fetch_is_reported_to_the_caller(self):
        errors = []
        with self.assertLogs(_base.logger, level="WARNING"):
            _base.query_artifact_results(_Stub(fail=RuntimeError("RESOURCE_EXHAUSTED")),
                                         "C.1", "F.1", "Windows.Hayabusa.Rules", errors=errors)
        self.assertEqual(["Windows.Hayabusa.Rules: RESOURCE_EXHAUSTED"], errors)


def _load_upload_routes():
    """upload_routes.py on its own (routes/__init__ pulls in every blueprint),
    with flask/werkzeug stubbed where they are not installed."""
    import importlib.util
    for name, attrs in (("flask", ("Blueprint", "request", "jsonify")),
                        ("werkzeug", ()), ("werkzeug.utils", ("secure_filename",))):
        try:
            importlib.import_module(name)
        except ImportError:
            mod = types.ModuleType(name)
            for a in attrs:
                setattr(mod, a, lambda *a, **k: types.SimpleNamespace(route=lambda *a, **k: (lambda f: f)))
            sys.modules[name] = mod
    spec = importlib.util.spec_from_file_location(
        "_upload_routes_under_test", os.path.join(ROOT, "modules/backend/routes/upload_routes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EmptyReadsKeepVelociraptorsReason(unittest.TestCase):
    """F.DB1MDRE9ATTNA: every source() read came back with 0 rows in ~4 ms and
    the log said nothing about why. Velociraptor puts a plugin failure in the
    response's `log` field, and the fetch loop never looked at it."""
    def setUp(self):
        from unittest import mock
        self._pb = _base.api_pb2
        _base.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=lambda **kw: kw, VQLRequest=lambda VQL: VQL)
        self.logs = []
        self.stub = _FlowStub(["Windows.Hayabusa.Rules", "Windows.Forensics.SAM/Parsed"],
                              "source: no such file\n")
        self.patches = [
            mock.patch.object(_base, "setup_velociraptor_connection",
                              lambda: types.SimpleNamespace(close=lambda: None)),
            mock.patch.object(_base.api_pb2_grpc, "APIStub", lambda ch: self.stub, create=True),
            mock.patch.object(_base, "add_log_to_run",
                              lambda rid, msg, level="info": self.logs.append((level, msg))),
            mock.patch.object(_base, "_run_client_ids", lambda rid: []),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        _base.api_pb2 = self._pb

    def test_each_empty_read_is_reported_with_the_server_log(self):
        empty = []
        results, _, info = _base.get_existing_collection_results(
            "run_1", flow_id="F.X", empty_reads=empty)
        self.assertEqual({}, results)
        self.assertIn("C.1", info)
        self.assertEqual([("Windows.Hayabusa.Rules", ["source: no such file"]),
                          ("Windows.Forensics.SAM/Parsed", ["source: no such file"])], empty)
        warned = [m for lvl, m in self.logs if lvl == "warning" and "source: no such file" in m]
        self.assertEqual(2, len(warned))

    def test_the_kwarg_is_optional(self):
        results, _, _ = _base.get_existing_collection_results("run_1", flow_id="F.X")
        self.assertEqual({}, results)


class ImportSaysWhatIsMissing(unittest.TestCase):
    """The UTICA import lost its detections to RESOURCE_EXHAUSTED and still ended
    with "[Import] Added N rows ... success"."""
    def run_import(self, rows, errors):
        from unittest import mock
        up = _load_upload_routes()
        logs, saved = [], []

        def fetch(*a, **kw):
            kw["errors"].extend(errors)
            return rows, list(rows), {"C.1": {"hostname": "UTICA"}}
        with mock.patch("services.workflow_service.add_log_to_run",
                        lambda rid, msg, level="info": logs.append((level, msg))), \
             mock.patch("services.workflow_service.get_automation_run", lambda rid: {"id": rid}), \
             mock.patch("services.workflow_service.update_run_status", lambda *a, **k: None), \
             mock.patch("services.file_storage_service.save_workflow", saved.append), \
             mock.patch("services.agentic.collectors.get_existing_collection_results", fetch), \
             mock.patch("services.agentic.collectors.persist_pipeline_artifacts", lambda *a: None):
            up._fuse_offline_import({"success": True, "flow_id": "F.X", "client_id": "C.1"}, "velociraptor_upload_1")
        return logs, saved

    def test_partial_import_is_a_warning_naming_the_source(self):
        logs, _ = self.run_import({"Windows.EventLogs.CondensedAccountUsage": [{"a": 1}]},
                                  ["Windows.Hayabusa.Rules: RESOURCE_EXHAUSTED"])
        added = [(lvl, m) for lvl, m in logs if m.startswith("[Import] Added")]
        self.assertEqual(1, len(added))
        self.assertEqual("warning", added[0][0])
        self.assertIn("MISSING: Windows.Hayabusa.Rules", added[0][1])

    def test_clean_import_still_succeeds(self):
        logs, _ = self.run_import({"Windows.Hayabusa.Rules": [{"a": 1}]}, [])
        added = [(lvl, m) for lvl, m in logs if m.startswith("[Import] Added")]
        self.assertEqual("success", added[0][0])
        self.assertNotIn("MISSING", added[0][1])

    def test_nothing_read_is_an_error_and_keeps_the_retry_locator(self):
        logs, saved = self.run_import({}, ["fetch: deadline exceeded"])
        self.assertEqual("error", logs[-1][0])
        self.assertIn("MISSING", logs[-1][1])
        self.assertEqual("F.X", saved[-1]["details"]["offline_flow_id"])


class NoFetchAsksForHugeParts(unittest.TestCase):
    """The import used a SECOND loop (max_row=50000 -> a 393 MB message): every
    VQLCollectorArgs in the collector module must ask for small parts."""
    def test_every_max_row_is_small(self):
        import re
        src = open(os.path.join(ROOT, "modules/backend/services/agentic/collectors/_base.py")).read()
        for m in re.finditer(r"max_row=([A-Za-z_0-9]+)", src):
            v = m.group(1)
            n = _base.VELO_FETCH_BATCH_ROWS if v == "VELO_FETCH_BATCH_ROWS" else int(v)
            self.assertLessEqual(n, 5000, f"max_row={v} at offset {m.start()}")


if __name__ == "__main__":
    unittest.main()
