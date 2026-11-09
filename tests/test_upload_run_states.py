"""Upload / offline-import runs must end in the state that actually happened.

E3  a read-back that raised inside _fuse_offline_import was only printed, so the
    run ended green "completed" with an empty case and nothing in its log.
E7  an import Velociraptor returned no flow for (not a collection, or a server
    VQL error it reports only in its log) ended green too; a failed import's
    reason was overwritten by the caller's "completed" -> "1 fatal error(s)".
A1  tus hooks are not ordered against Stop: a late post-receive wrote "running"
    over a stopped/terminated run, and post-finish processed every purpose but
    memory for a run that was already over.
"""
import os
import sys
import tempfile
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
from test_fetch_in_batches import _load_upload_routes  # noqa: E402


class _Run:
    """Records the run's log and status writes."""
    def __init__(self):
        self.logs, self.status = [], []

    def log(self, rid, msg, level="info", force=False):
        self.logs.append((level, msg, force))

    def upd(self, rid, status, progress=None, error=None, details=None, force=False):
        self.status.append((status, error, details))


class FuseFailureFailsTheRun(unittest.TestCase):           # E3
    def test_a_read_back_that_raises_ends_failed_with_the_reason(self):
        up, run = _load_upload_routes(), _Run()

        def boom(*a, **k):
            raise OSError("No space left on device")
        ok = {"success": True, "hunt_id": "H.1", "run_id": "r1"}
        with mock.patch.object(up, "add_log_to_run", run.log), \
                mock.patch.object(up, "update_run_status", run.upd), \
                mock.patch.object(ws, "add_log_to_run", run.log), \
                mock.patch.object(ws, "update_run_status", run.upd), \
                mock.patch.object(importer, "import_results", lambda *a, **k: ok), \
                mock.patch("services.agentic.collectors.get_existing_collection_results", boom):
            up.import_offline_collection("/nope.zip", "c.zip", "r1")
        self.assertEqual("failed", run.status[-1][0])
        self.assertIn("No space left on device", run.status[-1][1])
        self.assertTrue(any(lvl == "error" and "Reading imported data" in m for lvl, m, _ in run.logs))
        self.assertNotIn("completed", [s for s, _, _ in run.status])

    def test_a_failed_import_keeps_its_reason(self):                       # E7, caller side
        up, run = _load_upload_routes(), _Run()
        bad = {"success": False, "run_id": "r1", "error": "Incorrect password"}
        with mock.patch.object(up, "add_log_to_run", run.log), \
                mock.patch.object(up, "update_run_status", run.upd), \
                mock.patch.object(importer, "import_results", lambda *a, **k: bad):
            up.import_offline_collection("/nope.zip", "c.zip", "r1")
        self.assertEqual([("failed", "Incorrect password", None)], run.status)


class ImportWithNoFlowIsAFailure(unittest.TestCase):     # E7, importer side
    def _import(self, collection):
        d = tempfile.mkdtemp()
        z = os.path.join(d, "Collection-WS1.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("collection_context.json", "{}")
        cfg = "ca_certificate: a\nclient_private_key: b\nclient_cert: c\napi_connection_string: x\n"
        resp = [types.SimpleNamespace(log="", Response=""),   # existing-client lookup
                types.SimpleNamespace(log="ImportCollection: no such file", Response=collection)]

        class Stub:
            def __init__(self, *_a):
                self.calls = 0

            def Query(self, *_a, **_k):
                self.calls += 1
                if self.calls > 2:
                    raise RuntimeError("no detail queries in this test")
                return [resp[self.calls - 1]]
        from pyvelociraptor import api_pb2_grpc
        run = _Run()
        grpc = sys.modules["grpc"]
        with mock.patch.object(importer.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=0, stdout=cfg, stderr="")), \
                mock.patch.object(importer, "_org_channel", return_value=mock.Mock()), \
                mock.patch.object(importer, "_wait_import_flow_finished"), \
                mock.patch.object(importer.time, "sleep"), \
                mock.patch.object(api_pb2_grpc, "APIStub", Stub, create=True), \
                mock.patch.object(ws, "add_log_to_run", run.log), \
                mock.patch.object(ws, "update_run_status", run.upd), \
                mock.patch.object(grpc, "RpcError", type("RpcError", (Exception,), {}), create=True):
            return importer.import_results(z, "Collection-WS1.zip", run_id="r1", finalize=False), run

    def test_no_flow_id_fails_with_error_text(self):
        res, run = self._import('[{"Collection": null}]')
        self.assertFalse(res["success"])
        self.assertIn("no import flow", res["error"])
        self.assertEqual("failed", run.status[-1][0])
        self.assertIn("no import flow", run.status[-1][1])

    def test_a_flow_without_a_client_still_succeeds_and_keeps_the_flow(self):
        res, run = self._import('[{"Collection": {"flow_id": "F.1"}}]')
        self.assertTrue(res["success"])
        self.assertEqual("F.1", res["flow_id"])          # the read-back needs it
        self.assertEqual("running", run.status[-1][0])   # finalize=False: caller ends it
        self.assertEqual("F.1", run.status[-1][2]["flow_id"])

    def test_a_wrong_password_sets_the_error_field(self):
        run = _Run()
        with mock.patch.object(importer, "_decrypt_container_if_needed",
                               side_effect=ValueError("Incorrect password")), \
                mock.patch.object(ws, "add_log_to_run", run.log), \
                mock.patch.object(ws, "update_run_status", run.upd), \
                mock.patch.object(importer.os.path, "getsize", return_value=1):
            res = importer.import_results("/x.zip", "x.zip", run_id="r1")
        self.assertEqual({"success": False, "run_id": "r1", "error": "Incorrect password"}, res)
        self.assertEqual(("failed", "Incorrect password"), run.status[-1][:2])


class StopIsRespectedByTheTusHook(unittest.TestCase):    # A1 (tus part)
    def _hook(self, up, event, status, purpose="timesketch", upload_id="u1"):
        run, threads = _Run(), []
        up._upload_runs[upload_id] = "r1"
        up.request = types.SimpleNamespace(get_json=lambda force=True: {
            "Type": event, "Event": {"Upload": {
                "ID": upload_id, "Size": 100, "Offset": 50,
                "MetaData": {"purpose": purpose, "filename": "k.zip"}}}})
        up.jsonify = lambda d: d
        with mock.patch.object(up, "add_log_to_run", run.log), \
                mock.patch.object(up, "update_run_status", run.upd), \
                mock.patch.object(up.threading, "Thread",
                                  lambda *a, **k: threads.append(k) or mock.Mock()), \
                mock.patch.object(up.os, "remove") as rm, \
                mock.patch.object(up.os.path, "exists", return_value=True), \
                mock.patch.object(up.os.path, "getsize", return_value=100), \
                mock.patch("services.file_storage_service.get_workflow",
                           lambda rid, *a, **k: {"status": status}):
            up.handle_tus_hook()
        return run, threads, rm

    def test_progress_does_not_reopen_an_ended_run(self):
        up = _load_upload_routes()
        for status in ("failed", "cancelled"):
            run, _, _ = self._hook(up, "post-receive", status, upload_id="u-" + status)
            self.assertEqual([], run.status, status)

    def test_progress_still_moves_a_live_run(self):
        up = _load_upload_routes()
        run, _, _ = self._hook(up, "post-receive", "running")
        self.assertEqual("running", run.status[0][0])

    def test_progress_after_terminate_is_dropped(self):
        up = _load_upload_routes()
        self._hook(up, "post-terminate", "running", upload_id="u-t")
        self.assertIn("u-t", up._finished_uploads)

    def test_finish_after_stop_processes_nothing_for_every_purpose(self):
        up = _load_upload_routes()
        for purpose in ("velociraptor", "timesketch", "upgrade_package", "case_import",
                        "memory_symbols", "agentic_external", "memory"):
            run, threads, rm = self._hook(up, "post-finish", "cancelled", purpose=purpose,
                                          upload_id="f-" + purpose)
            self.assertEqual([], threads, purpose)
            self.assertEqual([], run.status, purpose)
            rm.assert_any_call("/data/uploads/f-" + purpose)
            self.assertTrue(any(f and "after the run was stopped" in m for _, m, f in run.logs))

    def test_finish_on_a_live_run_still_processes(self):
        up = _load_upload_routes()
        run, threads, _ = self._hook(up, "post-finish", "running", upload_id="f-live")
        self.assertEqual(1, len(threads))


if __name__ == "__main__":
    unittest.main()
