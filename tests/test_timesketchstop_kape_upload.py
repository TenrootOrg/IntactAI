"""Stop really stops a Timesketch KAPE upload (QA A2).

TUS uploads never registered a cancel Event, and process_kape_upload only looked
at Stop around Plaso, so Stop relabelled the run 'cancelled' while extraction,
log2timeline (in a container nothing removed) and the Timesketch import kept going.
These drive the real process_kape_upload / process_local_with_plaso with Plaso,
pinfo and Timesketch mocked, and Stop going through the real request_stop.
"""
import io
import os
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import kape_upload_service as kus  # noqa: E402
from services import workflow_service as ws  # noqa: E402
import services.archive_guard as archive_guard  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, True)
        self.logs, self.statuses = [], []
        self.on_log = None   # hook: called with each log line, to press Stop mid-step
        rows = {}

        def log(run_id, m, l="info"):
            self.logs.append((l, m))
            if self.on_log:
                self.on_log(m)

        def status(run_id, st, **_k):
            # update_run_status keeps 'cancelled' terminal; mirror that.
            if rows.get(run_id) != "cancelled":
                rows[run_id] = st
            self.statuses.append(st)
            return True
        self.rows = rows
        for target, name, value in (
                (kus, "PLASO_OUTPUT_DIR", self.out),
                (kus, "add_log_to_run", log),
                (kus, "update_run_status", status),
                (kus, "_PLASO_SLOTS", threading.BoundedSemaphore(1)),
                (ws, "add_log_to_run", log),
                (ws, "update_run_status", status),
                (ws, "file_get_workflow", lambda *a, **k: {"status": rows.get(a[0], "running")}),
                (archive_guard, "guard_zip", lambda *a, **k: {"members": 3})):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.zip = os.path.join(self.out, "upload.zip")
        with zipfile.ZipFile(self.zip, "w") as zf:
            for i in range(3):
                zf.writestr(f"C/f{i}.txt", "x")

    def stop_on(self, text, run_id):
        def hook(m):
            if text in m and not ws.is_cancelled(run_id):
                ws.request_stop(run_id)
        self.on_log = hook


class UploadStops(Base):
    def test_tus_upload_stop_during_extraction_stops_everything(self):
        run_id = "timesketch_upload_1"
        self.assertIsNone(ws.get_cancel_event(run_id))     # the TUS hook registers nothing
        self.stop_on("Extracting ZIP file", run_id)
        plaso = mock.Mock()
        with mock.patch.object(kus, "process_local_with_plaso", plaso):
            res = kus.process_kape_upload(self.zip, "upload.zip", {"client_name": "H"}, run_id=run_id)
        self.assertEqual(res["status"], "cancelled")
        plaso.assert_not_called()
        self.assertEqual(self.rows[run_id], "cancelled")
        self.assertNotIn("failed", self.statuses)
        self.assertFalse(any(l == "error" for l, _ in self.logs), self.logs)
        self.assertEqual(os.listdir(self.out), [])           # temp tree and ZIP gone
        self.assertIsNone(ws.get_cancel_event(run_id))       # the Event it registered is dropped

    def test_stop_after_plaso_skips_the_timesketch_import(self):
        run_id = "timesketch_upload_2"
        self.stop_on("Verifying Plaso Output", run_id)
        plaso_path = os.path.join(self.out, "h.plaso")

        def fake_plaso(*_a, **_k):
            open(plaso_path, "w").close()
            return plaso_path
        imp = mock.Mock()
        with mock.patch.object(kus, "process_local_with_plaso", fake_plaso), \
                mock.patch.object(kus, "run_pinfo", lambda *a, **k: {"event_count": 5}), \
                mock.patch.object(kus, "import_to_timesketch", imp):
            res = kus.process_kape_upload(self.zip, "upload.zip", {"client_name": "H"}, run_id=run_id)
        self.assertEqual(res["status"], "cancelled")
        imp.assert_not_called()
        self.assertEqual(self.rows[run_id], "cancelled")
        self.assertFalse(os.path.exists(plaso_path))

    def test_failure_caused_by_stop_is_not_reported_as_failed(self):
        run_id = "timesketch_upload_3"

        def stop_then_boom(*_a, **_k):   # Stop mid-import breaks the upload
            ws.request_stop(run_id)
            raise RuntimeError("connection reset")
        with mock.patch.object(kus, "process_local_with_plaso",
                               lambda *a, **k: open(os.path.join(self.out, "p.plaso"), "w").close()
                               or os.path.join(self.out, "p.plaso")), \
                mock.patch.object(kus, "run_pinfo", lambda *a, **k: {"event_count": 5}), \
                mock.patch.object(kus, "import_to_timesketch", stop_then_boom):
            res = kus.process_kape_upload(self.zip, "upload.zip", {"client_name": "H"}, run_id=run_id)
        self.assertEqual(res["status"], "cancelled")
        self.assertNotIn("failed", self.statuses)
        self.assertFalse(any(l == "error" for l, _ in self.logs), self.logs)

    def test_caller_registered_event_is_kept(self):
        run_id = "timesketch_kape_4"
        ev = ws.register_cancel_event(run_id)
        self.addCleanup(ws.unregister_cancel, run_id)
        with mock.patch.object(kus, "process_local_with_plaso",
                               lambda *a, **k: open(os.path.join(self.out, "q.plaso"), "w").close()
                               or os.path.join(self.out, "q.plaso")), \
                mock.patch.object(kus, "run_pinfo", lambda *a, **k: {"event_count": 5}), \
                mock.patch.object(kus, "import_to_timesketch",
                                  lambda *a, **k: {"sketch_id": 1, "timeline_id": 2}):
            res = kus.process_kape_upload(self.zip, "upload.zip", {"client_name": "H"}, run_id=run_id)
        self.assertEqual(res["status"], "completed")
        self.assertIs(ws.get_cancel_event(run_id), ev)   # start-multi still owns it


class PlasoContainerStops(Base):
    def test_stop_mid_log2timeline_removes_container_and_partial_file(self):
        run_id = "timesketch_upload_5"
        ws.register_cancel_event(run_id)
        self.addCleanup(ws.unregister_cancel, run_id)
        calls = {}

        def fake_popen(cmd, **kw):
            calls["cmd"], calls["kw"] = cmd, kw
            storage = cmd[cmd.index("--storage-file") + 1]
            calls["file"] = os.path.join(self.out, os.path.basename(storage))
            open(calls["file"], "w").close()      # half-written output

            def lines():
                yield "Processing started.\n"
                ws.request_stop(run_id)
                yield "status: 10 events\n"
                yield "status: 20 events\n"
            proc = mock.Mock()
            proc.stdout = lines()
            proc.wait.return_value = -15
            return proc

        killed, ran = [], []
        with mock.patch.object(kus.subprocess, "Popen", fake_popen), \
                mock.patch.object(kus.subprocess, "run", lambda c, **k: ran.append(c)), \
                mock.patch.object(kus, "terminate_subprocess", lambda p, *a, **k: killed.append(p)), \
                mock.patch.object(kus, "get_plaso_image", return_value="plaso"):
            res = kus.process_local_with_plaso("/src", "H", run_id=run_id)
        self.assertIsNone(res)
        self.assertTrue(calls["kw"].get("start_new_session"))   # never signal the backend's group
        name = calls["cmd"][calls["cmd"].index("--name") + 1]
        self.assertFalse(name.startswith("intact_"))
        self.assertIn(["docker", "rm", "-f", name], ran)
        self.assertTrue(killed)
        self.assertFalse(os.path.exists(calls["file"]))
        self.assertEqual(self.rows[run_id], "cancelled")


if __name__ == "__main__":
    unittest.main()
