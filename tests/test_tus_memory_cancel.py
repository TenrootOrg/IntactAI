"""A Stop during a tus memory upload's stage/extract reaches the pipeline.

The pipeline used to register its own cancel event after the multi-GB move and
ZIP extract, so a Stop that landed during them was never seen by it. The hook
now registers first and hands the event over; a failed extract unregisters it.
"""
import os
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import services.workflow_service as ws  # noqa: E402
from services.memory import pipeline, upload_extract  # noqa: E402
from test_fetch_in_batches import _load_upload_routes  # noqa: E402

RID = "memory_tus_cancel"


class TusMemoryCancel(unittest.TestCase):
    def _worker(self, up):
        """The run_memory_upload closure post-finish starts for a live run."""
        threads = []
        up._upload_runs["tm1"] = RID
        up.request = types.SimpleNamespace(get_json=lambda force=True: {
            "Type": "post-finish", "Event": {"Upload": {
                "ID": "tm1", "Size": 100, "Offset": 100,
                "MetaData": {"purpose": "memory", "filename": "m.raw"}}}})
        up.jsonify = lambda d: d
        up.secure_filename = lambda s: s  # werkzeug may be a stub here
        with mock.patch.object(up, "add_log_to_run"), \
                mock.patch.object(up, "update_run_status"), \
                mock.patch.object(up.threading, "Thread",
                                  lambda *a, **k: threads.append(k["target"]) or mock.Mock()), \
                mock.patch.object(up.os.path, "exists", return_value=True), \
                mock.patch.object(up.os.path, "getsize", return_value=100), \
                mock.patch("services.file_storage_service.get_workflow",
                           lambda *a, **k: {"status": "running"}):
            up.handle_tus_hook()
        self.assertEqual(1, len(threads))
        return threads[0]

    def _run(self, up, worker, move, extract):
        seen = {}
        with mock.patch.object(up, "add_log_to_run"), \
                mock.patch.object(up, "update_run_status"), \
                mock.patch.object(up.os, "makedirs"), \
                mock.patch.object(up.os, "remove"), \
                mock.patch("shutil.move", move), \
                mock.patch("shutil.rmtree"), \
                mock.patch.object(upload_extract, "extract_memory_from_upload", extract), \
                mock.patch.object(pipeline, "run_memory_pipeline",
                                  lambda **kw: seen.update(kw)), \
                mock.patch("services.file_storage_service.get_workflow",
                           lambda *a, **k: {"status": "running"}):
            worker()
        return seen

    def test_a_stop_during_staging_reaches_the_pipeline(self):
        up = _load_upload_routes()
        worker = self._worker(up)
        # The Stop lands mid-move; the row read is stubbed "running" so only
        # the event can carry it.
        seen = self._run(up, worker,
                         move=lambda *a: ws._cancel_events[RID].set(),
                         extract=lambda dest, **k: dest)
        self.assertTrue(seen["cancel_event"].is_set())
        self.assertNotIn(RID, ws._cancel_events)

    def test_a_failed_extract_unregisters_the_event(self):
        up = _load_upload_routes()
        worker = self._worker(up)

        def boom(*a, **k):
            raise upload_extract.UploadExtractError("not a memory image")
        seen = self._run(up, worker, move=lambda *a: None, extract=boom)
        self.assertEqual({}, seen)
        self.assertNotIn(RID, ws._cancel_events)


if __name__ == "__main__":
    unittest.main()
