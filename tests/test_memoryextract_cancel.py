"""Stop during a memory-upload ZIP extract ends the unzip and drops the partial.

extract_memory_from_upload used to copy a multi-GB member to the end after Stop.
It now polls an optional should_cancel between chunks; both callers pass the
run's cancel Event.
"""
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import upload_extract as ue  # noqa: E402

MB = 1024 * 1024


class ExtractCancel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.zip = os.path.join(self.tmp.name, "dump.zip")
        with zipfile.ZipFile(self.zip, "w", zipfile.ZIP_STORED) as z:
            z.writestr("uploads/file/PhysicalMemory", b"\0" * (20 * MB))
        self.staging = os.path.join(self.tmp.name, "staging")
        p = mock.patch.object(ue, "_MIN_DUMP_SIZE", MB)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_stop_mid_extract_raises_and_removes_partial(self):
        calls = []

        def should_cancel():
            calls.append(1)
            return len(calls) > 2   # two 4 MB chunks land, then Stop
        with self.assertRaises(ue.UploadExtractCancelled) as cm:
            ue.extract_memory_from_upload(self.zip, staging_dir=self.staging,
                                          should_cancel=should_cancel)
        # Callers catch UploadExtractError; the cancel must take that path.
        self.assertIsInstance(cm.exception, ue.UploadExtractError)
        self.assertEqual([], os.listdir(self.staging))
        self.assertEqual(3, len(calls))

    def test_no_check_and_no_stop_extract_fully(self):
        for kw in ({}, {"should_cancel": lambda: False}):
            out = ue.extract_memory_from_upload(self.zip, staging_dir=self.staging, **kw)
            self.assertEqual(20 * MB, os.path.getsize(out))
            os.remove(out)

    def test_both_callers_pass_the_cancel_event(self):
        for rel in ("modules/backend/routes/memory_routes.py",
                    "modules/backend/routes/upload_routes.py"):
            src = open(os.path.join(ROOT, rel)).read()
            call = src[src.index("extract_memory_from_upload(\n"):]
            call = call[:call.index(")\n")]
            self.assertIn("should_cancel=cancel_event.is_set", call, rel)


if __name__ == "__main__":
    unittest.main()
