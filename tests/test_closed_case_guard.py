"""A Closed case refuses new runs.

QA 2026-11-08: with a Closed case active, a Velociraptor hunt still started and
landed in it. Every new module run is tagged in workflow_service._resolve_case_id,
so the refusal sits there; the tus upload hook and log-data attachments check
before a byte is stored, since their run is opened only after.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import workflow_service as ws  # noqa: E402
from services.fusion import store  # noqa: E402

CASES = {
    "c_open": {"name": "IR-1", "case_status": "open"},
    "c_old": {"name": "IR-0"},                                  # from before case status existed
    "c_closed": {"name": "TEST v4", "case_status": "closed"},
    "c_contained": {"name": "IR-2", "case_status": "contained"},
}


class ClosedCaseRefusesRuns(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(store, "get_case", lambda cid: dict(CASES.get(cid) or {})),
                  mock.patch.object(ws, "_system_case_id", lambda: "c_system"),
                  mock.patch.object(ws, "_default_case_id", lambda: "c_default")):
            p.start()
            self.addCleanup(p.stop)

    def test_a_hunt_into_a_closed_case_is_refused_with_its_own_code(self):
        with self.assertRaises(ws.WorkspaceError) as cm:
            ws._resolve_case_id("velociraptor_hunt", "c_closed")
        self.assertEqual("case_closed", cm.exception.code)
        self.assertIn("TEST v4", str(cm.exception))
        self.assertIn("closed", str(cm.exception))

    def test_open_contained_and_old_cases_still_take_runs(self):
        for cid in ("c_open", "c_old", "c_contained"):
            self.assertEqual(cid, ws._resolve_case_id("velociraptor_hunt", cid))

    def test_system_ops_and_case_bookkeeping_are_not_refused(self):
        self.assertEqual("c_system", ws._resolve_case_id("case_export", "c_closed"))
        self.assertEqual("c_closed", ws._resolve_case_id("fusion_baseline", "c_closed"))

    def test_the_system_guard_keeps_its_code(self):
        self.assertEqual("workspace_system_blocked", ws.WorkspaceError("x").code)

    def test_a_failed_lookup_never_blocks(self):
        def boom(cid):
            raise RuntimeError("store down")
        with mock.patch.object(store, "get_case", boom):
            self.assertIsNone(ws.closed_case_error("c_closed"))

    def test_log_data_into_a_closed_case_is_refused_before_the_file_is_written(self):
        import io
        from services.fusion import case_files
        with mock.patch.object(case_files, "_store", lambda: store), \
                mock.patch.object(case_files, "_dir", side_effect=AssertionError("file written")):
            out = case_files.add("c_closed", io.BytesIO(b"x"), "fw.log", name="fw",
                                 description="d", data_type="auto")
        self.assertIn("closed", out.get("error", ""))


if __name__ == "__main__":
    unittest.main()
