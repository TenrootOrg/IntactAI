"""A schedule's runs land in the case chosen for it, not always in Default.

A scheduled run fires with no browser request, so the active case (X-Case-Id) is
unknown and _resolve_case_id fell back to Default for every scheduled run
(2026-10-21). The case is now stored on the schedule and passed to each run.
"""
import os
import sys
import threading
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "scheduled_case_executor", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                            "modules/backend/services/scheduler/executor.py"))
executor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(executor)
from services import kape_service, velociraptor_service, workflow_service, file_storage_service  # noqa: E402
from services.fusion import store  # noqa: E402

CASES = {"case_ir": {"name": "IR-42"}}


class JobCase(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(store, "get_case", lambda cid: CASES.get(cid))
        p.start()
        self.addCleanup(p.stop)

    def test_the_schedules_case(self):
        self.assertEqual("case_ir", executor._job_case({"id": "j", "case_id": "case_ir"}))

    def test_no_case_is_default_as_before(self):
        self.assertIsNone(executor._job_case({"id": "j"}))
        self.assertIsNone(executor._job_case({"id": "j", "case_id": ""}))

    def test_a_deleted_case_falls_back_to_default(self):
        self.assertIsNone(executor._job_case({"id": "j", "case_id": "case_gone"}))


class ScheduledRunGetsTheCase(unittest.TestCase):
    def setUp(self):
        self.created = []
        release = threading.Event()
        patches = [
            mock.patch.object(store, "get_case", lambda cid: CASES.get(cid)),
            mock.patch.object(kape_service, "run_kape_timesketch_pipeline", lambda *a, **k: release.wait(5)),
            mock.patch.object(velociraptor_service, "get_clients_from_snapshot",
                              lambda include_offline=False: [{"client_id": "C.1", "hostname": "H", "last_seen_at": 0}]),
            mock.patch.object(workflow_service, "create_automation_run",
                              lambda **kw: self.created.append(kw) or "run-1"),
            mock.patch.object(workflow_service, "add_log_to_run", lambda *a, **k: None),
            mock.patch.object(workflow_service, "update_run_status", lambda *a, **k: None),
            mock.patch.object(workflow_service, "register_cancel_event", lambda rid: threading.Event()),
            mock.patch.object(file_storage_service, "get_timesketch_blueprint", lambda bid: {"name": "BP", "settings": {}}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(release.set)
        self.addCleanup(executor._TIMESKETCH_ACTIVE.clear)

    def test_the_run_is_created_in_the_schedules_case(self):
        executor.run_timesketch_pipeline({"id": "j1", "name": "Nightly", "blueprint_id": "bp", "case_id": "case_ir"},
                                         ["C.1"])
        self.assertEqual("case_ir", self.created[0]["case_id"])

    def test_without_one_the_run_still_goes_to_default(self):
        executor.run_timesketch_pipeline({"id": "j2", "name": "Nightly", "blueprint_id": "bp"}, ["C.1"])
        self.assertIsNone(self.created[0]["case_id"])        # _resolve_case_id -> Default, as before


class RouteChoosesTheCase(unittest.TestCase):
    def setUp(self):
        try:
            from routes import scheduler_routes
        except Exception as e:                             # noqa: BLE001 -- flask not importable here
            self.skipTest(f"routes not importable: {e}")
        self.r = scheduler_routes
        patches = [mock.patch.object(store, "get_case", lambda cid: CASES.get(cid) or ({} if cid == "case_sys" else None)),
                   mock.patch.object(workflow_service, "_system_case_id", lambda: "case_sys"),
                   mock.patch.object(workflow_service, "_active_case_from_request", lambda: self.active)]
        self.active = None
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_chosen_else_active_else_default(self):
        self.assertEqual(("case_ir", None), self.r._schedule_case("case_ir"))
        self.active = "case_ir"
        self.assertEqual(("case_ir", None), self.r._schedule_case(""))
        self.active = None
        self.assertEqual((None, None), self.r._schedule_case(""))

    def test_never_the_system_workspace_and_never_a_missing_case(self):
        self.assertIsNotNone(self.r._schedule_case("case_sys")[1])
        self.active = "case_sys"
        self.assertEqual((None, None), self.r._schedule_case(""), "in System, nothing chosen: Default")
        self.assertIsNotNone(self.r._schedule_case("case_nope")[1])


if __name__ == "__main__":
    unittest.main()
