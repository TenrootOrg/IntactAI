"""The shared run lifecycle (workflows.status) and the cancel registry.

QA items A1, A2, A3/C9, A5 (implicit-state-machines report, 2026-11-09):
  A1  a finished run was reopened by late writers (a tus post-receive after
      post-terminate, KAPE's progress timer) and Stop wrote 'cancelled' over a
      completed run; Plaso lines containing "error" failed good timelines.
  A2  request_stop popped the set Event, so is_cancelled()/get_cancel_event()
      answered "not cancelled" to every pipeline that polls by run id.
  A3  the boot reaper missed most in-backend run types, never looked at
      'uploaded', and failed runs created after boot.
  A5  only success armed the auto-fuse, so a stopped collection's rows stayed
      out of the graph until a manual Refusion.

Runs the real workflow_service against a real SQLite DB in a temp dir.
"""

import os
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta
from unittest import mock

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-core-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import delete_workflow, get_workflow, init_storage, save_workflow  # noqa: E402

init_storage()
from services import workflow_service as ws  # noqa: E402


def _wf(status, atype="velociraptor_collection", rid="r1", **extra):
    delete_workflow(rid)
    ws.unregister_cancel(rid)
    save_workflow({"run_id": rid, "status": status, "automation_type": atype,
                   "logs": [], **extra})
    return rid


def _status(rid="r1"):
    return (get_workflow(rid) or {}).get("status")


class FinishedRunsStayFinished(unittest.TestCase):

    def test_running_still_ends_normally(self):
        _wf("running")
        ws.update_run_status("r1", "completed", progress=100)
        self.assertEqual(_status(), "completed")

    def test_a_late_progress_tick_does_not_reopen(self):
        for end in ("completed", "failed"):
            _wf(end, error="Upload cancelled")
            self.assertFalse(ws.update_run_status("r1", "running", progress=4))
            self.assertEqual(_status(), end, f"{end} -> running must be refused")

    def test_stop_cannot_overwrite_a_finished_run(self):
        for end in ("completed", "failed"):
            _wf(end)
            ws.update_run_status("r1", "cancelled")
            self.assertEqual(_status(), end)

    def test_a_stopped_worker_may_still_write_its_final_progress(self):
        # kape_service / the scheduler batch write 'cancelled' + progress after Stop.
        _wf("cancelled", progress=10)
        self.assertTrue(ws.update_run_status("r1", "cancelled", progress=40))
        self.assertEqual((get_workflow("r1") or {}).get("progress"), 40)

    def test_a_presumed_failure_may_come_back(self):
        # tusd keeps receiving through a restart; the reaper's guess was wrong.
        _wf("failed", error="Interrupted by a backend restart — the task's worker...")
        ws.update_run_status("r1", "running", progress=5)
        self.assertEqual(_status(), "running")
        _wf("failed", error="Workflow idle for 11.0h with no updates (max: 10h)")
        ws.update_run_status("r1", "running", progress=5)
        self.assertEqual(_status(), "running")

    def test_the_deliberate_reopens_still_work(self):
        _wf("completed", atype="case", rid="case_1")
        ws.update_run_status("case_1", "pending")
        self.assertEqual(_status("case_1"), "pending", "a case row is re-fused for ever")
        for t in ("upgrade_package_upload", "upgrade", "prepare_package"):
            _wf("failed", atype=t)
            ws.update_run_status("r1", "running", progress=0)
            self.assertEqual(_status(), "running", f"{t}: apply retries on its own row")
        _wf("completed")
        ws.update_run_status("r1", "running", force=True)
        self.assertEqual(_status(), "running", "force=True is the escape hatch")


class StopIsRemembered(unittest.TestCase):

    def test_is_cancelled_stays_true_after_stop(self):
        _wf("running")
        ev = ws.register_cancel_event("r1")
        self.assertTrue(ws.request_stop("r1"))
        self.assertTrue(ev.is_set())
        self.assertTrue(ws.is_cancelled("r1"), "AWS/Azure poll this after Stop")
        self.assertIs(ws.get_cancel_event("r1"), ev)
        self.assertEqual(_status(), "cancelled")
        ws.unregister_cancel("r1")
        self.assertFalse(ws.is_cancelled("r1"))

    def test_a_late_registration_sees_the_stop(self):
        # memory upload: the worker registers after the route's ZIP extract
        _wf("running")
        ws.request_stop("r1")
        self.assertTrue(ws.register_cancel_event("r1").is_set())
        ws.unregister_cancel("r1")

    def test_cleanup_runs_once(self):
        _wf("running")
        ws.register_cancel_event("r1")
        cb = mock.Mock()
        ws.register_cleanup("r1", cb)
        ws.request_stop("r1")
        ws.request_stop("r1")
        cb.assert_called_once()
        ws.unregister_cancel("r1")

    def test_stop_on_a_finished_run_is_a_no_op(self):
        _wf("completed")
        ws.register_cancel_event("r1")
        cb = mock.Mock()                    # a memory run's cleanup deletes files
        ws.register_cleanup("r1", cb)
        self.assertFalse(ws.request_stop("r1"))
        cb.assert_not_called()
        self.assertFalse(ws.is_cancelled("r1"))
        self.assertEqual(_status(), "completed")
        ws.unregister_cancel("r1")

    def test_stop_ends_an_uploaded_row(self):
        _wf("uploaded", atype="azure_scan")
        self.assertTrue(ws.request_stop("r1"))
        self.assertEqual(_status(), "cancelled")
        ws.unregister_cancel("r1")


class EveryEndArmsTheAutoFuse(unittest.TestCase):

    def test_failed_and_cancelled_arm_it(self):
        from services.fusion import autofuse
        for end in ("completed", "failed", "cancelled"):
            _wf("running", case_id="case_9")
            with mock.patch.object(autofuse, "schedule") as sch:
                ws.update_run_status("r1", end)
            sch.assert_called_once()
            self.assertEqual(sch.call_args[0][0], "case_9", end)

    def test_progress_does_not_arm_it(self):
        from services.fusion import autofuse
        _wf("running", case_id="case_9")
        with mock.patch.object(autofuse, "schedule") as sch:
            ws.update_run_status("r1", "running", progress=50)
        sch.assert_not_called()


def _reap(runs):
    """Run app.py's reaper block against stub runs (the test_memory_batch_reaped way)."""
    with open(os.path.join(ROOT, "modules", "backend", "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    start = src.index("        _REAP_TYPES = {")
    block = textwrap.dedent(src[start:src.index("        if _reaped:", start)])
    failed = {}
    exec(block, {"load_workflows": lambda with_logs=True: runs,
                 "created_before_boot": ws.created_before_boot,
                 "update_run_status": lambda rid, st, error=None: failed.__setitem__(rid, st)})
    return failed


class TheBootReaper(unittest.TestCase):
    OLD = (datetime.now() - timedelta(hours=1)).isoformat()

    def _row(self, rid, atype, status="running", created=None):
        return {"run_id": rid, "automation_type": atype, "status": status,
                "created_at": created or self.OLD, "details": {}}

    def test_in_backend_types_are_reaped(self):
        types = ("case_export", "case_import", "decision_relevance", "support_bundle",
                 "timesketch_upload", "velociraptor_offline_import", "external_log")
        failed = _reap([self._row(t, t) for t in types])
        self.assertEqual(sorted(failed), sorted(types))

    def test_upgrades_and_server_side_runs_are_left_alone(self):
        types = ("upgrade", "online_upgrade", "upgrade_package_upload", "prepare_package",
                 "velociraptor_hunt", "velociraptor_client_upgrade", "case")
        self.assertEqual(_reap([self._row(t, t) for t in types]), {},
                         "reconcile_on_boot resumes the upgrade's own run")

    def test_a_run_created_after_boot_survives(self):
        new = (ws._PROCESS_STARTED_AT + timedelta(seconds=5)).isoformat()
        self.assertEqual(_reap([self._row("n", "case_export", created=new)]), {})

    def test_uploaded_azure_is_reaped_aws_is_not(self):
        failed = _reap([self._row("az", "azure_scan", "uploaded"),
                        self._row("aws", "aws_scan", "uploaded"),
                        self._row("done", "case_export", "completed")])
        self.assertEqual(list(failed), ["az"], "AWS keeps its upload on disk")


class PlasoChatterIsNotAnError(unittest.TestCase):

    def test_error_words_log_as_warning(self):
        from services import kape_upload_service as k

        class _P:
            stdout = iter(["Processing started.",
                           "[ERROR] parser chrome_cache skipped file: no such file",
                           "warning: unsupported format"])
            pid = 1

            def wait(self, timeout=None):
                return 0

            def poll(self):
                return 0

        seen = []
        with mock.patch.object(k, "PLASO_OUTPUT_DIR", tempfile.mkdtemp()), \
                mock.patch.object(k, "get_plaso_image", return_value="plaso"), \
                mock.patch.object(k.subprocess, "Popen", return_value=_P()):
            k.process_local_with_plaso("/tmp/src", "h", logger=lambda m, l="info": seen.append((m, l)))
        levels = {m: l for m, l in seen}
        self.assertEqual(levels["[ERROR] parser chrome_cache skipped file: no such file"], "warning")
        self.assertEqual(levels["warning: unsupported format"], "warning")
        self.assertEqual(levels["Processing started."], "info")


if __name__ == "__main__":
    unittest.main()
