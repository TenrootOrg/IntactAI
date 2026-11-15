"""Scheduled runs: run_count counts successes, Run now never stacks, Stop reaches scheduled agentic runs.

- run_count was bumped on dispatch, so a schedule that failed every night read "Runs: 30".
- Run now on a schedule whose run was still going started a second copy of the pipeline.
- A scheduled agentic run registered no cancel event, so Stop only changed the label.
"""
import os
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("INTACT_STORAGE_BASE", tempfile.mkdtemp())  # package import writes a DB
import _optional_deps  # noqa: F401,E402


def _stub(name, **attrs):
    if name not in sys.modules:
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        sys.modules[name] = mod


try:
    import apscheduler  # noqa: F401
except ImportError:
    for _n in ("apscheduler", "apscheduler.schedulers", "apscheduler.jobstores", "apscheduler.triggers"):
        _stub(_n)
    _stub("apscheduler.schedulers.background", BackgroundScheduler=object)
    _stub("apscheduler.jobstores.sqlalchemy", SQLAlchemyJobStore=object)
    for _n, _c in (("cron", "CronTrigger"), ("interval", "IntervalTrigger"), ("date", "DateTrigger")):
        _stub(f"apscheduler.triggers.{_n}", **{_c: object})

from services.scheduler import executor, jobs  # noqa: E402
from services import workflow_service, file_storage_service  # noqa: E402


class _DB(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.unlink, self.db)
        c = sqlite3.connect(self.db)
        c.execute("CREATE TABLE scheduled_jobs (id TEXT PRIMARY KEY, name TEXT, blueprint_id TEXT, "
                  "blueprint_type TEXT, client_ids TEXT, options TEXT, enabled INTEGER, "
                  "last_run_at TEXT, run_count INTEGER DEFAULT 0, updated_at TEXT, interval_unit TEXT)")
        c.execute("INSERT INTO scheduled_jobs VALUES ('j','Nightly','bp','agentic','[\"C.1\"]','{}',1,"
                  "NULL,0,'','days')")
        c.commit()
        c.close()
        for mod in (executor, jobs):
            p = mock.patch.object(mod, "get_db_connection", lambda: sqlite3.connect(self.db))
            p.start()
            self.addCleanup(p.stop)

    def run_count(self):
        c = sqlite3.connect(self.db)
        try:
            return c.execute("SELECT run_count FROM scheduled_jobs WHERE id='j'").fetchone()[0]
        finally:
            c.close()


class RunCountCountsSuccesses(_DB):
    def test_dispatch_does_not_count(self):
        executor.update_job_run_stats("j")
        self.assertEqual(0, self.run_count())

    def test_only_completed_runs_count(self):
        status = {}
        with mock.patch.object(workflow_service, "get_automation_run",
                               lambda rid, with_logs=True: {"status": status[rid]}):
            status.update(a="completed", b="failed", c="cancelled", d="running")
            for rid in "abcd":
                executor.count_if_completed("j", rid)
        self.assertEqual(1, self.run_count())

    def test_a_db_error_never_raises(self):
        with mock.patch.object(workflow_service, "get_automation_run", side_effect=RuntimeError("db")):
            executor.count_if_completed("j", "x")
        self.assertEqual(0, self.run_count())


class RunNowRefusesOverlap(_DB):
    def setUp(self):
        super().setUp()
        self.live = []   # rows load_workflows(statuses=pending/running) returns
        p = mock.patch.object(file_storage_service, "load_workflows",
                              lambda with_logs=True, statuses=None: list(self.live))
        p.start()
        self.addCleanup(p.stop)

    def test_refused_while_the_db_has_its_run_running(self):
        # As after a restart: nothing in memory, only the run row in the DB.
        self.live = [{"run_id": "other", "details": {"scheduled_job_id": "k"}},
                     {"run_id": "velociraptor_collection_1", "details": {"scheduled_job_id": "j"}}]
        with mock.patch.object(executor, "run_scheduled_blueprint") as run:
            with self.assertRaises(jobs.JobBusy) as cm:
                jobs.run_job_now("j")
        self.assertEqual("velociraptor_collection_1", cm.exception.run_id)
        run.assert_not_called()

    def test_double_click_starts_one_and_frees_after(self):
        release, started = threading.Event(), threading.Event()

        def slow(job_id):
            started.set()
            release.wait(5)

        with mock.patch.object(executor, "run_scheduled_blueprint", slow):
            self.assertTrue(jobs.run_job_now("j"))
            self.assertTrue(started.wait(5))
            with self.assertRaises(jobs.JobBusy) as cm:
                jobs.run_job_now("j")
            self.assertIsNone(cm.exception.run_id)
            release.set()
            for _ in range(100):
                if "j" not in jobs._DISPATCHING:
                    break
                threading.Event().wait(0.02)
            started.clear()
            self.assertTrue(jobs.run_job_now("j"))   # finished run: allowed again
            self.assertTrue(started.wait(5))

    def test_route_answers_409_with_a_message(self):
        try:
            import flask
        except ImportError:
            self.skipTest("flask not installed")
        from routes.scheduler_routes import scheduler_bp
        import routes.scheduler_routes as sr
        app = flask.Flask(__name__)
        app.register_blueprint(scheduler_bp)
        self.live = [{"run_id": "r1", "details": {"scheduled_job_id": "j"}}]
        with mock.patch.object(sr, "run_job_now", jobs.run_job_now):
            resp = app.test_client().post("/api/scheduler/jobs/j/run")
        self.assertEqual(409, resp.status_code)
        self.assertIn("r1", resp.get_json()["error"])
        self.assertIn("still running", resp.get_json()["error"])


class ScheduledAgenticRegistersCancel(_DB):
    def test_pipeline_gets_the_registered_event_and_counts_on_success(self):
        got, done = {}, threading.Event()

        def pipeline(run_id, bp, cids, minutes, cancel_event=None, run_settings=None):
            got["event"] = cancel_event
            got["registered"] = workflow_service.get_cancel_event(run_id)
            done.set()

        import services.agentic as agentic
        with mock.patch.object(agentic, "run_agentic_pipeline", pipeline), \
             mock.patch.object(file_storage_service, "get_agentic_blueprint", lambda bid: {"name": "BP"}), \
             mock.patch.object(workflow_service, "create_automation_run", lambda **kw: "sched_agentic_1"), \
             mock.patch.object(workflow_service, "get_automation_run",
                               lambda rid, with_logs=True: {"status": "completed"}), \
             mock.patch.object(executor, "_job_case", lambda meta: None):
            executor._run_scheduled_blueprint("j")
            self.assertTrue(done.wait(5))
            for _ in range(100):
                if self.run_count():
                    break
                threading.Event().wait(0.02)
        self.addCleanup(workflow_service.unregister_cancel, "sched_agentic_1")
        self.assertIsInstance(got["event"], threading.Event)
        self.assertIs(got["event"], got["registered"])   # Stop sets this very Event
        self.assertEqual(1, self.run_count())


if __name__ == "__main__":
    unittest.main()
