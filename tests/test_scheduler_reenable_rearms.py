"""Turning a schedule back on must re-arm it; editing a disabled one must not un-pause it.

update_scheduled_job used resume_job on enable. A paused month/year job (one-shot
DateTrigger) past its run date resumes to no fire time, and one that already fired
is gone, so "enable" did nothing and the error was swallowed. An edit rebuilt the
trigger unpaused, so a disabled job could fire (and the executor then skipped it,
using up the one-shot). The scan quietly stopped until the next backend restart.

APScheduler is not installed in the test run, so a small fake scheduler stands in.
It keeps the two behaviours that matter: resume/pause of a missing job raises, and
a one-shot that fires is removed.
"""
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("INTACT_STORAGE_BASE", tempfile.mkdtemp())  # package import writes a DB
import _optional_deps  # noqa: F401,E402


class _Trigger:
    def __init__(self, **kw):
        self.kw = kw


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
    _stub("apscheduler.triggers.cron", CronTrigger=_Trigger)
    _stub("apscheduler.triggers.interval", IntervalTrigger=_Trigger)
    _stub("apscheduler.triggers.date", DateTrigger=_Trigger)

from services.scheduler import jobs  # noqa: E402


class FakeScheduler:
    def __init__(self):
        self.jobs = {}

    def add_job(self, func, trigger, args, id, name, replace_existing):
        kw = getattr(trigger, "kw", {})
        nrt = kw.get("run_date") or kw.get("start_date") or (getattr(trigger, "run_date", None))
        self.jobs[id] = types.SimpleNamespace(id=id, next_run_time=nrt or datetime.utcnow())

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def remove_job(self, job_id):
        del self.jobs[job_id]

    def pause_job(self, job_id):
        self.jobs[job_id].next_run_time = None  # KeyError like JobLookupError

    def resume_job(self, job_id):
        self.jobs[job_id].next_run_time = None  # past one-shot resumes to nothing

    def fire_one_shot(self, job_id):
        self.jobs.pop(job_id)


class ReenableRearms(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.unlink, self.db)
        c = sqlite3.connect(self.db)
        c.execute("""CREATE TABLE scheduled_jobs (id TEXT PRIMARY KEY, name TEXT, description TEXT,
            interval_type TEXT, interval_value INTEGER, interval_unit TEXT, start_at TEXT,
            run_time TEXT, next_run_at TEXT, enabled INTEGER, updated_at TEXT)""")
        start = (datetime.utcnow() - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S")
        c.execute("INSERT INTO scheduled_jobs VALUES ('j','Monthly','', 'months',1,'months',?,'02:00',NULL,1,'')",
                  (start,))
        c.commit()
        c.close()
        self.sched = FakeScheduler()
        orig = (jobs.get_db_connection, jobs.get_scheduler)
        jobs.get_db_connection = lambda: sqlite3.connect(self.db)
        jobs.get_scheduler = lambda: self.sched
        self.addCleanup(lambda: (setattr(jobs, "get_db_connection", orig[0]),
                                 setattr(jobs, "get_scheduler", orig[1])))
        jobs.update_scheduled_job("j", {"run_time": "02:00"})  # arm it
        self.assertIsNotNone(self.sched.get_job("j").next_run_time)

    def _edit(self, **kw):
        # scheduler.js always sends the recurrence fields on an edit
        base = {"interval_value": 1, "interval_unit": "months", "run_time": "02:00"}
        base.update(kw)
        return jobs.update_scheduled_job("j", base)

    def test_disable_edit_reenable_rearms(self):
        jobs.toggle_scheduled_job("j", False)
        self._edit(name="Renamed")
        self.assertIsNone(self.sched.get_job("j").next_run_time, "edit un-paused a disabled job")
        row = jobs.toggle_scheduled_job("j", True)
        self.assertGreater(self.sched.get_job("j").next_run_time, datetime.utcnow())
        self.assertIsNotNone(row["next_run_at"])

    def test_reenable_after_one_shot_was_used_up(self):
        jobs.toggle_scheduled_job("j", False)
        self.sched.fire_one_shot("j")
        jobs.toggle_scheduled_job("j", True)
        self.assertIsNotNone(self.sched.get_job("j"), "enable left the job unarmed")
        self.assertGreater(self.sched.get_job("j").next_run_time, datetime.utcnow())

    def test_edit_while_disabled_stays_paused_and_shows_no_next_run(self):
        jobs.toggle_scheduled_job("j", False)
        row = self._edit(run_time="03:00")
        self.assertIsNone(self.sched.get_job("j").next_run_time)
        self.assertIsNone(row["next_run_at"])

    def test_disable_of_a_missing_job_does_not_raise(self):
        self.sched.fire_one_shot("j")
        row = jobs.toggle_scheduled_job("j", False)
        self.assertEqual(0, row["enabled"])


if __name__ == "__main__":
    unittest.main()
