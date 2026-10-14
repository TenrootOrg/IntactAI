"""Finished runs age out after options.workflow_retention_days (fleet F24).

Run history had no retention: scheduled per-client jobs add a row per host per
firing and nothing deleted them. Now an hourly sweep deletes finished runs last
touched more than N days ago (default 90, 0 = never), with their log lines.

What it must never delete: a running/pending run, a case container, and any run
that is a case's evidence -- fusion reads every member run, failed and cancelled
included, so aging one out would silently drop data from the next fuse.

Real SQLite in a temp dir, created by init_storage().
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-retention-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import get_connection, init_storage  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402

OLD, NEW = "2020-01-01T00:00:00", "2999-01-01T00:00:00"


def _row(run_id, atype, status, when=OLD, details=None):
    get_connection().execute(
        "INSERT INTO workflows (run_id, automation_type, name, status, details, created_at, updated_at) "
        "VALUES (?, ?, 'r', ?, ?, ?, ?)", (run_id, atype, status, json.dumps(details or {}), when, when))
    get_connection().execute(
        "INSERT INTO workflow_logs (run_id, ts, level, msg) VALUES (?, ?, 'info', 'x')", (run_id, when))
    get_connection().commit()


def _ids():
    return {r[0] for r in get_connection().execute("SELECT run_id FROM workflows")}


def _log_ids():
    return {r[0] for r in get_connection().execute("SELECT DISTINCT run_id FROM workflow_logs")}


class Retention(unittest.TestCase):

    def setUp(self):
        conn = get_connection()
        conn.execute("DELETE FROM workflows")
        conn.execute("DELETE FROM workflow_logs")
        conn.commit()
        _row("upgrade_1", "upgrade", "completed")                      # old system run: goes
        _row("maintenance_1", "maintenance", "failed")                 # old failed system run: goes
        _row("settings_new", "settings", "completed", when=NEW)        # recent: stays
        _row("maintenance_live", "maintenance", "running")             # not finished: stays
        _row("velociraptor_collection_1", "velociraptor_collection", "completed")   # case evidence
        _row("velociraptor_collection_2", "velociraptor_collection", "cancelled")   # still evidence
        _row("velociraptor_offline_import_1", "velociraptor_offline_import", "completed")  # legacy member
        _row("case_1", "case", "completed",
             details={"member_run_ids": ["velociraptor_offline_import_1", None]})
        _row("fusion_baseline_1", "fusion_baseline", "completed")
        get_connection().execute(
            "INSERT INTO workflow_logs (run_id, msg) VALUES ('deleted_long_ago', 'orphan')")
        get_connection().commit()

    def _purge(self, days):
        with mock.patch("config.get_installation_options",
                        return_value={"workflow_retention_days": days}):
            return ws.purge_old_runs()

    def test_old_finished_non_case_runs_go_with_their_lines(self):
        gone = self._purge(90)
        self.assertEqual(sorted(gone), ["maintenance_1", "upgrade_1"])
        self.assertEqual(_ids(), {"settings_new", "maintenance_live", "velociraptor_collection_1",
                                  "velociraptor_collection_2", "velociraptor_offline_import_1",
                                  "case_1", "fusion_baseline_1"})
        self.assertEqual(_log_ids(), _ids(), "their log lines and orphan lines are gone too")

    def test_zero_disables_it(self):
        self.assertEqual(self._purge(0), [])
        self.assertIn("upgrade_1", _ids())

    def test_default_is_90_days(self):
        with mock.patch("config.get_installation_options", return_value={}):
            self.assertEqual(ws._retention_days(), 90)

    def test_an_unreadable_setting_deletes_nothing(self):
        self.assertEqual(self._purge("ninety"), [])
        self.assertIn("upgrade_1", _ids())


if __name__ == "__main__":
    unittest.main()
