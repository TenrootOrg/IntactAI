"""Run log lines live in their own table (workflow_logs), one INSERT per line.

They used to be a JSON array inside the run row: every line re-read and re-wrote
the whole run, so a fleet run's bytes written grew with the square of its line
count, all its worker threads queued on one lock, and a save that hit "database
is locked" was swallowed -- lines silently lost (fleet-scale audit F2).

What must not change: every reader still gets run["logs"] as a list of
{timestamp, level, message}, oldest first -- including runs written before the
table existed, whose lines stay embedded in the row.

Runs against a real SQLite database in a temp dir, created by init_storage().
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-wflogs-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import (  # noqa: E402
    delete_workflow, get_connection, get_workflow, get_workflow_logs, init_storage,
    load_workflows, get_workflows_by_case, save_workflow)
from services.storage.export_import import export_db, import_db  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402


def _mk(status, case_id):
    rid = ws.create_automation_run("velociraptor_collection", "t", case_id=case_id)
    ws.update_run_status(rid, status)
    return rid


def _msgs(rid):
    return [l["message"] for l in get_workflow(rid)["logs"]]


def _legacy(rid, lines):
    """A run the way an earlier version stored it: lines embedded in the row."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO workflows (run_id, automation_type, name, status, logs, case_id, created_at) "
        "VALUES (?, 'velociraptor_collection', 'old', 'completed', ?, 'c1', '2026-08-01T00:00:00')",
        (rid, json.dumps([{"timestamp": "2026-08-01T00:00:0%d" % i, "level": "info",
                           "message": m} for i, m in enumerate(lines)])))
    conn.commit()


class AppendIsOneInsert(unittest.TestCase):

    def test_ten_thousand_lines_stay_out_of_the_run_row(self):
        rid = _mk("running", "c1")
        t0 = time.time()
        for i in range(10000):
            ws.add_log_to_run(rid, f"line {i}")
        elapsed = time.time() - t0
        row = get_connection().execute(
            "SELECT logs FROM workflows WHERE run_id = ?", (rid,)).fetchone()
        self.assertEqual(row[0], "[]", "the run row no longer grows per line")
        msgs = _msgs(rid)
        self.assertEqual(len(msgs), 10000)
        self.assertEqual((msgs[0], msgs[-1]), ("line 0", "line 9999"))
        self.assertLess(elapsed, 60, "linear: 10k inserts, not 10k whole-row rewrites")

    def test_concurrent_writers_lose_nothing(self):
        rid = _mk("running", "c1")

        def worker(n):
            for i in range(200):
                ws.add_log_to_run(rid, f"t{n}-{i}")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(_msgs(rid)), 1600)

    def test_a_stale_save_cannot_erase_lines_or_errors(self):
        """The read-modify-write paths (status, details, phase) save the row they
        read. Lines and error counts appended in between must survive."""
        rid = _mk("running", "c1")
        stale = get_workflow(rid)                 # what a pipeline thread holds
        ws.add_log_to_run(rid, "appended meanwhile")
        ws.add_log_to_run(rid, "boom", "error")
        stale["phase"] = "Exporting"
        save_workflow(stale)
        run = get_workflow(rid)
        self.assertEqual([l["message"] for l in run["logs"]], ["appended meanwhile", "boom"])
        self.assertEqual(run["error_count"], 1)
        self.assertEqual(run["phase"], "Exporting")

    def test_error_lines_count_and_auto_fail_still_works(self):
        rid = _mk("running", "c1")
        ws.add_log_to_run(rid, "fatal", "error")
        ws.update_run_status(rid, "completed")
        run = get_workflow(rid)
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["error_count"], 1, "the summary line is not one more error")
        self.assertIn("auto-set to 'failed'", run["logs"][-1]["message"])
        self.assertEqual(run["logs"][-1]["level"], "error")

    def test_an_unknown_run_gets_no_orphan_lines(self):
        ws.add_log_to_run("no_such_run_1", "hello")
        n = get_connection().execute(
            "SELECT COUNT(*) FROM workflow_logs WHERE run_id = 'no_such_run_1'").fetchone()[0]
        self.assertEqual(n, 0)

    def test_delete_takes_the_lines_with_it(self):
        rid = _mk("running", "c1")
        ws.add_log_to_run(rid, "x")
        delete_workflow(rid)
        n = get_connection().execute(
            "SELECT COUNT(*) FROM workflow_logs WHERE run_id = ?", (rid,)).fetchone()[0]
        self.assertEqual(n, 0)


class ReadersSeeTheSameShape(unittest.TestCase):

    def test_legacy_lines_come_first_then_new_ones(self):
        _legacy("velociraptor_collection_1700000000001", ["old a", "old b"])
        ws.add_log_to_run("velociraptor_collection_1700000000001", "new c", force=True)
        rid = "velociraptor_collection_1700000000001"
        self.assertEqual(_msgs(rid), ["old a", "old b", "new c"])
        for reader in (load_workflows(), get_workflows_by_case("c1"),
                       ws.get_all_automation_runs(), ws.get_automation_runs_by_case("c1")):
            run = next(r for r in reader if r["run_id"] == rid)
            self.assertEqual([l["message"] for l in run["logs"]], ["old a", "old b", "new c"])
            self.assertEqual(set(run["logs"][0]), {"timestamp", "level", "message"})

    def test_with_logs_false_leaves_logs_out(self):
        rid = _mk("running", "c1")
        ws.add_log_to_run(rid, "x")
        self.assertNotIn("logs", get_workflow(rid, with_logs=False))

    def test_logs_endpoint_reader_pages_with_a_cursor(self):
        _legacy("velociraptor_collection_1700000000002", ["old"])
        rid = "velociraptor_collection_1700000000002"
        for i in range(5):
            ws.add_log_to_run(rid, f"n{i}", force=True)
        full = get_workflow_logs(rid)
        self.assertEqual([l["message"] for l in full["logs"]], ["old", "n0", "n1", "n2", "n3", "n4"])
        self.assertFalse(full["truncated"])
        tail = get_workflow_logs(rid, limit=2)
        self.assertEqual([l["message"] for l in tail["logs"]], ["n3", "n4"])
        self.assertTrue(tail["truncated"])
        self.assertEqual(tail["cursor"], full["cursor"])
        self.assertEqual(get_workflow_logs(rid, since=full["cursor"])["logs"], [])
        ws.add_log_to_run(rid, "n5", force=True)
        more = get_workflow_logs(rid, since=full["cursor"])
        self.assertEqual([l["message"] for l in more["logs"]], ["n5"])
        self.assertGreater(more["cursor"], full["cursor"])
        # A viewer that fell behind catches up in order, `limit` lines a poll.
        step = get_workflow_logs(rid, since=0, limit=2)
        self.assertEqual([l["message"] for l in step["logs"]], ["n0", "n1"])

    def test_backup_round_trip_keeps_every_line_once(self):
        rid = _mk("running", "c1")
        ws.add_log_to_run(rid, "a")
        ws.add_log_to_run(rid, "b")
        dump = export_db()
        wf = next(w for w in dump["workflows"] if w["run_id"] == rid)
        self.assertEqual([l["message"] for l in wf["logs"]], ["a", "b"])
        self.assertTrue(import_db({"workflows": [wf]}))
        self.assertEqual(_msgs(rid), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
