"""A new workflow run must never take the id of a run that is already stored.

run_id is `{type}_{ms}` and save_workflow() writes with INSERT OR REPLACE, so a
duplicate id does not fail -- it silently overwrites the stored run. Within one
process ids already only increase; these tests cover the other half: runs that were
stored BEFORE this process started, including runs written by earlier versions of the
product, on a box whose clock is behind them (a VM snapshot restore, an NTP step, a
database carried over from a machine whose clock ran ahead).

Runs against a real SQLite database in a temp dir, created by the product's own
init_storage(), with "earlier version" rows inserted as plain SQL.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="intact-runid-")
os.environ["INTACT_STORAGE_BASE"] = _TMP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import get_connection, get_workflow, init_storage  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402


def _store_old_run(run_id, name="written by an earlier version"):
    """Insert a row the way an earlier version left it: plain SQL, no product code."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO workflows (run_id, automation_type, name, status, created_at) "
        "VALUES (?, ?, ?, 'completed', '2026-08-01T00:00:00')",
        (run_id, run_id.rsplit("_", 1)[0], name))
    conn.commit()


def _ms(run_id):
    return int(run_id.rsplit("_", 1)[1])


class NewIdsNeverTakeAStoredRun(unittest.TestCase):

    def setUp(self):
        conn = get_connection()
        conn.execute("DELETE FROM workflows")
        conn.commit()
        ws._last_run_ms[0] = None          # a freshly started backend

    def test_a_clock_behind_a_stored_run_skips_its_id(self):
        _store_old_run("maintenance_1789000000000")
        # The clock reads exactly the stored run's millisecond.
        with mock.patch.object(ws.time, "time", return_value=1789000000.000):
            rid = ws._next_run_id("maintenance")
        self.assertNotEqual("maintenance_1789000000000", rid)
        self.assertGreater(_ms(rid), 1789000000000)

    def test_creating_a_run_leaves_the_stored_run_intact(self):
        _store_old_run("maintenance_1789000000000", name="the evidence")
        with mock.patch.object(ws.time, "time", return_value=1789000000.000):
            new_id = ws.create_automation_run("maintenance", "new run")
        old = get_workflow("maintenance_1789000000000")
        self.assertIsNotNone(old, "the stored run is still there")
        self.assertEqual("the evidence", old["name"], "and it was not overwritten")
        self.assertIsNotNone(get_workflow(new_id), "the new run was stored too")

    def test_new_ids_start_above_a_future_dated_stored_run(self):
        # A database from a box whose clock ran a day ahead.
        future = 1789000000000 + 86_400_000
        _store_old_run(f"agentic_{future}")
        with mock.patch.object(ws.time, "time", return_value=1789000000.000):
            rid = ws._next_run_id("agentic")
        self.assertGreater(_ms(rid), future)

    def test_ids_in_other_shapes_do_not_break_the_counter(self):
        for rid in ("aws_offline_2f5615076aea", "azure_offline_8a8016ba8d14",
                    "custom_run", "legacy-run-id", "case_1789377446038"):
            _store_old_run(rid)
        rid = ws._next_run_id("velociraptor_adopt")
        self.assertRegex(rid, r"^velociraptor_adopt_\d{13}$")
        self.assertGreater(_ms(rid), 1789377446038)

    def test_ids_keep_their_format_and_keep_increasing(self):
        ids = [ws._next_run_id("agentic") for _ in range(50)]
        for rid in ids:
            self.assertRegex(rid, r"^agentic_\d{13}$")
        self.assertEqual(ids, sorted(ids, key=_ms), "monotonic")
        self.assertEqual(len(ids), len(set(ids)), "unique")

    def test_storage_trouble_never_stops_a_run_being_created(self):
        with mock.patch("services.storage.get_connection",
                        side_effect=RuntimeError("database is locked")):
            rid = ws._next_run_id("maintenance")
        self.assertRegex(rid, r"^maintenance_\d{13}$")

    def test_a_long_run_of_taken_ids_is_skipped(self):
        base = 1789000000000
        for i in range(5):
            _store_old_run(f"maintenance_{base + i}")
        ws._last_run_ms[0] = 0              # as if the seed read nothing
        with mock.patch.object(ws.time, "time", return_value=base / 1000):
            rid = ws._next_run_id("maintenance")
        self.assertEqual(f"maintenance_{base + 5}", rid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
