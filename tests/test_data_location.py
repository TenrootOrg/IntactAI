"""Data location (services/data_location.py): Settings → General → Data location.

A move stops every service, so it must refuse to start under an upgrade, ask
before cutting off running work, and never start on a folder the host check
rejected. The disk warning levels drive the dashboard banner.
"""
import os
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import data_location as dl  # noqa: E402


class Paths(unittest.TestCase):
    def test_system_disk_spellings(self):
        for p in ("", "  ", None, "default", "system"):
            self.assertEqual("", dl.clean_path(p))

    def test_a_folder(self):
        self.assertEqual("/mnt/intact-data", dl.clean_path(" /mnt/intact-data/ "))

    def test_unsafe_paths_are_refused(self):
        for p in ("mnt/x", "/mnt/a b", "/mnt/../etc", "/mnt/x;rm -rf /", "/mnt/$(id)", "/mnt/'x'"):
            with self.assertRaises(ValueError, msg=p):
                dl.clean_path(p)


class StartMove(unittest.TestCase):
    _real_active_runs = staticmethod(dl.active_runs)

    def setUp(self):
        self.host_calls = []
        patches = [
            mock.patch.object(dl, "status", return_value={"state": "none"}),
            mock.patch.object(dl, "check", return_value={"ok": True, "used_bytes": 10}),
            mock.patch.object(dl, "host_run", side_effect=lambda argv, timeout=120: (self.host_calls.append(argv) or (0, "", ""))),
            mock.patch.object(dl, "active_runs", return_value=[]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_starts_the_script_on_the_host_as_a_systemd_unit(self):
        out = dl.start_move("/mnt/intact-data")
        self.assertEqual("starting", out["state"])
        argv = self.host_calls[-1]
        self.assertEqual("systemd-run", argv[0])
        self.assertEqual(["bash", dl.SCRIPT, "/mnt/intact-data", "--yes"], argv[-4:])

    def test_back_to_the_system_disk(self):
        dl.start_move("")
        self.assertEqual(["bash", dl.SCRIPT, "--default", "--yes"], self.host_calls[-1][-4:])

    def test_refused_while_an_upgrade_runs(self):
        dl.active_runs.return_value = [{"automation_type": "upgrade", "name": "Upgrade to X", "status": "running"}]
        with self.assertRaisesRegex(ValueError, "Upgrade to X"):
            dl.start_move("/mnt/intact-data", force=True)
        self.assertEqual([], self.host_calls)

    def test_asks_before_cutting_off_running_work(self):
        dl.active_runs.return_value = [{"automation_type": "velociraptor_collection", "name": "Collect", "status": "running"}]
        with self.assertRaisesRegex(ValueError, "still going"):
            dl.start_move("/mnt/intact-data")
        self.assertEqual("starting", dl.start_move("/mnt/intact-data", force=True)["state"])

    def test_case_records_are_not_running_work(self):
        from services import workflow_service as ws
        runs = [{"automation_type": "case", "name": "Case — Default", "status": "running"},
                {"automation_type": "fusion_baseline", "status": "running"},
                {"automation_type": "velociraptor_collection", "status": "running"}]
        with mock.patch.object(ws, "get_all_automation_runs", return_value=runs):
            self.assertEqual(["velociraptor_collection"],
                             [r["automation_type"] for r in StartMove._real_active_runs()])

    def test_never_starts_on_a_folder_the_host_rejected(self):
        dl.check.return_value = {"ok": False, "reason": "/mnt/x is on vfat filesystem"}
        with self.assertRaisesRegex(ValueError, "vfat"):
            dl.start_move("/mnt/x")
        self.assertEqual([], self.host_calls)

    def test_not_twice_at_once(self):
        dl.status.return_value = {"state": "running"}
        with self.assertRaisesRegex(ValueError, "already running"):
            dl.start_move("/mnt/intact-data")


class StartUndo(unittest.TestCase):
    """Undo switches back to the backup the last move kept, with no copy, so it
    must only start when that move recorded one, and never under running work."""
    setUp = StartMove.setUp
    DONE = {"state": "done", "undo_path": "", "undo_root_backup": "/var/lib/docker.before-move-1",
            "undo_data_backup": "/opt/intact/data.before-move-1", "old_copies": ["/var/lib/docker.before-move-1"]}

    def test_runs_the_script_with_undo(self):
        dl.status.return_value = dict(self.DONE)
        self.assertEqual("starting", dl.start_undo()["state"])
        self.assertEqual(["bash", dl.SCRIPT, "--undo"], self.host_calls[-1][-3:])

    def test_nothing_to_undo(self):
        for st in ({"state": "none"}, {"state": "failed", "undo_root_backup": "/x"},
                   {"state": "done", "old_copies": ["/x"]}):   # after a cleanup or an undo
            dl.status.return_value = st
            with self.assertRaisesRegex(ValueError, "no move to undo"):
                dl.start_undo()
        self.assertEqual([], self.host_calls)

    def test_asks_before_cutting_off_running_work(self):
        dl.status.return_value = dict(self.DONE)
        dl.active_runs.return_value = [{"automation_type": "velociraptor_collection", "name": "Collect", "status": "running"}]
        with self.assertRaisesRegex(ValueError, "still going"):
            dl.start_undo()
        self.assertEqual("starting", dl.start_undo(force=True)["state"])


class DiskLevels(unittest.TestCase):
    def test_levels(self):
        for used, level in ((50, "ok"), (80, "warning"), (89, "warning"), (90, "critical")):
            u = types.SimpleNamespace(total=100, used=used, free=100 - used)
            with mock.patch.object(dl.shutil, "disk_usage", return_value=u):
                self.assertEqual(level, dl.disk()["level"], used)


if __name__ == "__main__":
    unittest.main()
