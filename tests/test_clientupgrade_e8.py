"""Velociraptor client upgrade run (E8): no duplicate hunts on resume, one run at
a time even under a double-click, and a failed run leaves no live hunts or labels.
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velo_org  # noqa: E402
from services import velociraptor_clients as vc  # noqa: E402
from services import workflow_service as ws  # noqa: E402

TARGETS = [{"client_id": "C.1", "hostname": "A", "os": "windows", "from": "0.77.1", "org": "root"},
           {"client_id": "C.2", "hostname": "B", "os": "linux", "from": "0.77.1", "org": "OFM5G",
            "org_name": "intact-test"}]


def _run(hunts=None, fail_hunt=None):
    """Run _run_upgrade with Stop already pressed (the watch is not under test)."""
    made, stopped, labels, saved, logs, status = [], [], [], [], [], []

    def query(vql, timeout=120):
        org = velo_org.current() or "root"
        if "hunt(" in vql:
            if fail_hunt and fail_hunt in vql:
                raise RuntimeError("velociraptor went away")
            made.append(org)
            return [{"HuntId": f"H.{org}"}]
        if "hunt_update" in vql:
            stopped.append((org, vql.split("'")[1]))
        return []
    stop = threading.Event()
    if not fail_hunt:
        stop.set()
    run = {"details": {"stage": "rest", "package_version": "0.77.3", "label": "intact-upgrade-0.77.3-rest",
                       "targets": TARGETS, "watch_until": 9e12, "hunts": hunts or {}}}
    with mock.patch.object(vc, "packages_ready", return_value={"package_id": "p1"}), \
         mock.patch.object(vc, "prepare_org_packages"), \
         mock.patch.object(vc, "_query", side_effect=query), \
         mock.patch.object(vc, "_label_clients",
                           side_effect=lambda ids, label, op: labels.append((velo_org.current() or "root", op))), \
         mock.patch.object(ws, "get_automation_run", return_value=run), \
         mock.patch.object(ws, "add_log_to_run", side_effect=lambda rid, m, lvl="info", force=False: logs.append(m)), \
         mock.patch.object(ws, "update_run_status",
                           side_effect=lambda rid, st, **kw: (status.append(st),
                                                              saved.append(dict((kw.get("details") or {})
                                                                                .get("hunts") or {})))), \
         mock.patch.object(ws, "register_cancel_event", return_value=stop), \
         mock.patch.object(ws, "unregister_cancel"):
        vc._run_upgrade("run1")
    return made, stopped, labels, [h for h in saved if h], logs, status


class ResumeMakesNoDuplicateHunts(unittest.TestCase):
    def test_a_restart_after_one_hunt_creates_only_the_missing_one(self):
        made, _, _, saved, _, _ = _run(hunts={"windows": "H.root"})
        self.assertEqual(["OFM5G"], made)
        self.assertEqual({"windows": "H.root", "OFM5G:linux": "H.OFM5G"}, saved[-1])

    def test_all_hunts_present_creates_none(self):
        made, _, labels, _, _, _ = _run(hunts={"windows": "H.root", "OFM5G:linux": "H.OFM5G"})
        self.assertEqual([], made)
        self.assertNotIn("set", [op for _, op in labels])

    def test_each_hunt_is_saved_as_soon_as_it_exists(self):
        _, _, _, saved, _, _ = _run(fail_hunt="Linux")
        self.assertIn({"windows": "H.root"}, saved)


class FailedRunCleansUp(unittest.TestCase):
    def test_an_exception_stops_its_hunts_and_removes_its_labels(self):
        _, stopped, labels, _, logs, status = _run(fail_hunt="Linux")
        self.assertEqual([("root", "H.root")], stopped)
        self.assertIn(("root", "remove"), labels)
        self.assertIn(("OFM5G", "remove"), labels)
        self.assertEqual("failed", status[-1])
        self.assertTrue(any("velociraptor went away" in m for m in logs))


class OneRunAtATime(unittest.TestCase):
    def test_two_concurrent_starts_let_only_one_through(self):
        created, results = [], []

        def versions():
            time.sleep(0.2)          # the slow call that opened the race window
            return {"server_version": "0.77.3", "clients": []}

        def create(*a, **k):
            created.append(1)
            return f"run{len(created)}"
        target = {"client_id": "C.1", "hostname": "H", "os": "windows", "version": "0.77.2"}
        with mock.patch.object(vc, "running_upgrade", side_effect=lambda: {"name": "x"} if created else None), \
             mock.patch.object(vc, "client_versions", side_effect=versions), \
             mock.patch.object(vc, "packages_ready", return_value={"package_id": "p1"}), \
             mock.patch.object(vc, "pilot_passed", return_value=True), \
             mock.patch.object(vc, "upgrade_targets", return_value=([target], [])), \
             mock.patch.object(vc, "_run_upgrade"), \
             mock.patch.object(ws, "create_automation_run", side_effect=create), \
             mock.patch.object(ws, "add_log_to_run"), \
             mock.patch.object(ws, "update_run_status"):
            def go():
                try:
                    results.append(vc.start_upgrade("rest"))
                except ValueError as e:
                    results.append(str(e))
            ts = [threading.Thread(target=go) for _ in range(2)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        self.assertEqual(1, len(created))
        self.assertEqual(1, sum("still being followed" in r for r in results))


if __name__ == "__main__":
    unittest.main()
