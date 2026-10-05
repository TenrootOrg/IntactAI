"""A slow plugin is not a stuck one.

Reported 2026-10-05 (Windows 11 IoT LTSC 24H2, 5 GB image): VolWeb runs the
selective plugins ONE AT A TIME, Malfind took 6 minutes, and the idle-grace exit
("row count stable for 300s") gave up on Malfind, MutantScan, NetScan, NetStat
and PsScan while the worker was still busy with them. The wait now holds while
the worker's log shows it RUNNING one of the plugins still missing.
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
from services.memory import volweb_client as vc  # noqa: E402

FAST = [f"volatility3.plugins.windows.p{i}.P{i}" for i in range(7)]
SLOW = "volatility3.plugins.windows.malfind.Malfind"


def row(name):
    return {"name": name, "results": True}


class Client(vc.VolWebClient):
    def __init__(self, busy_polls):
        super().__init__("http://x", "u", "p")
        self.polls = 0
        self.busy_polls = busy_polls
        self.lines = []
        self._logger = lambda m, lvl="info": self.lines.append(m)

    def list_plugins(self, _eid):
        self.polls += 1
        rows = [row(n) for n in FAST]
        if self.busy_polls and self.polls > self.busy_polls:
            rows.append(row(SLOW))
        return rows

    def plugin_in_progress(self, **_k):
        return "Malfind" if self.busy_polls and self.polls <= self.busy_polls else None

    def _evidence_snapshot(self, _eid):
        return {"celery_task_id": "T"}


def wait(c):
    with mock.patch.object(vc.time, "sleep"):
        return c.wait_for_plugin_results(1, FAST + [SLOW], task_id="T",
                                         idle_grace_s=-1, poll_s=0, timeout_s=60)


class SlowPlugin(unittest.TestCase):
    def test_a_plugin_still_running_is_waited_for(self):
        c = Client(busy_polls=5)
        done, completed = wait(c)
        self.assertIn(SLOW, done)
        self.assertTrue(completed)
        self.assertTrue(any("still running Malfind" in m for m in c.lines))
        self.assertFalse(any("proceeding without" in m for m in c.lines))

    def test_a_quiet_worker_still_gets_the_idle_exit(self):
        c = Client(busy_polls=0)
        done, completed = wait(c)
        self.assertNotIn(SLOW, done)
        self.assertTrue(any("proceeding without missing plugins: Malfind" in m for m in c.lines))


class ReadingTheWorkerLog(unittest.TestCase):
    def run_log(self, text):
        out = mock.Mock(stdout="", stderr=text)
        with mock.patch.object(vc.subprocess, "run", return_value=out):
            return vc.VolWebClient("http://x", "u", "p").plugin_in_progress()

    def test_the_last_running_line_names_the_plugin(self):
        self.assertEqual(self.run_log(
            "RUNNING: volatility3.plugins.windows.cmdline.CmdLine\n"
            "RUNNING: volatility3.plugins.windows.malfind.Malfind\n"), "Malfind")

    def test_a_finished_task_is_running_nothing(self):
        self.assertIsNone(self.run_log(
            "RUNNING: volatility3.plugins.windows.psscan.PsScan\n"
            "Task VolWeb.SelectiveEngine[a7b3] succeeded in 900.1s: None\n"))

    def test_no_docker_is_none(self):
        with mock.patch.object(vc.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIsNone(vc.VolWebClient("http://x", "u", "p").plugin_in_progress())


if __name__ == "__main__":
    unittest.main()
