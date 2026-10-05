"""Cancelling a memory run stops its VolWeb tasks too.

2026-10-05: memory_1791192160389 was stopped while VolWeb indexed symbols; the
pipeline cancelled the Velociraptor flow and cleaned up, but VolWeb went on
running all twelve plugins for an image nobody wanted, holding the only worker.
VolWeb's own Stop revokes evidence.celery_task_id alone — the yarascan's id in
layered mode — so the run has to name its extraction task itself.
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import volweb_client as vc  # noqa: E402

MB = 1024 * 1024


def run_pipeline(cancelled):
    from services.memory import pipeline as pm
    d = tempfile.mkdtemp()
    stops, logs, flag = [], [], []

    class Client:
        def __init__(self, **_kw): pass
        def ensure_case(self, _n): return 1
        def register_existing_file(self, rel, **_kw): return 7
        def get_evidence(self, _i): return {"name": "x"}
        def stage_media_dir(self, _i): return None
        def yarascan_history(self, _i): return []
        def list_plugins(self, _i): return []
        def fetch_plugin(self, *_a, **_k): return None
        def trigger_extraction(self, *_a): return "EXTRACT-1"
        def harvest_symbols(self): return 0
        def stop_tasks(self, evidence_id, ids): stops.append((evidence_id, list(ids))); return list(ids)

        def wait_for_plugin_results(self, *_a, **_k):
            if cancelled:                       # the operator pressed Stop mid-extraction
                flag.append(True)
                raise vc.VolWebError("plugin extraction cancelled by operator")
            return ({}, True)

    def fake_acquire(client_id, dumps_dir, **_kw):
        p = os.path.join(dumps_dir, "PC-F.X.raw")
        with open(p, "wb") as fh:
            fh.write(b"M" * 2 * MB)
        return {"flow_id": "F.X", "host_path": p, "hostname": "PC", "size_bytes": 2 * MB,
                "shared_volume": True, "shared_basename": "PC-F.X.raw"}

    fakes = {"add_log_to_run": lambda _r, m, *a, **k: logs.append(m),
             "update_run_status": lambda *a, **k: None,
             "mutate_run_details": lambda *a, **k: None, "register_cleanup": lambda *a, **k: None,
             "unregister_cancel": lambda *a, **k: None, "cleanup_after_run": lambda **k: None,
             "register_cancel_event": lambda _r: type("E", (), {"is_set": staticmethod(lambda: bool(flag))})(),
             "acquire_memory_dump": fake_acquire, "_estimate_client_memory_bytes": lambda _c: 0,
             "_disk_preflight": lambda *a, **k: None, "VolWebClient": Client}
    saved = {k: getattr(pm, k) for k in fakes}
    for k, v in fakes.items():
        setattr(pm, k, v)
    try:
        pm.run_memory_pipeline(run_id="r1", client_id="C.1", client_name="PC",
                               mode="plugin", dumps_dir=d, case_name="c")
    finally:
        for k, v in saved.items():
            setattr(pm, k, v)
        shutil.rmtree(d, ignore_errors=True)
    return stops, logs


class TheRun(unittest.TestCase):
    def test_a_cancelled_run_stops_the_extraction_it_dispatched(self):
        stops, logs = run_pipeline(cancelled=True)
        self.assertTrue(stops, "\n".join(logs[-5:]))
        self.assertEqual(stops[0], (7, ["EXTRACT-1"]))
        self.assertTrue(any("stopped VolWeb task" in m for m in logs))

    def test_a_finished_run_stops_nothing(self):
        stops, _ = run_pipeline(cancelled=False)
        self.assertEqual(stops, [])


class StopTasks(unittest.TestCase):
    def test_both_the_extraction_and_the_task_on_the_evidence_are_stopped(self):
        c = vc.VolWebClient("http://x", "u", "p")
        ok = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(c, "_evidence_snapshot", return_value={"celery_task_id": "YARA-9"}), \
                mock.patch.object(vc.subprocess, "run", return_value=ok) as run:
            self.assertEqual(c.stop_tasks(7, ["EXTRACT-1"]), ["EXTRACT-1", "YARA-9"])
        cmd = run.call_args.args[0][-1]
        self.assertIn("control terminate SIGTERM EXTRACT-1 YARA-9", cmd)

    def test_nothing_to_stop_runs_nothing(self):
        c = vc.VolWebClient("http://x", "u", "p")
        with mock.patch.object(c, "_evidence_snapshot", return_value={"celery_task_id": ""}), \
                mock.patch.object(vc.subprocess, "run") as run:
            self.assertEqual(c.stop_tasks(7, [None]), [])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
