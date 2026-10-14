"""The KAPE -> Plaso -> Timesketch fleet pipeline is bounded (F4).

At 1,000 clients the old orchestrator started one monitor thread per client,
exported every finished collection at once into /tmp/plaso (root filesystem,
~2 GB each) while one consumer ran Plaso AND waited for Timesketch indexing
(up to 3 days) one host at a time. These drive the real pipeline with
Velociraptor, Plaso and Timesketch mocked out.
"""
import os
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
import zipfile
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import kape_service as ks  # noqa: E402
from services import kape_upload_service as kus  # noqa: E402
import services.archive_guard as archive_guard  # noqa: E402


class Peak:
    """Counts how many callers are inside a section at once."""

    def __init__(self):
        self.now = 0
        self.peak = 0
        self.lock = threading.Lock()

    def __enter__(self):
        with self.lock:
            self.now += 1
            self.peak = max(self.peak, self.now)

    def __exit__(self, *_):
        with self.lock:
            self.now -= 1


class Harness(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, True)
        self.logs = []
        self.statuses = []
        self.jobs = {}
        for name, value in {
            "PLASO_OUTPUT_DIR": self.out,
            "add_log_to_run": lambda run_id, m, l="info": self.logs.append((l, m)),
            "update_run_status": lambda run_id, st, **k: self.statuses.append(st),
            "add_job": lambda fid, d: self.jobs.__setitem__(fid, dict(d)),
            "update_job": lambda fid, d: self.jobs.setdefault(fid, {}).update(d),
            "unregister_cancel": lambda run_id: None,
            "cleanup_flow_export": lambda *a, **k: None,
            "run_kape_collection_grpc": lambda cid, **k: "F." + cid[2:],
            "TIMESKETCH_EXPORT_MIN_FREE_GB": 0,
        }.items():
            p = mock.patch.object(ks, name, value)
            p.start()
            self.addCleanup(p.stop)

    def run_pipeline(self, n, cancel_event=None):
        clients = [{"client_id": f"C.{i:016x}", "client_name": f"HOST-{i}"} for i in range(n)]
        ks.run_kape_timesketch_pipeline("run-1", clients, {"kape_target": "_KapeTriage"},
                                        {"sketch_name": "S"}, 100, cancel_event or threading.Event())
        return clients


class BoundedPipeline(Harness):
    def test_collectors_zip_staging_and_indexing_are_bounded_the_right_way(self):
        monitors, staged_zips, plaso, indexing = Peak(), Peak(), Peak(), Peak()
        zips_on_disk = []

        def monitor(*_a, **_k):
            with monitors:
                time.sleep(0.02)
            return "FINISHED"

        def export(cid, fid, path, logger=None):
            open(path, "w").close()
            with staged_zips.lock:
                zips_on_disk.append(len([f for f in os.listdir(self.out) if f.endswith(".zip")]))
            return True

        def upload(zip_path, original_filename, settings, run_id=None, cleanup_zip=True,
                   suppress_status_writes=False, on_plaso_done=None):
            self.assertTrue(suppress_status_writes)
            with plaso:
                time.sleep(0.02)
            os.remove(zip_path)
            on_plaso_done()
            with indexing:                      # Timesketch indexing wait: holds no slot
                time.sleep(0.15)
            return {"status": "completed", "sketch_id": 1, "timeline_id": 2}

        with mock.patch.object(ks, "TIMESKETCH_MAX_COLLECTORS", 4), \
                mock.patch.object(ks, "PLASO_MAX_CONCURRENT", 1), \
                mock.patch.object(ks, "monitor_flow_completion", monitor), \
                mock.patch.object(ks, "export_flow_to_zip", export), \
                mock.patch.object(kus, "process_kape_upload", upload):
            self.run_pipeline(30)

        self.assertLessEqual(monitors.peak, 4)            # not one thread per client
        self.assertEqual(monitors.peak, 4)
        self.assertLessEqual(max(zips_on_disk), 2)         # PLASO_MAX_CONCURRENT + 1 staged
        self.assertGreater(indexing.peak, 1)               # indexing waits overlap the next Plaso job
        self.assertEqual(self.statuses[-1], "completed")
        self.assertEqual(sum(1 for j in self.jobs.values() if j.get("status") == "completed"), 30)

    def test_low_disk_skips_the_host_clearly_instead_of_exporting(self):
        clock = {"t": 1000.0}

        def fake_time():
            clock["t"] += 600
            return clock["t"]

        class NoWaitEvent(threading.Event):
            def wait(self, timeout=None):
                return self.is_set()

        exported = []
        with mock.patch.object(ks, "TIMESKETCH_EXPORT_MIN_FREE_GB", 10 ** 6), \
                mock.patch.object(ks, "time", types.SimpleNamespace(time=fake_time)), \
                mock.patch.object(ks, "monitor_flow_completion", lambda *a, **k: "FINISHED"), \
                mock.patch.object(ks, "export_flow_to_zip", lambda *a, **k: exported.append(a) or True):
            self.run_pipeline(2, NoWaitEvent())

        self.assertEqual(exported, [])
        errors = [m for lvl, m in self.logs if lvl == "error"]
        self.assertEqual(sum("not enough free space" in m for m in errors), 2, errors)
        self.assertTrue(any("TIMESKETCH_EXPORT_MIN_FREE_GB" in m for lvl, m in self.logs if lvl == "warning"))
        self.assertEqual({j["status"] for j in self.jobs.values()}, {"failed"})


class OnePlasoLimitForEveryCaller(unittest.TestCase):
    """process_kape_upload takes the slot, so uploads, single imports, scheduled
    runs and start-multi share it; and it is free again before the indexing wait."""

    def test_plaso_stages_serialize_but_imports_overlap(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, True)
        plaso, imports = Peak(), Peak()
        done = []

        def fake_plaso(source_dir, client_name, **_k):
            with plaso:
                time.sleep(0.05)
            path = os.path.join(out, f"{client_name}.plaso")
            open(path, "w").close()
            return path

        def fake_import(*_a, **_k):
            with imports:
                time.sleep(0.2)
            return {"sketch_id": 1, "timeline_id": 2}

        zips = []
        for i in range(3):
            z = os.path.join(out, f"in{i}.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("C/x.txt", "x")
            zips.append(z)

        with mock.patch.object(kus, "_PLASO_SLOTS", threading.BoundedSemaphore(1)), \
                mock.patch.object(kus, "PLASO_OUTPUT_DIR", out), \
                mock.patch.object(kus, "add_log_to_run", lambda *a, **k: None), \
                mock.patch.object(kus, "update_run_status", lambda *a, **k: None), \
                mock.patch.object(kus, "process_local_with_plaso", fake_plaso), \
                mock.patch.object(kus, "run_pinfo", lambda *a, **k: {"event_count": 1}), \
                mock.patch.object(kus, "import_to_timesketch", fake_import), \
                mock.patch.object(archive_guard, "guard_zip", lambda *a, **k: {"members": 1}):
            threads = [threading.Thread(target=lambda z=z, i=i: done.append(kus.process_kape_upload(
                z, os.path.basename(z), {"client_name": f"H{i}"}, run_id=f"r{i}",
                on_plaso_done=lambda: None))) for i, z in enumerate(zips)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual([r["status"] for r in done], ["completed"] * 3)
        self.assertEqual(plaso.peak, 1)        # one Plaso at a time
        self.assertGreater(imports.peak, 1)    # the indexing wait does not hold the slot
        self.assertEqual([f for f in os.listdir(out) if f.endswith(".zip")], [])  # inputs dropped


if __name__ == "__main__":
    unittest.main()
