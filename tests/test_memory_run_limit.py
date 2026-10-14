"""Memory runs are bounded, and their disk checks see each other.

Fleet audit F5 (2026-10-14): a scheduled capture started one pipeline per client
in the same tick, and each disk preflight read free space on its own and reserved
nothing — so N runs all passed and N multi-GB images landed together. Executed,
not asserted about: the real run_memory_pipeline runs, with Velociraptor, VolWeb
and the workflow store faked out.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import acquire as acq  # noqa: E402
from services.memory import pipeline as pm  # noqa: E402

GiB = 1024 ** 3


class _Client:
    def __init__(self, **_kw): pass


def _run_many(n, limit, cancelled=lambda _rid: False, stagger=0.0):
    """Start ``n`` real pipelines at once; the fake acquisition measures how
    many are inside it together, then fails the run (cleanup + release path)."""
    lock, live, peak, entered, logs = threading.Lock(), [0], [0], [], {}

    def fake_acquire(client_id, **kw):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
            entered.append(kw["run_id"])
        time.sleep(0.3)
        with lock:
            live[0] -= 1
        raise acq.AcquisitionError("test stops here")

    def cancel_event(rid):
        return type("E", (), {"is_set": staticmethod(lambda: cancelled(rid))})()

    fakes = {"add_log_to_run": lambda rid, m, *a, **k: logs.setdefault(rid, []).append(m),
             "update_run_status": lambda *a, **k: None,
             "mutate_run_details": lambda *a, **k: None,
             "register_cleanup": lambda *a, **k: None,
             "unregister_cancel": lambda *a, **k: None,
             "cleanup_after_run": lambda **k: None,
             "register_cancel_event": cancel_event,
             "acquire_memory_dump": fake_acquire,
             "_estimate_client_memory_bytes": lambda _c: 1 * GiB,
             "VolWebClient": _Client}
    d = tempfile.mkdtemp()
    with mock.patch.multiple(pm, **fakes), \
            mock.patch.dict(os.environ, {"MEMORY_MAX_CONCURRENT_RUNS": str(limit)}), \
            mock.patch.object(pm, "_limit_cache", [float("-inf"), 2]), \
            mock.patch.object(pm.traceback, "print_exc"), \
            mock.patch.object(acq.shutil, "disk_usage",
                              return_value=mock.Mock(free=1000 * GiB)):
        threads = [threading.Thread(target=pm.run_memory_pipeline,
                                    kwargs={"run_id": f"r{i}", "client_id": f"C.{i}",
                                            "mode": "plugin", "dumps_dir": d})
                   for i in range(n)]
        for t in threads:
            t.start()
            time.sleep(stagger)
        for t in threads:
            t.join(30)
    return peak[0], entered, logs


class RunLimit(unittest.TestCase):
    def tearDown(self):
        self.assertEqual(pm._runs_active, 0, "a run kept its slot after it ended")
        self.assertEqual(acq._DISK_RESERVED, {}, "a run kept its disk reservation after it ended")

    def test_five_runs_with_limit_two_never_overlap_more_than_two(self):
        peak, entered, logs = _run_many(5, limit=2)
        self.assertEqual(peak, 2)
        self.assertEqual(sorted(entered), [f"r{i}" for i in range(5)], "every run got its turn")
        queued = [r for r, ls in logs.items() if any("pipeline: queued" in m for m in ls)]
        self.assertGreaterEqual(len(queued), 3, "a waiting run must say why nothing happens")

    def test_zero_means_no_limit(self):
        peak, _, _ = _run_many(4, limit=0)
        self.assertEqual(peak, 4)

    def test_a_run_stopped_while_queued_never_starts(self):
        # r0 takes the only slot; r1 queues behind it and is stopped while it waits.
        go = time.monotonic()
        _, entered, logs = _run_many(
            2, limit=1, stagger=0.05,
            cancelled=lambda rid: rid == "r1" and time.monotonic() - go > 0.15)
        self.assertEqual(entered, ["r0"])
        self.assertTrue(any("pipeline: queued" in m for m in logs["r1"]), logs["r1"])
        self.assertTrue(any("cancelled while queued" in m for m in logs["r1"]), logs["r1"])


class DiskReservation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.logs = []
        p = mock.patch.object(acq.shutil, "disk_usage", return_value=mock.Mock(free=10 * GiB))
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(pm, "add_log_to_run", lambda _r, m, *a, **k: self.logs.append(m))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(acq._DISK_RESERVED.clear)

    def test_third_preflight_fails_when_free_space_fits_two(self):
        # 10 GiB free; each run needs 3 GiB × 1.5 = 4.5 GiB, so two fit.
        pm._disk_preflight("r1", self.d, 3 * GiB)
        pm._disk_preflight("r2", self.d, 3 * GiB)
        with self.assertRaises(RuntimeError) as cm:
            pm._disk_preflight("r3", self.d, 3 * GiB)
        self.assertIn("reserved by other memory runs", str(cm.exception))
        acq.release_disk("r1")                          # r1 finished
        pm._disk_preflight("r3", self.d, 3 * GiB)
        self.assertEqual(set(acq._DISK_RESERVED), {"r2", "r3"})

    def test_the_acquire_preflight_does_not_reserve_the_same_run_twice(self):
        pm._disk_preflight("r1", self.d, 2 * GiB)       # reserves 3 GiB
        with mock.patch.object(acq, "_client_total_ram", return_value=2 * GiB):
            acq._preflight_capacity("C.1", self.d, {"max_bytes": 64 * GiB},
                                    lambda *a: None, "r1")   # est 2.6 GiB, same run
            self.assertEqual(acq._DISK_RESERVED, {"r1": 3 * GiB})
            # Another run's acquire sees r1's 3 GiB held, not 3 + 2.6.
            acq._preflight_capacity("C.2", self.d, {"max_bytes": 64 * GiB},
                                    lambda *a: None, "r2")
            self.assertEqual(acq._DISK_RESERVED["r2"], int(2 * GiB * 1.3))
        # 10 - 5.6 GiB held = 4.4 GiB left; a 4 GiB client's ~5.2 GiB image does not fit.
        with mock.patch.object(acq, "_client_total_ram", return_value=4 * GiB):
            with self.assertRaises(acq.AcquisitionError):
                acq._preflight_capacity("C.3", self.d, {"max_bytes": 64 * GiB},
                                        lambda *a: None, "r3")
        self.assertNotIn("r3", acq._DISK_RESERVED)


if __name__ == "__main__":
    unittest.main()
