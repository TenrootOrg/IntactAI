"""stream_collect_and_analyze at fleet scale (F10, fleet-scale audit 2026-10-14).

Each 30 s poll walked every flow in turn, finished ones included (enumerate, a
fetch per source, a status check): at 1,000 flows one poll took minutes. The
heartbeat named every client, a ~25 KB line every minute.

Drives the REAL loop against a fake fleet on a simulated clock (the harness of
test_errored_flow_keeps_collecting.py).
"""
import importlib.util
import os
import threading
import time as real_time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "_errflow", os.path.join(HERE, "test_errored_flow_keeps_collecting.py"))
_errflow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_errflow)

SRC = "Windows.EventLogs.RDPAuth"


class Fleet:
    """Flow k finishes at finish[k]. Its LAST batch becomes visible only after a
    status check has reported FINISHED -- the gap the one post-finish fetch is
    there to close."""

    def __init__(self, finish, slow=0.0):
        self.finish = finish                       # flow_id -> seconds
        self.now = 0
        self.slow = slow
        self.reported = set()
        self.calls = []                            # (now, kind, flow_id)
        self.lock = threading.Lock()
        self.inflight = self.max_inflight = 0

    def _enter(self, kind, fid):
        with self.lock:
            self.calls.append((self.now, kind, fid))
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        if self.slow:
            real_time.sleep(self.slow)
        with self.lock:
            self.inflight -= 1

    def _rows(self, fid):
        n = min(self.now, self.finish[fid]) // 30
        return int(n) + (1 if fid in self.reported else 0)

    def check_flow_status(self, stub, cid, fid):
        self._enter("status", fid)
        if self.now >= self.finish[fid]:
            with self.lock:
                self.reported.add(fid)
            return "FINISHED", None
        return "RUNNING", None

    def enumerate_flow_sources(self, stub, cid, fid):
        self._enter("enumerate", fid)
        return [SRC]

    def query_artifact_results(self, stub, cid, fid, source, start_iso=None, end_iso=None, start_row=0):
        self._enter("query", fid)
        return [{"flow": fid, "i": i} for i in range(int(start_row or 0), self._rows(fid))]


class _Base(unittest.TestCase):
    def collect(self, fleet, minutes=30, workers=None):
        mod = _errflow._load()
        for k in ("check_flow_status", "enumerate_flow_sources", "query_artifact_results"):
            setattr(mod, k, getattr(fleet, k))
        self.logs = []
        mod.add_log_to_run = lambda rid, msg, lvl="info": self.logs.append((lvl, msg))
        mod.register_cleanup = mod.cancel_collections = lambda *a, **k: None
        mod.time = types.SimpleNamespace(sleep=lambda s: setattr(fleet, "now", fleet.now + s),
                                         monotonic=lambda: fleet.now)
        if workers:
            mod.POLL_WORKERS = workers
        flows = [{"client_id": f"C.{f}", "flow_id": f, "hostname": f"host-{f}"} for f in fleet.finish]
        return mod.stream_collect_and_analyze("run_1", flows, [SRC], minutes)


class TestFinishedFlowsAreLeftAlone(_Base):

    def setUp(self):
        self.fleet = Fleet({f"F.{k}": 60 + 30 * (k % 5) for k in range(40)} | {"F.slow": 900})
        self.results, self.timed_out = self.collect(self.fleet)

    def test_a_finished_flow_gets_one_more_fetch_then_nothing(self):
        for fid, fin in self.fleet.finish.items():
            seen_done = min(t for t, kind, f in self.fleet.calls if f == fid and kind == "status"
                            and t >= fin)
            later = [t for t, kind, f in self.fleet.calls if f == fid and t > seen_done]
            with self.subTest(flow=fid):
                if fid == "F.slow":             # the last one ends the loop: final pass only
                    continue
                self.assertEqual({seen_done + 30}, set(later),
                                 f"{fid} was still polled after it drained")

    def test_no_row_is_lost_including_the_late_batch(self):
        rows = self.results[SRC]
        for fid, fin in self.fleet.finish.items():
            with self.subTest(flow=fid):
                got = [r["i"] for r in rows if r["flow"] == fid]
                self.assertEqual(list(range(fin // 30 + 1)), got)
        self.assertFalse(self.timed_out)

    def test_the_cost_tracks_running_flows_not_all_flows(self):
        # 41 flows over 31 polls: re-polling everything is ~3,800 calls.
        self.assertLess(len(self.fleet.calls), 800, len(self.fleet.calls))


class TestPolling(_Base):

    def test_flows_are_polled_concurrently_and_bounded(self):
        fleet = Fleet({f"F.{k}": 60 for k in range(24)}, slow=0.005)
        self.collect(fleet, workers=8)
        self.assertGreater(fleet.max_inflight, 1, "flows were still polled one at a time")
        self.assertLessEqual(fleet.max_inflight, 8)

    def test_one_worker_gives_the_same_result(self):
        finish = {f"F.{k}": 30 * (k % 4 + 1) for k in range(12)}
        a, _ = self.collect(Fleet(finish), workers=1)
        b, _ = self.collect(Fleet(finish), workers=8)
        self.assertEqual(a, b)


class TestHeartbeat(_Base):

    def heartbeat(self, n):
        self.collect(Fleet({f"F.{k}": 10 ** 6 for k in range(n)}), minutes=3)
        return [m for _l, m in self.logs if m.startswith("[Pipeline] Per-client:")]

    def test_a_small_run_names_each_client(self):
        lines = self.heartbeat(3)
        self.assertTrue(lines)
        self.assertIn("host-F.0:1", lines[0])

    def test_a_fleet_run_gives_counts(self):
        lines = self.heartbeat(500)
        self.assertTrue(lines)
        self.assertLess(max(len(m) for m in lines), 200, lines[0][:300])
        self.assertIn("500 running", lines[0])


if __name__ == "__main__":
    unittest.main()
