"""A long collection must not strangle itself re-downloading what it already has.

WHAT HAPPENED (QA appliance, 2026-08-26, run velociraptor_collection_1787727431255).
A 10-minute BestPractice collection on DESKTOP-9RNKFB0. The poll loop re-fetched
every discovered source IN FULL every 30 seconds, so each poll got slower as the
data grew, while `elapsed` was incremented by a flat 30 per iteration. The gaps
between "one minute" heartbeats measured:

    75s, 130s, 139s, 205s, 287s, 234s, 229s

so at the last heartbeat the pipeline believed 7m30s had passed when 22m10s
really had — a 3.0x drift. The watchdog (window + 15 min grace = 1500s) fired 32
seconds after "All 1 flows completed!", and because the cancel check sat ABOVE
persist_pipeline_artifacts, all ~465,000 rows collected over 25 minutes were
discarded: no raw_results.json, no totals, nothing to fuse or re-collect from.

THE FIX HAS THREE PARTS AND EACH HAS ITS OWN FAILURE MODE:
  * fetch only the tail (Velociraptor's source() takes start_row — measured
    354,831 rows in 46.8s versus 4,831 rows in 0.6s from start_row=350000);
  * measure elapsed against the wall clock, so a 10-minute window means ten
    minutes however slow the polls are;
  * save what was collected BEFORE honouring a cancel, so no future variation
    on this can destroy the evidence.
"""

import importlib.util
import os
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STREAM = os.path.join(ROOT, "modules/backend/services/agentic/collectors/_stream.py")
BASE = os.path.join(ROOT, "modules/backend/services/agentic/collectors/_base.py")
RUNNERS = os.path.join(ROOT, "modules/backend/services/agentic/pipeline/_runners.py")
HELPERS = os.path.join(ROOT, "modules/backend/services/agentic/pipeline/_helpers.py")
WFSVC = os.path.join(ROOT, "modules/backend/services/workflow_service.py")

_spec = importlib.util.spec_from_file_location(
    "_errflow", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "test_errored_flow_keeps_collecting.py"))
_errflow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_errflow)


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


class GrowingFlow:
    """A flow that keeps producing, and counts what we ask it for.

    `rows_served` is the whole point: it is the network/gRPC cost. Re-fetching
    in full makes it grow with the square of the collection's length; fetching
    tails makes it equal the data exactly once.
    """

    def __init__(self, per_poll=1000, finish_at=600):
        self.now = 0
        self.per_poll = per_poll
        self.finish_at = finish_at
        self.rows_served = 0
        self.max_start_row = 0

    def _available(self):
        return int(min(self.now, self.finish_at) * self.per_poll / 30)

    def check_flow_status(self, stub, client_id, flow_id):
        return ("FINISHED", None) if self.now >= self.finish_at else ("RUNNING", None)

    def enumerate_flow_sources(self, stub, client_id, flow_id):
        return ["Big.Artifact"]

    def query_artifact_results(self, stub, client_id, flow_id, source,
                               start_iso=None, end_iso=None, start_row=0):
        self.max_start_row = max(self.max_start_row, int(start_row or 0))
        rows = [{"i": i} for i in range(int(start_row or 0), self._available())]
        self.rows_served += len(rows)
        return rows


class _Base(unittest.TestCase):
    def setUp(self):
        self.mod = _errflow._load()
        self.flow = GrowingFlow()
        self.mod.check_flow_status = self.flow.check_flow_status
        self.mod.enumerate_flow_sources = self.flow.enumerate_flow_sources
        self.mod.query_artifact_results = self.flow.query_artifact_results
        self.logs = []
        self.mod.add_log_to_run = lambda rid, msg, lvl="info": self.logs.append((lvl, msg))
        self.mod.register_cleanup = lambda *a, **k: None
        self.mod.cancel_collections = lambda *a, **k: None
        # Simulated clock: sleeping advances it, and monotonic() reads it, so the
        # loop's new wall-clock accounting is genuinely exercised.
        self.mod.time = types.SimpleNamespace(
            sleep=lambda s: setattr(self.flow, "now", self.flow.now + s),
            monotonic=lambda: self.flow.now)

    def collect(self, minutes=10):
        flows = [{"client_id": "C.1", "flow_id": "F.1", "hostname": "h1"}]
        return self.mod.stream_collect_and_analyze("run_1", flows, ["Big.Artifact"], minutes)


class TestItFetchesOnlyWhatIsNew(_Base):

    def test_no_row_is_downloaded_twice(self):
        results, _ = self.collect()
        stored = sum(len(v) for v in results.values())
        self.assertEqual(self.flow.rows_served, stored,
                         f"served {self.flow.rows_served} rows to store {stored} — "
                         f"the loop is re-downloading data it already has")

    def test_it_asks_velociraptor_to_skip(self):
        self.collect()
        self.assertGreater(self.flow.max_start_row, 0,
                           "start_row never used — every poll refetched from zero")

    def test_rows_are_appended_not_replaced(self):
        # Replacing is what let a short read shrink a source mid-collection
        # (479,334 -> 455,315 in the real run).
        results, _ = self.collect()
        rows = results["Big.Artifact"]
        self.assertEqual([r["i"] for r in rows], list(range(len(rows))),
                         "rows are out of order or duplicated — not a clean append")

    def test_a_longer_collection_costs_proportionally_not_quadratically(self):
        short = GrowingFlow(finish_at=10 ** 9)
        long = GrowingFlow(finish_at=10 ** 9)
        for flow, minutes in ((short, 5), (long, 20)):
            self.setUp()
            self.flow = flow
            self.mod.check_flow_status = flow.check_flow_status
            self.mod.enumerate_flow_sources = flow.enumerate_flow_sources
            self.mod.query_artifact_results = flow.query_artifact_results
            self.mod.time = types.SimpleNamespace(
                sleep=lambda s, f=flow: setattr(f, "now", f.now + s),
                monotonic=lambda f=flow: f.now)
            self.collect(minutes=minutes)
        # 4x the duration is 4x the data. Re-fetching in full would make the
        # BYTES MOVED grow ~16x; tails keep it at 4x.
        ratio = long.rows_served / max(short.rows_served, 1)
        self.assertLess(ratio, 6, f"cost grew {ratio:.1f}x for 4x the duration")


class TestTheClockIsTheWallClock(_Base):

    def test_elapsed_is_measured_not_tallied(self):
        src = read(STREAM)
        code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
        self.assertNotIn("elapsed += interval", code,
                         "elapsed is still a tally of intervals, not real time")
        self.assertIn("time.monotonic()", code)

    def test_a_slow_poll_does_not_extend_the_window(self):
        # The regression in one assertion: make every poll take four times the
        # interval and the collection must still end on time.
        slow = GrowingFlow(finish_at=10 ** 9)
        real = slow.query_artifact_results

        def slow_fetch(*a, **kw):
            slow.now += 90            # each fetch burns 3 extra intervals
            return real(*a, **kw)

        self.mod.check_flow_status = slow.check_flow_status
        self.mod.enumerate_flow_sources = slow.enumerate_flow_sources
        self.mod.query_artifact_results = slow_fetch
        self.mod.time = types.SimpleNamespace(
            sleep=lambda s: setattr(slow, "now", slow.now + s),
            monotonic=lambda: slow.now)
        self.collect(minutes=10)
        self.assertLess(slow.now, 10 * 60 + 200,
                        f"a 10-minute collection ran {slow.now}s — the old drift "
                        f"is what pushed these past the watchdog")


class TestNothingCollectedIsEverThrownAway(unittest.TestCase):

    def test_nothing_can_exit_between_collecting_and_saving(self):
        """The property, not the position.

        The first version of this test asserted that the persist appeared before
        A cancel check. It passed, and a live cancellation still lost every row,
        because the run exited at a DIFFERENT one — there were three `return`s
        between the collection and the save. What has to be true is that no exit
        path of any kind sits between the rows existing and the rows being
        written.
        """
        src = read(RUNNERS)
        code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
        start = code.index("all_results, timed_out = stream_collect_and_analyze(")
        persist = code.index("persist_pipeline_artifacts(run_id, all_results)", start)
        between = code[start:persist]
        for exit_kw in ("return", "raise", "continue", "break"):
            self.assertNotIn(exit_kw, between,
                             f"a `{exit_kw}` sits between the collection and the "
                             f"save — a run taking it loses everything it gathered")

    def test_a_stopped_run_says_what_was_kept(self):
        self.assertIn("were saved and can be fused", read(RUNNERS))


class TestAStoppedRunSaysWhy(unittest.TestCase):

    def test_request_stop_records_a_reason(self):
        src = read(WFSVC)
        self.assertIn("def request_stop(run_id, reason=None)", src)
        self.assertIn("error=reason or None", src)

    def test_the_watchdog_supplies_one(self):
        src = read(HELPERS)
        self.assertIn("request_stop(run_id, reason=", src)
        self.assertIn("Watchdog", src)

    def test_an_operator_stop_still_reads_as_one(self):
        # Only the watchdog passes a reason; a person pressing Stop must not be
        # relabelled as a failure.
        self.assertIn('"[Pipeline] Stop requested by user"', read(WFSVC))


class TestTheOffsetIsPerClient(unittest.TestCase):
    """A hunt-shaped collection has several flows writing the same artifact. A
    shared offset would let one host's progress skip past another host's rows."""

    def test_the_key_includes_the_client(self):
        src = read(STREAM)
        self.assertIn("fetched_offsets", src)
        self.assertIn("_key = (client_id, source_name)", src)

    def test_the_offset_counts_what_was_received(self):
        # Not what was requested: a fetch cut short by the query timeout must
        # leave the offset where the data really ends.
        src = read(STREAM)
        self.assertIn("fetched_offsets[_key] = _seen + len(rows)", src)

    def test_start_row_is_omitted_when_zero(self):
        # So the first fetch of every source is byte-identical to the old query.
        src = read(BASE)
        self.assertIn('if _offset else ""', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
