"""A Velociraptor flow in state ERROR is still running. Do not walk away from it.

WHAT HAPPENED (QA, 2026-08-25, DESKTOP-9RNKFB0, flow F.DA6NFH7FCBNS0).
A 31-artifact BestPractice collection with a 30-minute budget. One stock
artifact's VQL failed ("Symbol CommandLine not found" — the parameter set in the
error is Windows.Network.NetstatEnriched's), which put the FLOW into state
ERROR. We polled, saw ERROR, treated the flow as finished, stopped collecting
and closed the run COMPLETED at 100%.

    flow started      11:08:53.440
    we gave up        11:09:27.466   (34s in)
    flow last active  11:13:44.269   (290.83s — Velociraptor's own figure)

So 4m17s of an endpoint collection was thrown away, out of a 30-minute budget
the operator had asked for, and the run reported success with 10 of 31 artifacts.

THE MISREADING. In Velociraptor, ERROR on a flow means "something in this flow
errored", NOT "this flow stopped" — the remaining artifacts keep running, and
the state never becomes FINISHED afterwards. So for an errored flow the state
cannot be the completion signal. Progress is: the flow is done when it stops
producing anything.

This test drives the REAL stream_collect_and_analyze against a fake
Velociraptor that reproduces exactly that shape — errors early, keeps yielding
artifacts for another four minutes — and asserts we collect all of it. Time is
compressed by patching the module's `interval`; nothing sleeps for real.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/services/agentic/collectors/_stream.py")


class _FakeChannel:
    """grpc channel stub — the collector closes it in its finally block."""

    def close(self):
        pass


def _load():
    """Import _stream with its Velociraptor + workflow collaborators stubbed.

    The module does `from ._base import *` and imports pyvelociraptor at module
    scope, so those are satisfied rather than served — every one of them is
    replaced on the module afterwards.
    """
    for name in ("pyvelociraptor", "pyvelociraptor.api_pb2",
                 "pyvelociraptor.api_pb2_grpc"):
        m = types.ModuleType(name)
        sys.modules.setdefault(name, m)
    sys.modules["pyvelociraptor"].api_pb2 = sys.modules["pyvelociraptor.api_pb2"]
    sys.modules["pyvelociraptor"].api_pb2_grpc = sys.modules["pyvelociraptor.api_pb2_grpc"]
    sys.modules["pyvelociraptor.api_pb2_grpc"].APIStub = lambda ch: object()

    services = sys.modules.setdefault("services", types.ModuleType("services"))
    for name, attrs in (
        ("services.velociraptor_service",
         {"setup_velociraptor_connection": lambda: _FakeChannel()}),
        ("services.workflow_service", {"add_log_to_run": lambda *a, **k: None,
                                       "register_cleanup": lambda *a, **k: None}),
        ("services.agentic", {}),
        ("services.agentic.collectors", {}),
        ("services.agentic.collectors._base", {
            "check_flow_status": lambda *a, **k: (None, None),
            "enumerate_flow_sources": lambda *a, **k: [],
            "query_artifact_results": lambda *a, **k: [],
            "cancel_collections": lambda *a, **k: None,
        }),
    ):
        mod = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(mod, k, v)
        sys.modules[name] = mod
    services.agentic = sys.modules["services.agentic"]

    mod = types.ModuleType("_stream")
    mod.__file__ = SRC
    with open(SRC, encoding="utf-8") as fh:
        exec(compile(fh.read(), SRC, "exec"), mod.__dict__)
    return mod


class FakeVelociraptor:
    """The QA flow, to scale.

    31 artifacts. The flow enters ERROR at `error_at` seconds and STAYS there —
    Velociraptor never flips an errored flow to FINISHED. Artifacts keep landing
    on a schedule until `last_active`, after which nothing more ever appears.
    """

    N_ARTIFACTS = 31

    def __init__(self, error_at=34, last_active=291, early=10):
        self.error_at = error_at
        self.last_active = last_active
        self.early = early              # artifacts that had landed by error_at
        self.now = 0                    # advanced by the patched sleep
        self.status_calls = 0

    # --- the schedule ----------------------------------------------------
    def _landed(self):
        """How many artifacts have results by `now`. Monotonic, and defined even
        when the flow never errors (knee collapses to last_active)."""
        if self.now >= self.last_active:
            return self.N_ARTIFACTS
        knee = min(self.error_at, self.last_active)
        if self.now < knee:
            return max(0, int(self.early * self.now / max(knee, 1)))
        span = max(self.last_active - knee, 1)
        return self.early + int((self.N_ARTIFACTS - self.early) * (self.now - knee) / span)

    # --- the three collaborators the poll loop uses ----------------------
    def check_flow_status(self, stub, client_id, flow_id):
        self.status_calls += 1
        if self.now >= self.error_at:
            done = [f"Artifact.{i}" for i in range(self._landed())]
            return "ERROR", {
                "backtrace": "Symbol CommandLine not found",
                "context": {},
                "artifacts_completed": len(done),
                "artifacts_requested": self.N_ARTIFACTS,
                "failed_artifacts": [f"Artifact.{i}"
                                     for i in range(self._landed(), self.N_ARTIFACTS)],
                "error_reason": "Symbol CommandLine not found",
            }
        return "RUNNING", None

    def enumerate_flow_sources(self, stub, client_id, flow_id):
        return [f"Artifact.{i}" for i in range(self._landed())]

    def query_artifact_results(self, stub, client_id, flow_id, source,
                               start_iso=None, end_iso=None, start_row=0):
        # start_row: the loop fetches only what it has not already stored, so a
        # source it has already read returns nothing on the next poll. One row
        # per artifact here, so any offset means "already have it".
        if int(start_row or 0) > 0:
            return []
        idx = int(source.split(".")[1])
        return [{"row": idx}] if idx < self._landed() else []


class _Base(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.velo = FakeVelociraptor()
        self.mod.check_flow_status = self.velo.check_flow_status
        self.mod.enumerate_flow_sources = self.velo.enumerate_flow_sources
        self.mod.query_artifact_results = self.velo.query_artifact_results
        self.logs = []
        self.mod.add_log_to_run = lambda rid, msg, lvl="info": self.logs.append((lvl, msg))
        self.mod.register_cleanup = lambda *a, **k: None
        self.mod.cancel_collections = lambda *a, **k: None
        # Time is simulated: sleeping advances the fake clock instead of the wall,
        # and monotonic() reads it — the loop measures its window against the
        # wall clock now rather than tallying intervals.
        self.mod.time = types.SimpleNamespace(
            sleep=lambda s: setattr(self.velo, "now", self.velo.now + s),
            monotonic=lambda: self.velo.now)

    def collect(self, minutes=30):
        flows = [{"client_id": "C.1", "flow_id": "F.1", "hostname": "DESKTOP-9RNKFB0"}]
        artifacts = [f"Artifact.{i}" for i in range(FakeVelociraptor.N_ARTIFACTS)]
        return self.mod.stream_collect_and_analyze(
            "run_1", flows, artifacts, minutes)

    def log_text(self):
        return "\n".join(m for _l, m in self.logs)


class TestAnErroredFlowIsNotAbandoned(_Base):

    def test_it_collects_every_artifact_the_flow_eventually_produced(self):
        results, timed_out = self.collect()
        self.assertEqual(len(results), FakeVelociraptor.N_ARTIFACTS,
                         f"gave up early: kept {len(results)} of "
                         f"{FakeVelociraptor.N_ARTIFACTS} artifacts")
        self.assertFalse(timed_out, "an idle errored flow is finished, not timed out")

    def test_it_does_not_stop_at_the_moment_of_the_error(self):
        # The regression, stated as time: QA's run quit 34s into a 30-minute
        # budget because that is when the flow's state turned ERROR.
        self.collect()
        self.assertGreater(self.velo.now, self.velo.error_at,
                           "collection ended the moment the flow reported ERROR")

    def test_it_stops_once_the_flow_goes_quiet(self):
        # The other half: an errored flow must not hold the run open for the
        # whole 30 minutes when it has plainly stopped producing.
        self.collect()
        self.assertLess(self.velo.now, 30 * 60,
                        "waited out the entire budget on a flow that had finished")

    def test_the_operator_is_told_the_flow_errored(self):
        self.collect()
        self.assertIn("did not complete", self.log_text())

    def test_a_flow_that_never_errors_is_unaffected(self):
        # The ordinary path must not get slower or different.
        self.velo.error_at = 10 ** 9          # never errors
        self.velo.last_active = 120
        results, _ = self.collect()
        self.assertGreater(len(results), 0)


class TestTheFixDoesNotIntroduceItsOwnProblems(_Base):
    """Not abandoning an errored flow creates three new ways to be wrong."""

    def test_the_error_warning_is_logged_once_not_every_poll(self):
        # The ERROR branch is now reached on EVERY subsequent poll, where before
        # the flow was marked complete and never re-checked. Logging it each time
        # would put ~60 identical warnings into a 30-minute collection's log.
        self.collect()
        warnings = [m for lvl, m in self.logs if "did not complete" in m]
        self.assertEqual(len(warnings), 1, f"logged {len(warnings)} times")

    def test_a_flow_that_errors_with_no_data_still_ends_promptly(self):
        # The opposite failure: an errored flow that never produces anything must
        # not hold a 30-minute budget open. It goes idle immediately, so it ends
        # after the idle window, not after the budget.
        self.velo.early = 0
        self.velo.last_active = 10 ** 9        # never produces
        self.velo.error_at = 5
        results, timed_out = self.collect(minutes=30)
        self.assertEqual(results, {})
        self.assertLess(self.velo.now, 5 * 60,
                        "a dead flow held the collection open")

    def test_the_idle_window_is_bounded_and_small(self):
        # It costs every errored collection this much extra wall-clock, so it is
        # pinned rather than left to drift.
        with open(SRC, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("IDLE_POLLS_BEFORE_DONE = 3", src)

    def test_a_mixed_multi_client_run_waits_for_the_errored_one(self):
        # One host finishes cleanly, the other errors and keeps going. The run
        # must not end when the clean one finishes.
        velo = self.velo

        def status(stub, client_id, flow_id):
            if flow_id == "F.clean":
                return ("FINISHED", None) if velo.now >= 20 else ("RUNNING", None)
            return velo.check_flow_status(stub, client_id, flow_id)

        self.mod.check_flow_status = status
        self.mod.enumerate_flow_sources = lambda s, c, f: (
            [] if f == "F.clean" else velo.enumerate_flow_sources(s, c, f))
        flows = [{"client_id": "C.1", "flow_id": "F.1", "hostname": "erroring"},
                 {"client_id": "C.2", "flow_id": "F.clean", "hostname": "clean"}]
        artifacts = [f"Artifact.{i}" for i in range(FakeVelociraptor.N_ARTIFACTS)]
        results, _ = self.mod.stream_collect_and_analyze("run_1", flows, artifacts, 30)
        self.assertEqual(len(results), FakeVelociraptor.N_ARTIFACTS,
                         "the clean flow finishing cut the errored one short")


class TestTheArtifactCountIsHonest(_Base):
    """The warning read "21 artifact(s) did not complete … 21/31 succeeded".

    Both numbers were 21 and they mean different things: `failed_artifacts`
    counts artifact NAMES, while `artifacts_completed` counted
    `artifacts_with_results`, which is a list of SOURCES — one artifact with
    twelve sub-sources contributed twelve. The two 21s collided by coincidence
    and made the line read as a contradiction, hiding that only 10 of 31
    artifacts had actually produced anything.
    """

    def test_completed_plus_failed_never_exceeds_requested(self):
        self.velo.now = 40                      # past the error
        _st, info = self.velo.check_flow_status(None, "C.1", "F.1")
        base = os.path.join(ROOT, "modules/backend/services/agentic/collectors/_base.py")
        with open(base, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("_distinct_artifacts(", src,
                      "artifacts_completed still counts sources, not artifacts")
        self.assertLessEqual(info["artifacts_completed"] + len(info["failed_artifacts"]),
                             info["artifacts_requested"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
