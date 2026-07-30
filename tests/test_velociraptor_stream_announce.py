"""The collection log should say how much is left, not repeat every event.

stream_collect_and_analyze() used to trace every per-source transition:
"Discovered source: X", then "Found: X (N rows)" again on every 30s poll
where X grew, then "X stable (N rows)" once it stopped. A fast-writing
artifact (Windows.Hayabusa.Rules on a busy host writes on nearly every poll)
re-announced the SAME source five or more times in one run:

    Found: Windows.Hayabusa.Rules (3000 rows)
    Found: Windows.Hayabusa.Rules (4000 rows)
    Found: Windows.Hayabusa.Rules (5000 rows)

None of it told the operator anything the aggregate progress line didn't
already say every cycle. Reported from the UI as noise, with the ask being:
just say how much is left.

The fix removes the per-source announcements (and the growth/stability
bookkeeping that only existed to drive them) entirely, and throttles the one
remaining status line — "Still running — Nm Ns left | X/Y sources | Z rows
so far" — to roughly once a minute instead of every 30s poll. Actual polling
stays at the original cadence so flow completion is still noticed promptly;
only the LOG volume is throttled.

Drives the real function with the gRPC stub and its collaborators faked out,
so this exercises the real polling loop, not a re-implementation of it.

Run: docker exec intact_backend python3 /app/workdir/tests/test_velociraptor_stream_announce.py
"""

import os
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.agentic.collectors import _stream  # noqa: E402


class _CancelAfterPolls:
    """Ends the collection loop after exactly `n` polls, deterministically —
    no real time.sleep, no wall-clock dependency."""
    def __init__(self, n):
        self.n = n
        self.calls = 0

    def is_set(self):
        return self.calls >= self.n

    def wait(self, timeout=None):
        self.calls += 1


class _FakeChannel:
    """Stands in for the real gRPC channel setup_velociraptor_connection()
    returns. Only needs to be truthy and survive the `channel.close()` the
    real function calls in its `finally` block."""
    def close(self):
        pass


def _run_fake_collection(row_counts_per_poll, num_polls, run_id="test-run",
                         sources=("Windows.Hayabusa.Rules",)):
    """Drive stream_collect_and_analyze with one client, given source(s).

    row_counts_per_poll: list of row counts returned on successive polls for
    EACH source (index clamped to the last value once exhausted).
    """
    logs = []
    _stream.add_log_to_run = lambda run_id, msg, level="info": logs.append((level, msg))

    real_api_stub = _stream.api_pb2_grpc.APIStub
    _stream.setup_velociraptor_connection = lambda: _FakeChannel()
    _stream.api_pb2_grpc.APIStub = lambda channel: "fake-stub"

    poll_index = {s: -1 for s in sources}

    def fake_enumerate(stub, client_id, flow_id):
        return list(sources)

    def fake_query(stub, client_id, flow_id, source_name, start_iso=None, end_iso=None):
        poll_index[source_name] += 1
        idx = min(poll_index[source_name], len(row_counts_per_poll) - 1)
        return [{"i": i} for i in range(row_counts_per_poll[idx])]

    def fake_status(stub, client_id, flow_id):
        return "RUNNING", None  # never finishes on its own; cancel_event ends it

    _stream.enumerate_flow_sources = fake_enumerate
    _stream.query_artifact_results = fake_query
    _stream.check_flow_status = fake_status

    try:
        collection_results = [{"client_id": "C.abc123", "flow_id": "F.xyz", "hostname": "WIN11"}]
        all_results, timed_out = _stream.stream_collect_and_analyze(
            run_id, collection_results, artifacts=list(sources),
            collection_minutes=10, cancel_event=_CancelAfterPolls(num_polls))
        return logs, all_results
    finally:
        _stream.api_pb2_grpc.APIStub = real_api_stub


# --- the noisy lines are gone entirely -------------------------------------


def test_no_per_source_discovered_line():
    logs, _ = _run_fake_collection([3000, 4000, 5000], num_polls=3)
    assert not [m for _l, m in logs if "Discovered source" in m], \
        "per-source 'Discovered source' lines should no longer be logged"


def test_no_per_source_found_line():
    logs, _ = _run_fake_collection([3000, 4000, 5000], num_polls=3)
    assert not [m for _l, m in logs if "] Found: " in m], \
        "per-source 'Found' lines should no longer be logged during polling"


def test_no_per_source_stable_line():
    logs, _ = _run_fake_collection([3000, 4000, 5000], num_polls=3)
    assert not [m for _l, m in logs if " stable (" in m], \
        "per-source 'stable' lines should no longer be logged"


# --- growth is still tracked, just not re-announced -------------------------


def test_growth_across_polls_is_still_reflected_in_the_final_data():
    """Removing the announcement must not remove the DATA."""
    _, all_results = _run_fake_collection([3000, 4000, 5000], num_polls=3)
    assert len(all_results["Windows.Hayabusa.Rules"]) == 5000, (
        "the source's latest (largest) row set must still end up in all_results "
        "even with the per-poll announcement removed")


# --- the one line that remains says how much is left ------------------------


def test_the_heartbeat_reports_time_left_and_total_rows():
    logs, _ = _run_fake_collection([3000, 4000, 5000], num_polls=3)
    heartbeats = [m for _l, m in logs if "Still running" in m]
    assert heartbeats, "no 'Still running' heartbeat was logged at all"
    last = heartbeats[-1]
    assert "left" in last, f"heartbeat should say how much time is left: {last}"
    assert "rows" in last, f"heartbeat should say the running row total: {last}"


def test_the_heartbeat_is_throttled_not_logged_every_poll():
    """The whole point: a heartbeat every single 30s poll is exactly the kind
    of over-frequent chatter this was meant to cut down, even though it is a
    single aggregate line rather than a per-source one."""
    # HEARTBEAT_EVERY_N_POLLS = max(1, 60 // 30) = 2 with the real interval,
    # so 4 polls should yield at most 2 heartbeats, not 4.
    logs, _ = _run_fake_collection([100, 200, 300, 400], num_polls=4)
    heartbeats = [m for _l, m in logs if "Still running" in m]
    assert 0 < len(heartbeats) < 4, (
        f"expected the heartbeat to be throttled below one-per-poll, "
        f"got {len(heartbeats)} for 4 polls: {heartbeats}")


def test_two_sources_do_not_produce_two_separate_found_style_lines():
    """With the per-source announcement removed entirely, adding a second
    source must not reintroduce per-source noise — there is nothing left to
    key by source, so nothing to duplicate."""
    logs, all_results = _run_fake_collection(
        [10, 10], num_polls=2,
        sources=("Windows.Hayabusa.Rules", "DetectRaptor.Windows.Detection.Amcache"))
    assert not [m for _l, m in logs if "] Found: " in m or "Discovered source" in m]
    assert set(all_results) == {"Windows.Hayabusa.Rules",
                               "DetectRaptor.Windows.Detection.Amcache"}


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
