"""The memory extract wait: does it say anything while it waits, and does it
tell the truth when it gives up?

A customer ran a layered memory analysis on a 9.2 GB image. Acquisition
finished in six minutes, the log printed "12 plugins queued + yarascan queued",
and then emitted NOTHING for thirty-five minutes. They concluded the platform
had hung. It hadn't — `wait_for_plugin_results` logged only on state
*transitions*, so a run where VolWeb produced no rows produced no lines either,
for the entire 1800s budget. When it finally gave up it returned partial
results and the caller logged "plugins complete" at success level.

The load-bearing constraint, verified in VolWeb's own source: a
`VolatilityPlugin` row is written by `save_to_database()`, which runs from
`render()` — a row exists only once a plugin has FINISHED. Nothing is written
at dispatch. So "zero rows" is genuinely ambiguous between a dead worker and a
first plugin still grinding through a multi-GB image, and elapsed time cannot
separate them. That is why the wait escalates on evidence (is the worker
container running?) and never on a timer — see
`test_slow_first_row_still_succeeds`, which is the guard on that whole design.

The clock is faked, so these run in milliseconds rather than the real 30-minute
budget. Nothing here touches the network, docker, or the database.

Run: docker exec intact_backend python3 /app/workdir/tests/test_volweb_plugin_wait.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.memory import volweb_client as V  # noqa: E402
from services.memory import pipeline as P  # noqa: E402


class _Patch:
    """Swap module-level attributes on `V` for the duration of a block."""

    def __init__(self, **kw):
        self.kw, self.saved = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.saved[k] = getattr(V, k)
            setattr(V, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(V, k, v)


class _FakeClock:
    """Stand-in for the `time` module where sleeping advances the clock.

    The repo's existing polling harness (tests/test_velociraptor_ready_gate.py)
    stubs only `sleep`, which is not enough here: this loop derives its
    deadline, heartbeat cadence and idle-grace from `time.time()`. With a real
    clock the deadline would never arrive and the test would block for the
    actual 1800-second budget.
    """

    def __init__(self, start=1_000_000.0):
        self.now = float(start)

    def time(self):
        return self.now

    def sleep(self, n):
        self.now += n


def _client(rows_fn, worker=None):
    """A VolWebClient with its two outbound calls stubbed on the instance.

    `__init__` performs no I/O, so constructing one is safe. Instance
    attributes shadow the bound methods, so neither `requests` nor `subprocess`
    is ever reached.
    """
    rec: list[tuple[str, str]] = []
    c = V.VolWebClient(
        base_url="http://stub:8000", username="u", password="p",
        logger=lambda m, lvl="info": rec.append((m, lvl)),
    )
    c.list_plugins = rows_fn
    c.extraction_worker_alive = lambda: worker
    return c, rec


def _row(name, results=True):
    return {"name": name, "results": results, "icon": "", "error": None}


WANTED3 = ("volatility3.plugins.windows.pslist.PsList",
           "volatility3.plugins.windows.netscan.NetScan",
           "volatility3.plugins.windows.malfind.Malfind")


def _beats(rec):
    return [m for m, lvl in rec if m.startswith("plugin extract: waiting on")]


def _warns(rec, needle):
    return [m for m, lvl in rec if needle in m]


# ---------------------------------------------------------------------------


def test_heartbeat_emits_while_zero_rows():
    """THE regression. Thirty minutes of silence is what made a working-but-slow
    run indistinguishable from a crash."""
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=300, poll_s=15, heartbeat_s=60,
            no_rows_warn_s=10_000,          # keep the escalation out of this test
        )
    beats = _beats(rec)
    assert completed is False and got == {}, (completed, got)
    assert len(beats) >= 4, f"only {len(beats)} heartbeats in 300s: {beats}"
    # First beat must land early — a beat that only shows up near the end is
    # no better than silence.
    assert "0m " in beats[0] or "1m " in beats[0], beats[0]
    for m in beats:
        assert "elapsed" in m and "budget" in m, m
        assert "0/3 plugins done" in m, m
        assert "0 result rows" in m, m          # the fact on_progress cannot carry
        assert "pending:" in m, m


def test_heartbeat_reports_the_raw_row_count():
    """rows>0 with done=0 means VolWeb is alive but nothing from the curated
    set has landed; rows=0 means it has written literally nothing. Different
    problems, and the operator can only tell them apart if we print it."""
    clk = _FakeClock()
    # Two rows, neither in the wanted set.
    rows = [_row("volatility3.plugins.windows.cmdline.CmdLine"),
            _row("volatility3.plugins.windows.dlllist.DllList")]
    c, rec = _client(lambda eid: rows, worker=True)
    with _Patch(time=clk):
        c.wait_for_plugin_results(1, WANTED3, timeout_s=120, poll_s=15,
                                  heartbeat_s=60, no_rows_warn_s=10_000)
    beats = _beats(rec)
    assert beats, "no heartbeat emitted"
    assert "2 result rows" in beats[0], beats[0]
    assert "0/3 plugins done" in beats[0], beats[0]


def test_zero_rows_escalates_exactly_once():
    """One-shot. A warning repeated every poll is just a different flavour of
    noise, and the operator stops reading it."""
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=True)
    with _Patch(time=clk):
        c.wait_for_plugin_results(1, WANTED3, timeout_s=1800, poll_s=15,
                                  heartbeat_s=60, no_rows_warn_s=600)
    esc = _warns(rec, "ZERO plugin rows")
    assert len(esc) == 1, f"expected exactly 1 escalation, got {len(esc)}"
    assert V._VOLWEB_WORKER_CONTAINER in esc[0], esc[0]
    assert "only written when a plugin FINISHES" in esc[0], esc[0]
    assert "docker logs" in esc[0], esc[0]


def test_zero_rows_aborts_when_the_worker_is_proven_dead():
    """The one condition strong enough to stop on: not an inference from
    silence, but the queue demonstrably having no consumer."""
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=False)
    try:
        with _Patch(time=clk):
            c.wait_for_plugin_results(1, WANTED3, timeout_s=1800, poll_s=15,
                                      no_rows_warn_s=600)
    except V.VolWebError as e:
        assert V._VOLWEB_WORKER_CONTAINER in str(e), e
    else:
        raise AssertionError("a dead worker did not abort the wait")
    # Aborted at the escalation point, not after the full budget.
    assert clk.now - 1_000_000.0 < 700, f"waited {clk.now - 1_000_000.0}s before aborting"
    assert any(lvl == "error" for _, lvl in rec), rec


def test_zero_rows_keeps_waiting_when_the_worker_is_alive():
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=1200, poll_s=15, no_rows_warn_s=600)
    assert completed is False and got == {}
    assert clk.now - 1_000_000.0 >= 1200, "gave up before the budget"


def test_unknown_worker_state_never_aborts():
    """`None` is what a non-docker deployment and every unit test gets. Treating
    'I cannot tell' as 'it is dead' would abort healthy runs."""
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=None)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=900, poll_s=15, no_rows_warn_s=600)
    assert completed is False, "unknown worker state must not abort"
    assert clk.now - 1_000_000.0 >= 900


def test_slow_first_row_still_succeeds():
    """The guard on the whole design.

    Empty for 900 fake-seconds — well past the escalation — and then everything
    lands. This is a healthy run on a large image: VolWeb writes a row only
    when a plugin finishes, so a long gap before the first row is normal. Any
    "abort after N minutes of zero rows" design fails this test, which is
    exactly why the escalation warns and probes instead of giving up.
    """
    clk = _FakeClock()
    state = {"t0": clk.now}

    def rows(eid):
        if clk.now - state["t0"] < 900:
            return []
        return [_row(n) for n in WANTED3]

    c, rec = _client(rows, worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=1800, poll_s=15, no_rows_warn_s=600)
    assert completed is True, "a slow but healthy run was not allowed to finish"
    assert len(got) == 3, got
    assert _warns(rec, "ZERO plugin rows"), "should still have warned during the gap"


def test_timeout_returns_completed_false():
    clk = _FakeClock()
    c, rec = _client(lambda eid: [], worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=120, poll_s=15, no_rows_warn_s=10_000)
    assert completed is False, "a timeout must not report as completed"
    assert _warns(rec, "timed out"), rec


def test_all_done_returns_completed_true():
    clk = _FakeClock()
    c, rec = _client(lambda eid: [_row(n) for n in WANTED3], worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=1800, poll_s=15)
    assert completed is True and len(got) == 3, (completed, got)
    assert not _beats(rec), "no heartbeat should fire once everything is done"


def test_task_done_marker_fast_exits():
    """VolWeb's terminal marker row is authoritative: whatever hasn't surfaced
    by then is not coming. Pins behaviour the refactor could have silently
    dropped."""
    clk = _FakeClock()
    rows = [_row(WANTED3[0]), _row("volatility3.plugins.VolWebSelective")]
    c, rec = _client(lambda eid: rows, worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            1, WANTED3, timeout_s=1800, poll_s=15)
    assert completed is True, "the terminal marker should end the wait"
    assert len(got) == 1, got
    assert _warns(rec, "missing (no row or empty results)"), rec


def test_idle_grace_still_requires_the_partial_floor():
    """Deliberately preserved. 'The row count has been stable' says nothing
    when the count has never been anything but zero — the zero case is owned by
    the escalation, which decides on evidence rather than on elapsed time."""
    wanted12 = tuple(f"volatility3.plugins.p{i}.P{i}" for i in range(12))
    floor = max(1, int(12 * V._PLUGIN_PARTIAL_FLOOR))     # 7

    # 7 done → stable row count trips the soft exit.
    clk = _FakeClock()
    c, _ = _client(lambda eid: [_row(n) for n in wanted12[:floor]], worker=True)
    with _Patch(time=clk):
        got, completed = c.wait_for_plugin_results(
            wanted12 and 1, wanted12, timeout_s=1800, poll_s=15, idle_grace_s=300)
    assert completed is True and len(got) == floor, (completed, len(got))
    assert clk.now - 1_000_000.0 < 1800, "should have soft-exited well before the budget"

    # One below the floor → runs the full budget instead.
    clk2 = _FakeClock()
    c2, _ = _client(lambda eid: [_row(n) for n in wanted12[:floor - 1]], worker=True)
    with _Patch(time=clk2):
        got2, completed2 = c2.wait_for_plugin_results(
            1, wanted12, timeout_s=1800, poll_s=15, idle_grace_s=300,
            no_rows_warn_s=10_000)
    assert completed2 is False, "below the floor should not soft-exit"


def test_a_plugin_that_errors_then_succeeds_is_announced_as_done():
    """`announced` was keyed on the plugin name alone and shared between the
    success and error branches, so a transient error icon suppressed the later
    'plugin done' line — the operator's last word on a plugin that SUCCEEDED
    was 'errored'."""
    clk = _FakeClock()
    name = WANTED3[0]
    state = {"n": 0}

    def rows(eid):
        state["n"] += 1
        if state["n"] == 1:
            return [{"name": name, "results": False, "icon": "mdi-alert-circle",
                     "error": "transient"}]
        return [_row(n) for n in WANTED3]

    c, rec = _client(rows, worker=True)
    with _Patch(time=clk):
        c.wait_for_plugin_results(1, WANTED3, timeout_s=1800, poll_s=15)
    assert _warns(rec, "plugin errored"), "the error should still be reported"
    assert _warns(rec, "plugin done: PsList"), \
        "a plugin that recovered was never announced as done"


def test_cancel_check_cuts_through_the_sleep():
    """Stop must not wait out a 15s poll."""
    clk = _FakeClock()
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1

    c, _ = _client(lambda eid: [], worker=True)
    try:
        with _Patch(time=clk):
            c.wait_for_plugin_results(1, WANTED3, timeout_s=1800, poll_s=15,
                                      cancel_check=cancel)
    except V.VolWebError as e:
        assert "cancel" in str(e).lower(), e
    else:
        raise AssertionError("cancel_check was ignored")
    assert clk.now - 1_000_000.0 < 15, "did not cut through the poll sleep"


def test_extract_outcome_line_levels():
    """The line that told a customer a 30-minute timeout was 'complete'."""
    msg, lvl = P._extract_outcome_line(12, 12, 400, True, 1800)
    assert lvl == "success" and "complete" in msg, (lvl, msg)

    msg, lvl = P._extract_outcome_line(7, 12, 1800, False, 1800)
    assert lvl == "warning", lvl
    assert "budget" in msg and "7/12" in msg, msg

    msg, lvl = P._extract_outcome_line(0, 12, 1800, False, 1800)
    assert lvl == "error", "a zero-plugin extract must not be success or warning"
    assert "ZERO" in msg and "no memory artefacts" in msg, msg


def test_both_wait_loops_share_one_heartbeat_cadence():
    """They drifted once already — yarascan carried its own inline 60."""
    import inspect
    src = inspect.getsource(V.wait_for_yarascan if hasattr(V, "wait_for_yarascan")
                            else V.VolWebClient.wait_for_yarascan)
    assert "_HEARTBEAT_S" in src, "yarascan re-introduced its own heartbeat constant"


if __name__ == "__main__":
    failures = 0
    names = [n for n in sorted(globals()) if n.startswith("test_")]
    for name in names:
        fn = globals()[name]
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
        except Exception as e:      # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print(f"\n{len(names) - failures}/{len(names)} passed")
    sys.exit(1 if failures else 0)
