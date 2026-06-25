"""Regression tests for the cancel/stop infrastructure in workflow_service.py.

Covers:
- terminate_subprocess: must SIGTERM, fall back to SIGKILL, be idempotent on
  already-dead processes, and never raise.
- get_cancel_event: returns the registered Event, None for unknown run_ids.
- register_cancel_event / register_cleanup / request_stop: cleanup callbacks
  fire on stop, the Event gets set, the registry is cleaned up.

Run with:
    docker exec intact_backend python -m pytest \\
        /app/tests/test_workflow_service.py -v
"""

import subprocess
import time
import threading

from services.workflow_service import (
    terminate_subprocess,
    register_cancel_event,
    register_cleanup,
    is_cancelled,
    get_cancel_event,
)


# ---------------------------------------------------------------------------
# terminate_subprocess
# ---------------------------------------------------------------------------

def test_terminate_subprocess_kills_running_process():
    p = subprocess.Popen(['sleep', '60'])
    # Sanity: process is alive
    time.sleep(0.1)
    assert p.poll() is None
    terminate_subprocess(p, timeout=2.0)
    assert p.poll() is not None  # process is dead


def test_terminate_subprocess_noop_on_finished_process():
    p = subprocess.Popen(['true'])
    p.wait()
    # Process already exited — must not raise
    terminate_subprocess(p)


def test_terminate_subprocess_noop_on_none():
    # Defensive: callbacks may be lambda p=None: terminate_subprocess(p)
    terminate_subprocess(None)


def test_terminate_subprocess_falls_back_to_kill_on_ignored_term():
    # bash -c 'trap "" TERM; sleep 60' ignores SIGTERM. terminate_subprocess
    # should give up after timeout and SIGKILL.
    p = subprocess.Popen(['bash', '-c', 'trap "" TERM; sleep 60'])
    time.sleep(0.2)
    assert p.poll() is None
    start = time.time()
    terminate_subprocess(p, timeout=1.0)
    elapsed = time.time() - start
    # Should have escalated to SIGKILL within ~1s + small buffer
    assert p.poll() is not None
    assert elapsed < 4.0


# ---------------------------------------------------------------------------
# Cancel event + cleanup callbacks
# ---------------------------------------------------------------------------

def test_register_cancel_event_returns_event_and_get_returns_same():
    run_id = "test_run_cancel_get"
    event = register_cancel_event(run_id)
    assert isinstance(event, threading.Event)
    assert get_cancel_event(run_id) is event
    # Unregister via request_stop to clean up registry
    from services.workflow_service import request_stop
    request_stop(run_id)


def test_get_cancel_event_returns_none_for_unknown_run():
    assert get_cancel_event("nonexistent_run_id_zxy") is None


def test_request_stop_runs_cleanups_in_order_and_sets_event():
    run_id = "test_run_cleanup_order"
    event = register_cancel_event(run_id)

    fired = []
    register_cleanup(run_id, lambda: fired.append("a"))
    register_cleanup(run_id, lambda: fired.append("b"))

    from services.workflow_service import request_stop
    request_stop(run_id)

    assert event.is_set()
    assert fired == ["a", "b"]
    # Registry was cleaned up
    assert get_cancel_event(run_id) is None


def test_request_stop_continues_when_a_cleanup_raises():
    run_id = "test_run_cleanup_raise"
    register_cancel_event(run_id)

    fired = []
    def good():
        fired.append("ok-before")
    def bad():
        raise RuntimeError("simulated cleanup failure")
    def good2():
        fired.append("ok-after")

    register_cleanup(run_id, good)
    register_cleanup(run_id, bad)
    register_cleanup(run_id, good2)

    from services.workflow_service import request_stop
    request_stop(run_id)  # must not raise

    # Both good callbacks fired despite the middle one raising
    assert fired == ["ok-before", "ok-after"]


def test_is_cancelled_reflects_event_state():
    run_id = "test_run_is_cancelled"
    register_cancel_event(run_id)
    assert is_cancelled(run_id) is False
    from services.workflow_service import request_stop
    request_stop(run_id)
    # request_stop unregisters the event; is_cancelled then returns False
    # because there's no event. That's the expected behaviour — the
    # workflow has been stopped and cleaned up.
    assert is_cancelled(run_id) is False


def test_terminate_subprocess_via_cleanup_callback():
    """End-to-end: process spawned, callback registered, stop kills it."""
    run_id = "test_run_kill_via_callback"
    register_cancel_event(run_id)

    p = subprocess.Popen(['sleep', '60'])
    register_cleanup(run_id, lambda p=p: terminate_subprocess(p))

    time.sleep(0.1)
    assert p.poll() is None  # alive

    from services.workflow_service import request_stop
    request_stop(run_id)

    # Cleanup ran synchronously inside request_stop, process is dead
    assert p.poll() is not None
