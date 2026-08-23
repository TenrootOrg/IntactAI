"""Fuse a case by itself, shortly after its data stops arriving.

WHY A DEBOUNCE AND NOT A FUSE PER RUN
A fuse rebuilds the WHOLE case graph — measured on a live appliance at 29s for
one 9-host capture and 53s for two — because its cost is O(all data in the case),
not O(the run that just landed). Fusing on every terminal run would make a
20-host hunt fire twenty full rebuilds, each slower than the last, for one
useful result. So a landing run only ARMS a timer; each new landing re-arms it,
and the fuse happens once the case has been quiet for QUIET_SECONDS.

WHAT IT DELIBERATELY WILL NOT DO
  - It never narrates. The LLM report/advisory is the expensive part and it is
    what an analyst is actually reading; an automatic fuse builds the graph and
    leaves the narrative exactly where it was. Refreshing that stays a click
    (Rescan), so nothing is ever spent or rewritten without one.
  - It never redraws anyone's screen. This module only updates the stored graph;
    the case view notices via the staleness poll and offers to reload.
  - It never runs on a case whose operator turned it off.

WHAT IT MUST NOT DROP
The previous background path wrapped its fuse in `except: pass`, so a fuse that
collided with another simply vanished and left the graph stale with no banner and
nothing in the log. Here a collision RE-ARMS (bounded), and both the retry and
the final give-up are written to the case activity log.

TESTABILITY
Collaborators are imported lazily through _store() rather than at module import,
so a test can substitute a fake without pulling the backend in. The delays are
module-level and monkeypatchable, so tests drive real timers in milliseconds
instead of sleeping.
"""

from __future__ import annotations

import threading

# Quiet period after the last run lands before the case is fused. Long enough
# that a multi-host hunt arriving over a minute produces ONE fuse.
QUIET_SECONDS = 60.0
# A fuse was already running. Wait a little and try again rather than dropping
# this data on the floor until someone clicks Refusion.
BUSY_RETRY_SECONDS = 30.0
MAX_BUSY_RETRIES = 10

_TIMERS: dict = {}
_GUARD = threading.Lock()


def _store():
    from services.fusion import store          # lazy: keeps this module testable
    return store


def _enabled(store, case_id, d):
    """Automatic fusion is ALWAYS ON — there is no user-facing setting for it.

    It was briefly a checkbox in the Configuration rail and that was the wrong
    call: folding new data into the graph is not a preference, it is what the
    product does, and an operator has no basis on which to decide it. The
    checkbox is gone.

    The stored key is still honoured, with no UI to set it. This is a SUPPORT
    escape hatch, not a feature: if automatic fusion ever misbehaves on a customer
    appliance, `auto_fuse: false` on the case row stops it without a rebuild or a
    downgrade. Absent — which is every case — reads as ON.
    """
    return d.get("auto_fuse") is not False


def cancel(case_id) -> bool:
    """Stop a pending auto-fuse (case deleted, or the operator opted out)."""
    with _GUARD:
        t = _TIMERS.pop(case_id, None)
    if t is not None:
        t.cancel()
        return True
    return False


def pending(case_id) -> bool:
    with _GUARD:
        return case_id in _TIMERS


def schedule(case_id, reason="new data", *, delay=None, _attempt=0) -> bool:
    """Arm (or re-arm) the auto-fuse for a case. Returns True if armed.

    Cheap and non-blocking on purpose: this is called from inside
    update_run_status, which holds the per-run lock. It must never fuse inline,
    read the case, or touch the database.
    """
    if not case_id:
        return False
    wait = QUIET_SECONDS if delay is None else delay
    with _GUARD:
        old = _TIMERS.pop(case_id, None)
        if old is not None:
            old.cancel()                       # re-arm: the case is still busy
        t = threading.Timer(wait, _fire, args=(case_id, reason, _attempt))
        t.daemon = True                        # never hold up a shutdown
        _TIMERS[case_id] = t
        t.start()
    return True


def catch_up(stagger=None) -> int:
    """Arm a fuse for every case that already has unfused data. Returns how many.

    Timers live in memory, so data that landed in the minute before a backend
    restart would otherwise sit unfused until ANOTHER run happened to arrive —
    the operator would see the banner and have to click, which is exactly the
    manual step this feature exists to remove. Called once at startup.

    Staggered rather than fired together: the per-case fuse locks are independent,
    so ten cases would otherwise rebuild ten graphs at once on a box that has just
    come up. One quiet period apart is roughly one at a time (a fuse measured 29s
    against a 60s period) without needing a real queue.
    """
    step = QUIET_SECONDS if stagger is None else stagger
    store = _store()
    armed = 0
    try:
        runs = store._ws().get_all_automation_runs() or []
    except Exception as e:                     # noqa: BLE001 — startup must not fail
        print(f"[AUTOFUSE] catch-up skipped: {e}", flush=True)
        return 0
    for r in runs:
        try:
            if r.get("automation_type") != store.CASE_TYPE:
                continue
            cid = r.get("run_id")
            d = r.get("details") or {}
            if not _enabled(store, cid, d):
                continue
            if not store.stale_member_runs(cid, d):
                continue
            schedule(cid, "startup catch-up", delay=step * (armed + 1))
            armed += 1
        except Exception as e:                 # noqa: BLE001 — one bad case, not all
            print(f"[AUTOFUSE] catch-up skipped {r.get('run_id')}: {e}", flush=True)
    if armed:
        print(f"[AUTOFUSE] catch-up armed {armed} case(s) with unfused data", flush=True)
    return armed


def _fire(case_id, reason="new data", attempt=0) -> None:
    """The timer expired: fuse the case if it still wants fusing."""
    with _GUARD:
        _TIMERS.pop(case_id, None)
    store = _store()
    try:
        d = store.get_case(case_id)
        if not d:
            return                             # case deleted while we waited
        if not _enabled(store, case_id, d):
            return                             # operator opted out
        stale = store.stale_member_runs(case_id, d)
        if not stale:
            return                             # someone already fused it — no-op
        # CRASH-LOOP BREAKER. A fuse can die in a way no `except` will ever see:
        # a big case OOMs the process (measured — five 547 MB member runs peaked at
        # 5.6 GB and the kernel killed it). Automatic retry then becomes a loop:
        # fuse dies, backend restarts, catch_up re-arms, fuse dies. The flag is
        # written BEFORE the fuse and cleared after, so a fuse that never returns
        # leaves it set and the next automatic attempt stands down. A manual
        # Refusion clears it, which is the operator's way back in.
        if d.get("auto_fuse_incomplete"):
            store.log_case_event(
                case_id, "Refusion skipped", "warning",
                "a previous automatic re-fuse did not finish (the backend may have "
                "run out of memory on this case) — click Refusion to fuse it by hand")
            return
        store._merge_case_details(case_id, {"auto_fuse_incomplete": True})
        try:
            store.fuse_case(case_id,
                            trigger=store.TRIGGER_AUTOMATIC_RUN_LANDED,
                            allow_llm=False)
            store._merge_case_details(case_id, {"auto_fuse_incomplete": False})
        except store.FusionBusy:
            # Nothing was attempted, so this is not an incomplete fuse.
            store._merge_case_details(case_id, {"auto_fuse_incomplete": False})
            if attempt + 1 >= MAX_BUSY_RETRIES:
                store.log_case_event(
                    case_id, "Refusion skipped", "warning",
                    f"automatic re-fuse gave up after {MAX_BUSY_RETRIES} attempts — "
                    f"the case has been fusing throughout; click Refusion when it settles")
                return
            store.log_case_event(
                case_id, "Refusion deferred", "info",
                f"automatic re-fuse postponed — a fuse is already running "
                f"(attempt {attempt + 1}/{MAX_BUSY_RETRIES})")
            schedule(case_id, reason, delay=BUSY_RETRY_SECONDS, _attempt=attempt + 1)
    except Exception as e:                     # a timer thread must never die loudly
        try:
            st = _store()
            # It raised rather than vanished, so the case is not in the unknown
            # state the flag exists to mark — clear it and let the next run retry.
            st._merge_case_details(case_id, {"auto_fuse_incomplete": False})
            st.log_case_event(
                case_id, "Refusion failed", "error",
                f"automatic re-fuse failed — {type(e).__name__}: {e}")
        except Exception:
            pass
