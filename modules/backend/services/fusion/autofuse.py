"""Fuse a case by itself, shortly after its data stops arriving.

WHY A DEBOUNCE AND NOT A FUSE PER RUN
A fuse rebuilds the WHOLE case graph — measured on a live appliance at 29s for
one 9-host capture and 53s for two — because its cost is O(all data in the case),
not O(the run that just landed). Fusing on every terminal run would make a
20-host hunt fire twenty full rebuilds, each slower than the last, for one
useful result. So a landing run only ARMS a timer; each new landing re-arms it,
and the fuse happens once the case has been quiet for QUIET_SECONDS.

WHAT HAPPENS AFTER THE GRAPH IS REBUILT
The report is re-narrated too. This used to be the opposite — the automatic path
built the graph and deliberately left the narrative frozen, because narrating is
the billed half and rewriting it under a reading analyst is rude. What that
actually produced was a case whose numbers moved while its Executive Summary
still described the previous collection, and a banner asking the operator to
press a button to fix it. Nobody pressed it, so the report an analyst read was
routinely behind its own data.

So: new data lands -> quiet period -> graph rebuilt -> report + advisory
regenerated, WITH the model when one is configured and with the deterministic
air-gap narrator when one is not. The report step is separate from the fuse (the
fuse is still `allow_llm=False`), for two reasons: the graph must land quickly
and unconditionally even if narration fails, and the LLM narration is the same
background, lock-guarded, progress-reporting path the Regenerate button uses, so
the case view's existing `report_generating` poll shows it happening.

WHAT IT STILL WILL NOT DO
  - It never fires for a triage, timeline, identity or chat edit. Only a MEMBER
    RUN reaching a terminal state arms it (workflow_service.update_run_status,
    AGENTIC_TYPES) — those edits re-fuse through their own paths and never come
    through here, so an operator working the case never triggers a billed call.
  - It never fires per artifact. One collection is one run row, and the quiet
    period collapses a whole multi-host hunt into a single rebuild.
  - It never redraws anyone's screen. It updates the stored graph and report; the
    case view picks the new report up on its own.
  - It never runs on a case whose operator turned it off, and the narration half
    has its own switch (`auto_report: false`) for a customer who wants the graph
    kept current without spending tokens.

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
# A report was already being generated when the fuse finished — an LLM narrative
# runs for minutes, so a second burst of data can easily land inside one. Retry
# rather than leave the report describing the data from two collections ago.
REPORT_RETRY_SECONDS = 60.0
MAX_REPORT_RETRIES = 5

_TIMERS: dict = {}
_REPORT_TIMERS: dict = {}
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


def _report_enabled(d):
    """Should the automatic fuse also re-narrate the report?

    Yes, and there is no UI for it either — a report that does not describe the
    case's current data is not a preference, it is a wrong report.

    But this half SPENDS MONEY when a model is configured, which the graph half
    never does, so it gets its own stored key. `auto_report: false` on the case
    row keeps the graph current and freezes the narrative — the old behaviour,
    available per case for a customer who is watching their token bill, without a
    downgrade. Absent — which is every case — reads as ON.
    """
    return d.get("auto_report") is not False


def cancel(case_id) -> bool:
    """Stop a pending auto-fuse (case deleted, or the operator opted out)."""
    cancelled = False
    with _GUARD:
        t = _TIMERS.pop(case_id, None)
        rt = _REPORT_TIMERS.pop(case_id, None)
    for timer in (t, rt):
        if timer is not None:
            timer.cancel()
            cancelled = True
    return cancelled


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
    if old is None and _attempt == 0:
        _announce(case_id, reason, wait)       # a FRESH quiet window — say so
    return True


def _announce(case_id, reason, wait) -> None:
    """Tell the operator IMMEDIATELY that their data landed and a fuse is coming.

    Until this existed the case log went silent for the entire quiet period:
    a workflow finished, nothing was written anywhere, and a minute later
    "Refusion · starting" appeared from nowhere. Reported from a live appliance
    as "nothing happens immediately" -- which was exactly right, and made a
    working debounce indistinguishable from a system that had missed the data.

    Written from a throwaway thread, never inline. schedule() is called from
    inside update_run_status while it holds that run's lock, and its contract is
    explicit that it must not touch the database -- a case-log write is a
    read-modify-write of a row, and doing it here would stall the status update
    that carries the run's actual result.

    Only on a FRESH quiet window. A multi-host hunt re-arms this timer once per
    landing run, and the entire point of the debounce is that twenty runs
    produce ONE rebuild -- so they produce one line, not twenty.
    """
    def _write():
        try:
            store = _store()
            # Announce only what is really going to happen. schedule() cannot
            # check this itself -- it runs under a lock and must not read the
            # database -- but this thread can, and a stray or catch-up arming on
            # a case with nothing outstanding must stay silent rather than
            # promising a rebuild that _fire will correctly decline to do.
            d = store.get_case(case_id)
            if not d or not _enabled(store, case_id, d):
                return
            if not store.stale_member_runs(case_id, d):
                return
            store.log_case_event(
                case_id, "New data landed", "info",
                f"{reason} — fusing once the case has been quiet for "
                f"{int(wait)}s (more data arriving restarts that wait)")
        except Exception as e:                 # noqa: BLE001 — telemetry only
            print(f"[AUTOFUSE] could not log arming for {case_id}: {e}", flush=True)
    threading.Thread(target=_write, name=f"autofuse-announce-{case_id}",
                     daemon=True).start()


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
        # NOTE: no log line here on purpose. fuse_case already narrates itself
        # into the case log ("Refusion · starting" through "Refusion complete"
        # with counts), so anything added around it duplicates. The gap this
        # feature was missing is EARLIER — between pressing Fetch and the fuse
        # being armed — and it is filled by the recollect worker, not here.
        try:
            store.fuse_case(case_id,
                            trigger=store.TRIGGER_AUTOMATIC_RUN_LANDED,
                            allow_llm=False)
            store._merge_case_details(case_id, {"auto_fuse_incomplete": False})
            # The graph is current. Bring the words that describe it up to date
            # too — SEPARATELY, so a narration that fails or is refused never
            # rolls back or re-marks the fuse that just succeeded.
            _regenerate_report(case_id, d)
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


def _regenerate_report(case_id, d=None, attempt=0) -> None:
    """Re-narrate a case whose graph just changed under it.

    Narrates with the model when one is configured and with the deterministic
    air-gap narrator when one is not — the operator gets a current report either
    way, which is the whole point. `llm_sim._use_real()` is the SAME question the
    manual path asks, so an appliance with no model, no key or no route takes the
    free path here rather than spending a connection timeout on every collection.

    Both paths go through `regenerate_report_async`, which holds the per-case
    report lock either way — that lock is why. With a model the work is two
    sequential calls (measured at 5m29s on a real case), so it moves to a thread,
    sets `report_generating` for the case view's poll, and returns at once rather
    than parking this timer. Without one it is a string render and answers inline.
    What matters is that a deterministic automatic report and an operator's LLM
    report can now be in flight together, and whichever finished last used to
    overwrite the other.

    Every failure here is contained. The graph is already saved and correct; a
    report that could not be written is worth a line in the activity log and
    nothing more, because the alternative — letting it escape — lands in _fire's
    handler, which would blame the fuse and clear a flag it did not set.

    IT MUST NOT PAY TWICE. Reaching here supersedes any retry already armed for
    this case, so the first thing it does is cancel one. Without that: a retry is
    waiting on a busy report, new data lands, _fire regenerates successfully, and
    the orphaned retry fires a minute later and buys a second narration of data
    the report already describes. _fire_report guards the same thing from the
    other side.
    """
    store = _store()
    _cancel_report_retry(case_id)
    try:
        if d is None:
            d = store.get_case(case_id) or {}
        if not d:
            return                             # case deleted while we waited
        if not _report_enabled(d):
            return                             # narration turned off for this case
        use_llm = False
        try:
            from services.fusion import llm_sim
            use_llm = bool(llm_sim._use_real())
        except Exception:                      # noqa: BLE001 — no model is not an error
            use_llm = False
        try:
            store.regenerate_report_async(case_id, use_llm=use_llm)
        except store.ReportGenerationBusy:
            # A report is mid-flight — an LLM one runs for minutes, so a second
            # collection landing inside that window is ordinary, not exceptional.
            # Retrying matters: the in-flight report was started from the PREVIOUS
            # graph and will finish describing data the case has already moved past.
            if attempt + 1 >= MAX_REPORT_RETRIES:
                store.log_case_event(
                    case_id, "Report not refreshed", "warning",
                    f"the automatic report gave up after {MAX_REPORT_RETRIES} attempts — "
                    f"a report has been generating throughout; click Regenerate report "
                    f"once it settles")
                return
            store.log_case_event(
                case_id, "Report refresh deferred", "info",
                f"a report is already being generated — retrying "
                f"(attempt {attempt + 1}/{MAX_REPORT_RETRIES})")
            _schedule_report(case_id, attempt + 1)
    except Exception as e:                     # noqa: BLE001 — never escape into _fire
        try:
            _store().log_case_event(
                case_id, "Report refresh failed", "error",
                f"the graph was rebuilt, but the report could not be regenerated — "
                f"{type(e).__name__}: {e}")
        except Exception:
            pass


def _cancel_report_retry(case_id) -> None:
    """Disarm a pending report retry. Whatever is calling this is about to do the
    retry's job, so letting it also fire is a duplicate — and a billed one."""
    with _GUARD:
        t = _REPORT_TIMERS.pop(case_id, None)
    if t is not None:
        t.cancel()


def _schedule_report(case_id, attempt) -> None:
    """Arm a retry of the report step alone. Its own timer registry: re-arming the
    FUSE would be wrong — the graph is already current, so _fire would find nothing
    stale and return before ever reaching the report."""
    with _GUARD:
        old = _REPORT_TIMERS.pop(case_id, None)
        if old is not None:
            old.cancel()
        t = threading.Timer(REPORT_RETRY_SECONDS, _fire_report, args=(case_id, attempt))
        t.daemon = True
        _REPORT_TIMERS[case_id] = t
        t.start()


def _fire_report(case_id, attempt) -> None:
    """The retry timer expired: re-narrate, but only if that is still needed.

    The mirror of _fire's `if not stale: return` — and for the same reason. This
    retry exists because a report was busy a minute ago; by now that report may
    have finished and already covered this data, or an operator may have pressed
    Regenerate themselves. Narrating anyway would rewrite a current report with
    an identical one, and on a box with a model configured that costs real money.

    report_stale_runs is the honest answer to "does the written report reflect
    every completed member run", now that regenerate_report stamps report_run_ids.
    A legacy case that has a report but no tracking answers "not behind", so the
    retry stands down — the conservative direction: a missed refresh is visible
    and fixable, a surprise bill is neither.
    """
    with _GUARD:
        _REPORT_TIMERS.pop(case_id, None)
    store = _store()
    try:
        if not store.report_stale_runs(case_id):
            return                             # someone already covered this data
    except Exception:                          # noqa: BLE001 — a broken probe must
        pass                                   # not strand the report behind forever
    _regenerate_report(case_id, None, attempt)
