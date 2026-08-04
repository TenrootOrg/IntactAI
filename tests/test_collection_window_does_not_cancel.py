"""Collection Time bounds how long we WAIT, not how long the endpoints work.

The pipeline used to call cancel_collections() the moment the collection window
closed. That killed flows mid-write, so everything a slow client still had to
send was thrown away — and on a large artifact set that is most of the
collection. The operator paid the full cost of running the hunt and got a
fraction of the data, with no way to recover it short of re-running the whole
thing against the same hosts.

The window is meant to bound the PIPELINE: at the deadline, snapshot what has
arrived and hand it to fusion. The flows themselves should run to completion in
Velociraptor, where their full output stays queryable.

Two things this has to keep true, and both are easy to break:

  1. A user-requested Stop MUST still cancel the flows. That path is separate:
     _stream.py registers cancel_collections as a cleanup callback, and
     workflow_service only invokes cleanups from stop_workflow() — never on
     normal completion. So removing the timeout cancel does not weaken Stop.

  2. The operator has to be told the data is not lost. A "PARTIAL" message whose
     only advice is "raise Collection Time" implies the missing rows are gone;
     they are still being written, in Velociraptor.

Static assertions over the pipeline + collector sources. No live Velociraptor.

Run: docker exec intact_backend python3 /app/workdir/tests/test_collection_window_does_not_cancel.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
RUNNERS = os.path.join(REPO, "modules", "backend", "services", "agentic",
                       "pipeline", "_runners.py")
STREAM = os.path.join(REPO, "modules", "backend", "services", "agentic",
                      "collectors", "_stream.py")
WORKFLOW = os.path.join(REPO, "modules", "backend", "services", "workflow_service.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _code_only(text):
    """Strip whole-line comments so a mention of cancel_collections inside an
    explanatory note doesn't read as a live call."""
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


# --- the regression -----------------------------------------------------------


def test_the_pipeline_does_not_cancel_flows_when_the_window_closes():
    code = _code_only(_read(RUNNERS))
    calls = [ln.strip() for ln in code.splitlines()
             if re.search(r'\bcancel_collections\s*\(', ln)]
    assert not calls, (
        f"the pipeline still cancels collections; a flow killed mid-write loses "
        f"everything the client had left to send: {calls}")


def test_cancel_collections_is_not_even_imported_by_the_pipeline():
    """Belt and braces — an unused import is an invitation to call it again."""
    code = _code_only(_read(RUNNERS))
    import_block = code[:code.index("def ")] if "def " in code else code
    assert "cancel_collections" not in import_block, \
        "cancel_collections is imported by the pipeline again"


# --- what must still work -----------------------------------------------------


def test_a_user_stop_still_cancels_the_flows():
    """The whole point of removing the timeout cancel is that it was the WRONG
    trigger — not that cancelling is wrong."""
    code = _code_only(_read(STREAM))
    assert "register_cleanup" in code, \
        "the collector no longer registers a cleanup, so Stop cannot cancel flows"
    assert re.search(r'register_cleanup\([^)]*cancel_collections', code, re.DOTALL), \
        "the registered cleanup no longer cancels the collections"


def test_cleanups_run_only_on_stop_not_on_normal_completion():
    """If cleanups also fired at the end of a successful run, the registered
    canceller would kill the flows anyway and this change would be a no-op."""
    body = _read(WORKFLOW)
    start = body.index("def register_cleanup")
    doc = body[start:start + 400]
    assert "stop" in doc.lower(), \
        "register_cleanup no longer documents that it fires on stop only"

    # The callback list is READ in exactly one place. Locate the enclosing
    # function by walking back to the nearest `def` — if that is ever something
    # other than stop_workflow, cleanups fire outside a Stop and the flows would
    # be cancelled on a normal run again.
    read_at = body.index("callbacks = list(_cleanup_callbacks")
    enclosing = re.findall(r'^def (\w+)\(', body[:read_at], re.MULTILINE)
    assert enclosing, "could not find the function that drains the cleanup list"
    assert enclosing[-1] == "request_stop", (
        f"the cleanup list is drained by {enclosing[-1]!r}, not request_stop — "
        f"if that runs on normal completion it cancels the flows anyway")

    # And only one reader, so there is no second path.
    assert body.count("callbacks = list(_cleanup_callbacks") == 1, \
        "more than one place drains the cleanup callbacks"


def test_the_watchdog_cannot_silently_undo_this():
    """_start_watchdog fires request_stop() at collection_minutes + 15m grace,
    which drains the cleanups and DOES cancel the flows. That is correct for a
    genuinely stuck pipeline — but only because the pipeline cancels the timer on
    the way out. Without that .cancel(), every normal run would have its flows
    killed 15 minutes after the window and this whole change would be inert."""
    code = _read(RUNNERS)
    assert "_watchdog.cancel()" in code, (
        "the pipeline no longer cancels its watchdog, so request_stop() will fire "
        "after collection_minutes + grace and cancel the still-running flows")
    finally_at = code.rindex("finally:")
    assert "_watchdog.cancel()" in code[finally_at:], \
        "the watchdog is not cancelled in the finally block, so an early return " \
        "or an exception leaves the timer armed"


# --- the operator must know the data still exists -----------------------------


def test_the_timeout_message_says_flows_are_not_cancelled():
    code = _read(RUNNERS)
    start = code.index("if timed_out:")
    window = code[start:start + 900]
    lowered = window.lower()
    assert "not cancel" in lowered or "left to finish" in lowered or \
           "keep running" in lowered, (
        "the timeout message does not tell the operator the flows continue; "
        "they will assume the collection was truncated and the data lost")


def test_the_row_count_summary_is_not_duplicated_per_outcome():
    """There used to be two summaries — a green "Collection complete: N rows" and
    an orange "Collection SNAPSHOT: N rows ..." — chosen by timed_out. One count,
    logged the same way either way, is enough."""
    code = _code_only(_read(RUNNERS))
    summaries = re.findall(r'add_log_to_run\((?:[^()]|\([^()]*\))*Collected \{total_rows\}'
                           r'(?:[^()]|\([^()]*\))*\)', code, re.DOTALL)
    assert len(summaries) == 1, (
        f"expected exactly one row-count summary, found {len(summaries)}")
    assert "SNAPSHOT" not in code, \
        "the shouty SNAPSHOT wording is back"


def test_the_run_ends_with_a_normal_completion():
    """Reaching a limit the operator chose is not a failure, so the run finishes
    the same way either way.

    An earlier revision branched this on timed_out and closed with an orange
    "NOT the full collection". That over-corrected: by then the time-limit note
    has already been logged once (see the test below), so the closing shout only
    made a normal outcome look broken.
    """
    code = _code_only(_read(RUNNERS))
    assert 'add_log_to_run(run_id, "[Collection] Collection completed' in code, \
        "the run no longer ends with a plain completion line"
    idx = code.index('add_log_to_run(run_id, "[Collection] Collection completed')
    # Unconditional: no `if timed_out:` between the phase update and this line.
    phase_at = code.index('_update_phase(run_id, "completed", 100)')
    assert "if timed_out" not in code[phase_at:idx], (
        "the completion line is branched on timed_out again — a run that hit its "
        "time limit still completed, and saying otherwise reads as a fault")


def test_the_time_limit_is_explained_exactly_once():
    """Five near-identical messages inside two seconds is what made this feel
    alarming — the same log-noise pattern already cut from the streaming
    heartbeat. The explanation belongs in one place."""
    code = _code_only(_read(RUNNERS)) + _code_only(_read(STREAM))
    logged = re.findall(r'add_log_to_run\((?:[^()]|\([^()]*\))*\)', code, re.DOTALL)
    # Anchored on "... in Velociraptor" / "finish there" on purpose: a bare
    # "still running" also matches the streaming heartbeat ("Still running — 0m
    # 30s left"), which is a different, wanted message.
    mentions = [m for m in logged
                if re.search(r'(?:keep|still) running in Velociraptor|'
                             r'finish there|not cancelled',
                             m, re.IGNORECASE)]
    assert len(mentions) == 1, (
        f"the 'flows continue' explanation appears in {len(mentions)} log lines; "
        f"it should be stated once:\n" +
        "\n".join(m[:120] for m in mentions))


def test_that_one_explanation_is_informative_not_alarming():
    code = _code_only(_read(RUNNERS))
    logged = re.findall(r'add_log_to_run\((?:[^()]|\([^()]*\))*\)', code, re.DOTALL)
    note = [m for m in logged if "Reached the" in m and "collection time" in m]
    assert note, "the time-limit note is gone — the operator gets no explanation"
    note = note[0]
    assert '"info"' in note or "'info'" in note, \
        "the time-limit note is not at info level; reaching a chosen limit is " \
        "not a warning"
    # No shouting.
    assert not re.search(r'\bNOT\b|\bSTILL RUNNING\b|SNAPSHOT', note), \
        f"the note still shouts at the operator: {note[:200]}"
    # But it must still convey the two useful facts.
    assert re.search(r'keep running|finish there', note, re.IGNORECASE), \
        "the note does not say the flows continue in Velociraptor"
    assert "Collection Time" in note, \
        "the note does not tell the operator how to capture more next time"


def test_the_run_status_is_still_completed():
    """Guard the other direction: making the wording honest must not turn a
    finished pipeline into a permanently 'running' row."""
    code = _read(RUNNERS)
    tail = code[code.index('_update_phase(run_id, "completed", 100)'):]
    assert 'update_run_status(run_id, "completed", progress=100)' in tail, \
        "the pipeline no longer marks the run completed — the UI would show it " \
        "as stuck forever"


def test_the_collector_line_marks_its_total_as_provisional():
    code = _read(STREAM)
    start = code.index("Collection window closed")
    window = code[start:start + 400]
    assert "so far" in window, \
        "the collector's closing line reads as a final total, but flows continue"


# --- the data-visibility consequence, pinned so nobody is surprised by it -----


def test_the_snapshot_is_what_gets_persisted():
    """persist_pipeline_artifacts runs after the window, so rows written later do
    NOT reach this run's Case. That is a real limitation and the code should say
    so rather than leave it to be rediscovered."""
    code = _read(RUNNERS)
    assert "persist_pipeline_artifacts" in code
    assert re.search(r'(do not reach|not reach this run|after the window)',
                     code, re.IGNORECASE), (
        "the consequence of snapshotting (late rows never enter the Case) is "
        "not documented at the timeout branch")


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
