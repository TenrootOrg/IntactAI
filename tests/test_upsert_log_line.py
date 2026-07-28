"""upsert_log_line: one live status line instead of a transcript of one.

Long-running progress that appends floods the run log. A 4-part, 6 GB package
reporting every 30s over ~10 minutes adds ~20 near-identical lines, and the
per-part variant it replaced added ~80 interleaved ones -- burying the entries
that actually matter (retries, warnings, what happened next).

This rewrites the single line that starts with the caller's marker, so the
operator reads a live status rather than scrolling its history.

Run: docker exec intact_backend python /app/workdir/tests/test_upsert_log_line.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services import workflow_service as W  # noqa: E402

MARKER = "Download: "


class _Store:
    """Stands in for the workflow file/DB layer."""

    def __init__(self, status="running", logs=None):
        self.wf = {"id": "run_1", "status": status, "logs": list(logs or [])}
        self.saves = 0

    def install(self):
        self._get, self._save = W.file_get_workflow, W.save_workflow
        W.file_get_workflow = lambda rid: self.wf
        def _save(wf):
            self.saves += 1
        W.save_workflow = _save
        return self

    def restore(self):
        W.file_get_workflow, W.save_workflow = self._get, self._save

    def messages(self):
        return [e["message"] for e in self.wf["logs"]]


def _run(store, *calls):
    store.install()
    try:
        for msg in calls:
            W.upsert_log_line("run_1", MARKER, msg)
    finally:
        store.restore()


def test_first_call_appends():
    s = _Store()
    _run(s, MARKER + "10%")
    assert s.messages() == [MARKER + "10%"], s.messages()


def test_repeated_calls_rewrite_one_line():
    s = _Store()
    _run(s, MARKER + "10%", MARKER + "40%", MARKER + "100%")
    assert s.messages() == [MARKER + "100%"], (
        f"progress appended instead of rewriting: {s.messages()}")


def test_other_entries_are_untouched_and_keep_their_order():
    """Retries and warnings still append AFTER the status line, which stays
    where the phase began -- that is where it belongs chronologically."""
    s = _Store(logs=[{"timestamp": "t0", "level": "info", "message": "Starting download"}])
    s.install()
    try:
        W.upsert_log_line("run_1", MARKER, MARKER + "10%")
        W.add_log_to_run("run_1", "download hiccup — retry 1/4", "warning")
        W.upsert_log_line("run_1", MARKER, MARKER + "90%")
    finally:
        s.restore()
    assert s.messages() == [
        "Starting download",
        MARKER + "90%",
        "download hiccup — retry 1/4",
    ], s.messages()


def test_level_and_timestamp_are_refreshed():
    s = _Store(logs=[{"timestamp": "old", "level": "info", "message": MARKER + "1%"}])
    s.install()
    try:
        W.upsert_log_line("run_1", MARKER, MARKER + "99%", "warning")
    finally:
        s.restore()
    entry = s.wf["logs"][0]
    assert entry["level"] == "warning", entry
    assert entry["timestamp"] != "old", "timestamp not refreshed — the UI would " \
                                        "show the line as stale"


def test_cancelled_runs_are_left_alone():
    """Same rule add_log_to_run enforces: once cancelled, the stop warning is
    the last word, so late progress must not overwrite the timeline."""
    s = _Store(status="cancelled",
               logs=[{"timestamp": "t", "level": "warning", "message": "Stop requested"}])
    _run(s, MARKER + "50%")
    assert s.messages() == ["Stop requested"], s.messages()
    assert s.saves == 0, "a cancelled run was written to"


def test_missing_workflow_is_a_noop():
    s = _Store()
    s.install()
    W.file_get_workflow = lambda rid: None
    try:
        W.upsert_log_line("gone", MARKER, MARKER + "5%")
    finally:
        s.restore()
    assert s.saves == 0


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
