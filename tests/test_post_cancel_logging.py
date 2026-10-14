"""A deliberate operation after a cancel must be allowed to speak.

Reported from the box (case 'test2'): an operator stopped a Velociraptor
collection, then pressed Fetch on that same run to pull what the server already
had. The fetch WORKED — it re-read 481,253 rows and wrote them to the run's
details — and produced not one line of output. The button looked dead.

add_log_to_run drops every log on a cancelled run:

    if workflow.get("status") == "cancelled":
        return

That guard is right for what it was written for. When a Stop lands, background
threads are still unwinding, and their "success"/"failed" lines arriving after
"[Pipeline] Stop requested by user" made the cancelled timeline read as
confused nonsense. Race residue should be dropped.

But a Fetch pressed minutes later is not residue. It is a new operation the
operator started, on purpose, on a run they know is finished. Callers that own
such an operation pass force=True; everything else keeps the old behaviour.

The REAL add_log_to_run runs against a real SQLite database in a temp dir
(created by the product's own init_storage), so this cannot drift from what
ships. It used to be lifted out by AST and run against stubs; since the guard
moved into the INSERT itself (storage.append_workflow_log) a stub would test
nothing.
"""

import os
import sys
import tempfile
import unittest

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-postcancel-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

import _optional_deps  # noqa: F401,E402
from services.storage import delete_workflow, get_workflow, init_storage, save_workflow  # noqa: E402

init_storage()
from services.workflow_service import add_log_to_run  # noqa: E402


def _wf(status):
    """(Re)create run r1 with this status; None leaves no run at all."""
    delete_workflow("r1")
    if status is not None:
        save_workflow({"run_id": "r1", "status": status, "logs": []})


def _run():
    return get_workflow("r1")


def _logs():
    return [l["message"] for l in (_run() or {}).get("logs", [])]


class TestRaceResidueIsStillDropped(unittest.TestCase):
    """The guard's original purpose, which the fix must not break."""

    def setUp(self):
        _wf("cancelled")

    def test_an_unforced_log_on_a_cancelled_run_is_dropped(self):
        add_log_to_run("r1", "[Velociraptor] All flows completed naturally", "success")
        self.assertEqual(_logs(), [],
                         "subprocess wrap-up after a Stop is residue, not news")

    def test_several_residue_lines_are_all_dropped(self):
        for msg in ("[Pipeline] Collected 0 rows", "[Pipeline] done", "cleanup"):
            add_log_to_run("r1", msg)
        self.assertEqual(_logs(), [])


class TestADeliberateOperationIsHeard(unittest.TestCase):
    """The reported bug."""

    def setUp(self):
        _wf("cancelled")

    def test_a_forced_log_reaches_a_cancelled_run(self):
        add_log_to_run("r1", "[Fetch] Asking Velociraptor for this run's results",
                       "info", force=True)
        self.assertEqual(_logs(),
                         ["[Fetch] Asking Velociraptor for this run's results"])

    def test_the_whole_fetch_narrative_survives(self):
        """One line then silence is indistinguishable from a dead button, which
        is why the fetch reports every source as it lands."""
        for msg in ("[Fetch] Asking Velociraptor…",
                    "[Fetch] Flow 1/1: F.DA84OIQLD6GP6",
                    "[Fetch] Done — 481,253 row(s) across 37 artifact(s)."):
            add_log_to_run("r1", msg, "info", force=True)
        self.assertEqual(len(_logs()), 3)
        self.assertIn("481,253", _logs()[-1])

    def test_forcing_an_error_still_counts_it(self):
        add_log_to_run("r1", "[Fetch] Failed: ConnectionError", "error", force=True)
        self.assertEqual(_run().get("error_count"), 1,
                         "a forced error must still reach error_count")


class TestEveryOtherStatusIsUnaffected(unittest.TestCase):
    """force= changes exactly one thing: the cancelled guard."""

    def test_a_running_run_logs_without_force(self):
        for status in ("running", "pending", "completed", "failed"):
            with self.subTest(status=status):
                _wf(status)
                add_log_to_run("r1", "hello")
                self.assertEqual(_logs(), ["hello"])

    def test_a_missing_workflow_is_a_no_op(self):
        _wf(None)
        add_log_to_run("r1", "hello", force=True)          # must not raise
        self.assertIsNone(_run())


if __name__ == "__main__":
    unittest.main()
