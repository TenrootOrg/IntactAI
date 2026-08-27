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

The REAL function is lifted out of workflow_service.py and executed against
stubs, so this cannot drift from what ships.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = os.path.join(ROOT, "modules/backend/services/workflow_service.py")


def _load():
    with open(SERVICE, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    node = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "add_log_to_run")

    import contextlib
    import datetime as _dt
    state = {"wf": None, "saved": 0}

    ns = {
        "_state": state,
        "datetime": _dt.datetime,
        "_get_run_log_lock": lambda rid: contextlib.nullcontext(),
        "file_get_workflow": lambda rid: state["wf"],
    }

    def _save(wf):
        state["wf"] = wf
        state["saved"] += 1
    ns["save_workflow"] = _save

    exec(compile(ast.Module(body=[node], type_ignores=[]), SERVICE, "exec"), ns)
    return ns, state


NS, STATE = _load()
add_log_to_run = NS["add_log_to_run"]


def _wf(status):
    return {"run_id": "r1", "status": status, "logs": []}


def _logs():
    return [l["message"] for l in (STATE["wf"] or {}).get("logs", [])]


class TestRaceResidueIsStillDropped(unittest.TestCase):
    """The guard's original purpose, which the fix must not break."""

    def setUp(self):
        STATE["wf"] = _wf("cancelled")

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
        STATE["wf"] = _wf("cancelled")

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
        self.assertEqual(STATE["wf"].get("error_count"), 1,
                         "a forced error must still reach error_count")


class TestEveryOtherStatusIsUnaffected(unittest.TestCase):
    """force= changes exactly one thing: the cancelled guard."""

    def test_a_running_run_logs_without_force(self):
        for status in ("running", "pending", "completed", "failed"):
            with self.subTest(status=status):
                STATE["wf"] = _wf(status)
                add_log_to_run("r1", "hello")
                self.assertEqual(_logs(), ["hello"])

    def test_a_missing_workflow_is_a_no_op(self):
        STATE["wf"] = None
        add_log_to_run("r1", "hello", force=True)          # must not raise
        self.assertIsNone(STATE["wf"])
