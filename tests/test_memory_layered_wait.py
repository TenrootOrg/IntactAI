"""A layered run must not mistake its own YARA dispatch for the plugin task ending.

VolWeb keeps ONE `celery_task_id` slot per evidence, and two different views
write to it: the selective-extraction view and the yarascan view. In layered
mode (plugins + YARA — what the UI ships with ticked) we dispatch the yarascan
about a second after the extraction, so the slot stops holding our extraction
id almost immediately.

The fail-fast added for the symbol-download incident read "the slot no longer
holds my id" as "my task reached a terminal state" and aborted. Live, that
failed a layered run 6 seconds in, having extracted 13 plugin rows that were
sitting in VolWeb's database the whole time.

Only the extraction task's own `finally` (and an explicit stop) writes "" back,
and the yarascan task never touches the field — so emptiness is the signal, and
a different id is not.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "modules/backend/services/memory/volweb_client.py")


def _load(path, name):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"os": os}
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


ended = _load(CLIENT, "_extraction_task_ended")

OURS = "97a233c6-fffe-48aa-9e96-22e7328e1d72"


class TestWhatCountsAsTheTaskEnding(unittest.TestCase):

    def test_an_empty_slot_means_it_ended(self):
        """The task's finally wrote "" — this is the symbol-failure case the
        fail-fast exists for."""
        self.assertTrue(ended({"celery_task_id": "", "status": 0}))

    def test_a_missing_field_means_it_ended(self):
        self.assertTrue(ended({"status": 0}))

    def test_a_null_field_means_it_ended(self):
        self.assertTrue(ended({"celery_task_id": None}))

    def test_whitespace_is_empty(self):
        self.assertTrue(ended({"celery_task_id": "   "}))

    def test_our_own_id_means_it_is_still_running(self):
        self.assertFalse(ended({"celery_task_id": OURS}))

    def test_the_yarascan_claiming_the_slot_is_not_our_task_ending(self):
        """THE REGRESSION. A different, non-empty id is the yarascan we
        dispatched ourselves — it says nothing about the extraction."""
        self.assertFalse(ended({"celery_task_id": "a-completely-different-task-id"}))

    def test_a_flaky_read_is_not_evidence_of_anything(self):
        self.assertFalse(ended(None), "'don't know' must never be read as 'finished'")


class TestTheCallSiteUsesIt(unittest.TestCase):
    """The helper only helps if the wait loop actually calls it — an inline
    comparison left behind would keep the bug alive."""

    SRC = open(CLIENT, encoding="utf-8").read()

    def test_the_wait_loop_asks_the_helper(self):
        self.assertIn("if _extraction_task_ended(ev):", self.SRC)

    def test_no_inequality_against_the_task_id_survives(self):
        self.assertNotIn('!= task_id', self.SRC,
                         "comparing the slot to our id is exactly the bug")


if __name__ == "__main__":
    unittest.main(verbosity=2)
