"""A backend restart mid-batch fails a scheduled memory batch and names the hosts
it never reached.

The batch walks its hosts in one thread. The startup reaper failed the current
host's memory run but not the batch (memory_batch was not in _REAP_TYPES): the
batch sat "running" for 10 h until the orphan sweep, and the hosts after the
restart were dropped without a word.

Runs the reaper block of app.py itself against stub runs.
"""
import os
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "modules", "backend", "app.py")


def reap(runs):
    src = open(APP).read()
    start = src.index("        _REAP_TYPES = {")
    block = textwrap.dedent(src[start:src.index("        if _reaped:", start)])
    failed = {}
    exec(block, {"load_workflows": lambda with_logs=True: runs,
                 "update_run_status": lambda rid, st, error=None: failed.__setitem__(rid, (st, error))})
    return failed


class MemoryBatchIsReaped(unittest.TestCase):
    def test_batch_failed_and_unstarted_hosts_named(self):
        runs = [{"run_id": "b1", "automation_type": "memory_batch", "status": "running",
                 "details": {"client_ids": ["C.1", "C.2", "C.3"]}},
                {"run_id": "m1", "automation_type": "memory", "status": "completed",
                 "details": {"batch_run_id": "b1", "client_id": "C.1"}},
                {"run_id": "b0", "automation_type": "memory_batch", "status": "completed",
                 "details": {"client_ids": ["C.9"]}}]
        failed = reap(runs)
        self.assertEqual(["b1"], list(failed))
        st, why = failed["b1"]
        self.assertEqual("failed", st)
        self.assertIn("2 host(s) never started: C.2, C.3", why)


if __name__ == "__main__":
    unittest.main()
