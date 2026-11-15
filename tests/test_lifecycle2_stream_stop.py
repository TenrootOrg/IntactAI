"""A stopped collection is not logged as a success (QA item D2,
implicit-state-machines 2026-11-09): the cancel break fell through to the green
"All flows finished" line. Runs the real _stream loop on the fake clock of
test_errored_flow_keeps_collecting.py.
"""
import importlib.util
import os
import threading
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "_errflow", os.path.join(HERE, "test_errored_flow_keeps_collecting.py"))
_errflow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_errflow)


class StoppedCollectionIsNotASuccess(unittest.TestCase):

    def _collect(self, cancel):
        mod = _errflow._load()
        clock = types.SimpleNamespace(now=0)
        mod.check_flow_status = lambda *a: ("RUNNING", None)
        mod.enumerate_flow_sources = lambda *a: ["Src"]
        mod.query_artifact_results = lambda *a, start_row=0, **k: [] if start_row else [{"i": 1}]
        logs = []
        mod.add_log_to_run = lambda rid, msg, lvl="info": logs.append((lvl, msg))
        mod.register_cleanup = mod.cancel_collections = lambda *a, **k: None
        mod.time = types.SimpleNamespace(sleep=lambda s: setattr(clock, "now", clock.now + s),
                                         monotonic=lambda: clock.now)
        # No unset Event for the uncancelled run: the loop sleeps in ev.wait(),
        # on the real clock.
        ev = threading.Event() if cancel else None
        if ev:
            ev.set()
        mod.stream_collect_and_analyze("run_1", [{"client_id": "C.1", "flow_id": "F.1"}],
                                       ["Src"], 5, cancel_event=ev)
        return logs

    def test_stop_logs_stopped_not_finished(self):
        text = " | ".join(m for _, m in self._collect(cancel=True))
        self.assertNotIn("All flows finished", text)
        self.assertIn("Collection stopped", text)

    def test_window_close_still_says_so(self):
        text = " | ".join(m for _, m in self._collect(cancel=False))
        self.assertIn("Collection window closed", text)
        self.assertNotIn("Collection stopped", text)


if __name__ == "__main__":
    unittest.main()
