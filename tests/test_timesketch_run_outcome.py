"""A multi-client Timesketch run reports how many hosts really imported (E5).

The run used to end green "completed, Plaso N/N" as long as one KAPE flow
started, even when every host timed out or failed import.
"""
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_timesketch_pipeline_bounded import Harness, ks, kus  # noqa: E402


class RunOutcome(Harness):
    def run_with(self, results):
        """results: per-host process_kape_upload status, or 'timeout' for a KAPE flow that never finished."""
        def monitor(cid, fid, **_k):
            return "TIMEOUT" if results[int(cid[2:], 16)] == "timeout" else "FINISHED"

        def export(cid, fid, path, logger=None):
            open(path, "w").close()
            return True

        def upload(zip_path, original_filename, settings, run_id=None, cleanup_zip=True,
                   suppress_status_writes=False, on_plaso_done=None):
            os.remove(zip_path)
            on_plaso_done()
            st = results[int(settings["client_name"].split("-")[1])]
            return {"status": st, "error": "boom"}

        with mock.patch.object(ks, "monitor_flow_completion", monitor), \
                mock.patch.object(ks, "export_flow_to_zip", export), \
                mock.patch.object(kus, "process_kape_upload", upload):
            self.run_pipeline(len(results), threading.Event())

    def test_all_clients_failed_marks_run_failed(self):
        self.run_with(["timeout", "failed", "failed"])
        self.assertEqual(self.statuses[-1], "failed")
        self.assertTrue(any("all 3 clients failed" in m for _l, m in self.logs))

    def test_some_failed_completes_and_says_how_many(self):
        self.run_with(["completed", "failed", "timeout"])
        self.assertEqual(self.statuses[-1], "completed")
        self.assertTrue(any("1/3 imported, 2/3 failed" in m for _l, m in self.logs), self.logs)

    def test_all_succeeded_completes(self):
        self.run_with(["completed", "no_events"])
        self.assertEqual(self.statuses[-1], "completed")
        self.assertTrue(any(l == "success" and "2/2 imported" in m for l, m in self.logs))


if __name__ == "__main__":
    unittest.main()
