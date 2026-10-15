"""A manual Refusion re-downloads a live collection only when it can hold more.

Measured 2026-10-15: 18.7 s to download one 145k-row collection, and the
re-snapshot that follows invalidates the run's mapping cache -- paid again on
every manual Refusion for collections that finished days ago. One small
flows() query per flow now says whether anything can be new: ended, with the
same row count as the copy saved in full last time -> keep the snapshot.
Anything unknown (running, grown, never saved in full, Velociraptor down)
downloads exactly as before.
"""
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

FLOW, CLIENT = "F.ABC", "C.0123abcd"


class Velociraptor:
    """The flows() status and the result download, as the server answers them."""

    def __init__(self, state="FINISHED", rows=1000, down=False):
        self.state, self.rows, self.down, self.downloads = state, rows, down, 0

    def query(self, vql, timeout=120):
        if self.down:
            raise RuntimeError("Velociraptor is not reachable")
        assert "flows(client_id='C.0123abcd', flow_id='F.ABC')" in vql, vql
        return [{"state": self.state, "total_collected_rows": self.rows}]

    def fetch(self, *a, **k):
        self.downloads += 1
        return {"Windows.System.Pslist": [{"Pid": 1}]}, [], {}


class FinishedCollections(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fp = os.path.join(self.tmp, "raw_results.json")
        with open(self.fp, "w") as f:
            json.dump({"Windows.System.Pslist": [{"Pid": 1}]}, f)
        self.logs = []

    def refusion(self, vr):
        col = types.ModuleType("services.agentic.collectors")
        col.get_existing_collection_results = vr.fetch
        vc = types.ModuleType("services.velociraptor_clients")
        vc._query = vr.query
        det = {"flow_id": FLOW, "client_id": CLIENT}
        with mock.patch.dict(sys.modules, {"services.agentic.collectors": col, "services.velociraptor_clients": vc}), \
                mock.patch.object(store, "_raw_results_path", lambda rid, d: self.fp), \
                mock.patch.object(store, "_resnapshot_without_losing_rows", lambda *a, **k: None):
            return store._refetch_agentic_rows("r1", det, log=lambda m, l="info": self.logs.append(m))

    def test_finished_and_saved_in_full_is_not_downloaded_again(self):
        vr = Velociraptor()
        self.assertIsNotNone(self.refusion(vr), "never saved in full: downloaded once")
        self.assertEqual(1, vr.downloads)
        with open(os.path.join(self.tmp, store.FINAL_NAME)) as f:
            self.assertEqual({FLOW: 1000}, json.load(f))
        self.assertIsNone(self.refusion(vr), "the snapshot (and its mapping cache) is used")
        self.assertEqual(1, vr.downloads)
        self.assertIn("finished in Velociraptor and already saved in full", self.logs[-1])

    def test_rows_that_arrived_after_the_save_are_downloaded(self):
        vr = Velociraptor()
        self.refusion(vr)
        vr.rows = 1500
        self.assertIsNotNone(self.refusion(vr))
        self.assertEqual(2, vr.downloads)

    def test_a_running_flow_is_downloaded_and_never_marked_whole(self):
        vr = Velociraptor(state="RUNNING")
        self.refusion(vr)
        self.refusion(vr)
        self.assertEqual(2, vr.downloads)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, store.FINAL_NAME)))

    def test_an_errored_flow_has_ended_too(self):
        vr = Velociraptor(state="ERROR")
        self.refusion(vr)
        self.refusion(vr)
        self.assertEqual(1, vr.downloads)

    def test_velociraptor_down_for_the_status_check_downloads_as_before(self):
        vr = Velociraptor()
        self.refusion(vr)
        vr.down = True
        self.refusion(vr)
        self.assertEqual(2, vr.downloads, "unknown is never a reason to skip")


if __name__ == "__main__":
    unittest.main()
