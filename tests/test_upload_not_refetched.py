"""A manual Refusion must not re-read an offline upload from Velociraptor.

Live: every Refusion logged "[Velociraptor] Rejecting invalid client_ids:
['server']" as an error on a finished upload, because the re-read asked for the
import's placeholder client. The upload's data cannot change, so it is not re-read.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402


class UploadIsNotRefetched(unittest.TestCase):
    def _run(self, atype, cid):
        run = {"automation_type": atype, "run_id": "r1",
               "details": {"flow_id": "F.ABC", "client_id": cid, "hunt_id": "H.ABC"}}
        import types
        fetch = mock.Mock(return_value=({}, [], {}))
        col = types.ModuleType("services.agentic.collectors")
        col.get_existing_collection_results = fetch
        col.persist_pipeline_artifacts = lambda *a, **k: None
        with mock.patch.object(store, "_agentic_collected_data", return_value={}), \
             mock.patch.dict(sys.modules, {"services.agentic.collectors": col}):
            store._contribution_for_run(run, refetch=True)
        return fetch.call_count

    def test_upload_is_not_reread(self):
        self.assertEqual(self._run("velociraptor_upload", "server"), 0)

    def test_live_collection_still_is(self):
        self.assertEqual(self._run("velociraptor_collection", "C.0123abcd"), 1)

    def test_invalid_client_id_is_skipped_quietly(self):
        self.assertEqual(self._run("velociraptor_collection", "server"), 0)


if __name__ == "__main__":
    unittest.main()
