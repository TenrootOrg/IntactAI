"""The Velociraptor data purge counts deletions as they stream (audit F26, 2026-10-14).

It kept every deleted row in a Python list only to take len() of it, and asked for
batches of up to 2,000,000 rows, so a fleet purge held millions of dicts (and one
huge JSON string per batch) in memory for up to 1,800 s.
"""
import json
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velociraptor_service as vs  # noqa: E402

BATCHES = {"FROM hunts()": [3], "flow_delete": [10000, 10000, 2], "/artifacts/**": [7], "/monitoring/**": [0, 5]}


class Stub:
    def __init__(self):
        self.max_rows = []

    def Query(self, req, timeout=None):
        self.max_rows.append(req.max_row)
        vql = req.Query[0].VQL
        key = next(k for k in BATCHES if k in vql)
        for n in BATCHES[key]:
            yield types.SimpleNamespace(Response=json.dumps([{"deleted": True}] * n))
        yield types.SimpleNamespace(Response="")       # empty frames carry no rows


class PurgeCountsWhileStreaming(unittest.TestCase):
    def setUp(self):
        self.stub = Stub()
        self.saved = (vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub, vs.api_pb2)
        vs.setup_velociraptor_connection = lambda: types.SimpleNamespace(close=lambda: None)
        vs.api_pb2_grpc.APIStub = lambda ch: self.stub
        vs.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=types.SimpleNamespace,
                                           VQLRequest=types.SimpleNamespace)

    def tearDown(self):
        vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub, vs.api_pb2 = self.saved

    def test_counts_every_batch(self):
        out = vs.purge_velociraptor_data(logger=lambda *a: None)
        self.assertEqual({"hunts": 3, "flows": 20002, "data_files": 7, "monitoring": 5, "errors": []}, out)

    def test_batches_are_bounded(self):
        vs.purge_velociraptor_data(logger=lambda *a: None)
        self.assertEqual(4, len(self.stub.max_rows))
        self.assertTrue(all(m <= 10000 for m in self.stub.max_rows), self.stub.max_rows)


if __name__ == "__main__":
    unittest.main()
