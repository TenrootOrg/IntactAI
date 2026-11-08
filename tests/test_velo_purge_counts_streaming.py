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

# Order matters: the server-flow query also says delete_flow, so it is matched first.
BATCHES = {"FROM hunts()": [3], "FROM flows(client_id='server')": [71], "FROM delete_flow": [10000, 10000, 2],
           "/artifacts/**": [7], "/monitoring/**": [0, 5]}


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
        self.assertEqual({"hunts": 3, "flows": 20002, "server_flows": 71, "data_files": 7, "monitoring": 5,
                          "errors": []}, out)

    def test_batches_are_bounded(self):
        vs.purge_velociraptor_data(logger=lambda *a: None)
        self.assertEqual(5, len(self.stub.max_rows))
        self.assertTrue(all(m <= 10000 for m in self.stub.max_rows), self.stub.max_rows)



class ServerArtifactFlows(unittest.TestCase):
    """QA 2026-11-08: a purge left every offline import (Server.Utils.ImportCollection)
    and other server-artifact flow in Velociraptor's GUI: the flow query skips the
    'server' pseudo-client. They are deleted now, except the Server.Utils.Create*
    builders (the client MSI is registered from its flow's uploads) and running ones."""
    def setUp(self):
        self.vql = []
        test = self

        class S:
            def Query(self, req, timeout=None):
                test.vql.append(req.Query[0].VQL)
                yield types.SimpleNamespace(Response="[]")
        self.saved = (vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub, vs.api_pb2)
        vs.setup_velociraptor_connection = lambda: types.SimpleNamespace(close=lambda: None)
        vs.api_pb2_grpc.APIStub = lambda ch: S()
        vs.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=types.SimpleNamespace,
                                           VQLRequest=types.SimpleNamespace)

    def tearDown(self):
        vs.setup_velociraptor_connection, vs.api_pb2_grpc.APIStub, vs.api_pb2 = self.saved

    def test_server_flows_are_deleted_but_builders_and_running_ones_kept(self):
        vs.purge_velociraptor_data(logger=lambda *a: None)
        srv = [q for q in self.vql if "flows(client_id='server')" in q]
        self.assertEqual(1, len(srv))
        q = srv[0]
        self.assertIn("FROM delete_flow(client_id='server', flow_id=session_id, really_do_it=TRUE, sync=TRUE)", q)
        self.assertIn("state != 'RUNNING'", q)
        self.assertIn("NOT join(array=request.artifacts, sep=',') =~ '^Server.Utils.Create'", q)
        self.assertNotIn("\\", q, "no backslash escapes: VQL must receive the regex as written")

    def test_deletions_run_as_plugins_in_foreach(self):
        """flow_delete() / hunt_delete() as functions return null and delete
        nothing on 0.77.3, and a len(list={..}) sub-query did not delete either."""
        vs.purge_velociraptor_data(logger=lambda *a: None)
        q = " ".join(self.vql)
        self.assertNotIn("flow_delete", q)
        self.assertNotIn("len(list=", q)
        self.assertIn("query={ SELECT hunt_id, * FROM hunt_delete(hunt_id=hunt_id, really_do_it=TRUE) }", q)
        self.assertEqual(2, q.count("* FROM delete_flow("))

    def test_not_run_when_flows_are_kept(self):
        vs.purge_velociraptor_data(logger=lambda *a: None, delete_flows=False)
        self.assertFalse([q for q in self.vql if "flows(client_id='server')" in q])


if __name__ == "__main__":
    unittest.main()
