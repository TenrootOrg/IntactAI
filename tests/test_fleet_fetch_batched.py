"""get_existing_collection_results at fleet scale: a constant number of queries.

F8 (fleet-scale audit 2026-10-14). To find which client owns a flow, the flow
path sent one flows() query per enrolled client, each with its own debug log
line: 1,000 flows x ~500 clients = ~500,000 queries for one Fetch. The search
now runs on the server, one query per attempt.

Fusion (services/fusion/store.py) calls this function, so the RETURN SHAPE is
pinned here exactly: (all_results, artifacts, client_info), rows tagged with
_client_id/_hostname, client_info entries {client_id, hostname, os}.
"""
import json
import os
import re
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.agentic.collectors import _base  # noqa: E402


class FakeVelociraptor:
    """Answers the VQL the collector sends, from an in-memory fleet.

    flows: {(client_id, flow_id): {source: [rows]}}; every other client is
    enrolled but owns nothing. `queries` is the gRPC cost under test."""

    def __init__(self, n_clients, flows, hostnames=None):
        self.clients = [f"C.{i:04d}" for i in range(n_clients)]
        self.flows = flows
        self.hostnames = hostnames or {}
        self.queries = []

    def _host(self, cid):
        return self.hostnames.get(cid, cid.lower())

    def _answer(self, vql):
        m = re.search(r"FROM clients\(\)( WHERE client_id IN \(([^)]*)\))?\}, "
                      r"query=\{SELECT LocCid, LocHost FROM flows\(client_id=LocCid, flow_id='([^']+)'\)", vql)
        if m:
            scope = re.findall(r"'([^']+)'", m.group(2)) if m.group(1) else self.clients
            for cid in scope:
                if (cid, m.group(3)) in self.flows:
                    return [{"LocCid": cid, "LocHost": self._host(cid)}]
            return []
        m = re.search(r"SELECT artifacts_with_results FROM flows\(client_id='([^']+)', flow_id='([^']+)'\)", vql)
        if m:
            srcs = self.flows.get((m.group(1), m.group(2)))
            return [{"artifacts_with_results": list(srcs)}] if srcs else []
        if "flows(client_id='server'" in vql:
            return []
        m = re.search(r"SELECT \* FROM source\(client_id='([^']+)', flow_id='([^']+)', artifact='([^']+)'", vql)
        if m:
            return [dict(r) for r in self.flows.get((m.group(1), m.group(2)), {}).get(m.group(3), [])]
        if "FROM flows(client_id='" in vql:          # the old per-client probe
            m = re.search(r"flows\(client_id='([^']+)', flow_id='([^']+)'\)", vql)
            return [{"session_id": m.group(2)}] if (m.group(1), m.group(2)) in self.flows else []
        if "FROM clients()" in vql:                  # the old full enumeration
            return [{"client_id": c, "hostname": self._host(c)} for c in self.clients]
        raise AssertionError(f"unexpected VQL: {vql}")

    def Query(self, req, timeout=None):
        vql = req["Query"][0]
        self.queries.append(vql)
        rows = self._answer(vql)
        if rows:
            yield types.SimpleNamespace(Response=json.dumps(rows), log="")


class _Harness(unittest.TestCase):
    def setUp(self):
        self.saved = {k: getattr(_base, k) for k in
                      ("api_pb2", "api_pb2_grpc", "setup_velociraptor_connection",
                       "add_log_to_run", "_run_client_ids")}
        self.logs = []
        _base.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=lambda **kw: kw,
                                              VQLRequest=lambda VQL: VQL)
        _base.setup_velociraptor_connection = lambda: types.SimpleNamespace(close=lambda: None)
        _base.add_log_to_run = lambda rid, msg, level="info": self.logs.append((level, msg))
        _base._run_client_ids = lambda rid: []

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(_base, k, v)

    def use(self, velo):
        _base.api_pb2_grpc = types.SimpleNamespace(APIStub=lambda ch: velo)
        self.velo = velo
        return velo


ROWS = {"Windows.EventLogs.RDPAuth": [{"EventID": 4624, "User": "bob"}, {"EventID": 4625, "User": "eve"}],
        "Windows.NTFS.MFT": [{"FileName": "x"}]}


class TestFlowLocation(_Harness):

    def fetch(self, **kw):
        return _base.get_existing_collection_results(
            "run_1", flow_id="F.OWNED", only_artifacts={"windows.eventlogs.rdpauth"}, **kw)

    def test_the_return_shape_is_unchanged(self):
        self.use(FakeVelociraptor(50, {("C.0042", "F.OWNED"): ROWS}, {"C.0042": "WKS-42"}))
        all_results, artifacts, client_info = self.fetch()
        self.assertEqual(all_results, {"Windows.EventLogs.RDPAuth": [
            {"EventID": 4624, "User": "bob", "_client_id": "C.0042", "_hostname": "WKS-42"},
            {"EventID": 4625, "User": "eve", "_client_id": "C.0042", "_hostname": "WKS-42"}]})
        self.assertEqual(artifacts, ["Windows.EventLogs.RDPAuth"])
        self.assertEqual(client_info, {"C.0042": {"client_id": "C.0042", "hostname": "WKS-42",
                                                  "os": "Unknown"}})

    def test_query_count_does_not_grow_with_the_fleet(self):
        for n in (10, 2000):
            with self.subTest(fleet=n):
                velo = self.use(FakeVelociraptor(n, {(f"C.{n - 1:04d}", "F.OWNED"): ROWS}))
                all_results, _a, _ci = self.fetch()
                self.assertIn("Windows.EventLogs.RDPAuth", all_results)
                # locate + list sources + one wanted source
                self.assertLessEqual(len(velo.queries), 3, velo.queries)

    def test_no_log_line_per_client(self):
        self.use(FakeVelociraptor(300, {("C.0299", "F.OWNED"): ROWS}))
        self.fetch()
        self.assertLess(len(self.logs), 10, self.logs)
        self.assertFalse([m for _l, m in self.logs if "Query log for" in m or "Query result for" in m])

    def test_a_correct_hint_is_searched_alone(self):
        velo = self.use(FakeVelociraptor(500, {("C.0007", "F.OWNED"): ROWS}))
        self.fetch(client_ids=["C.0007"])
        self.assertIn("WHERE client_id IN ('C.0007')", velo.queries[0])

    def test_a_wrong_hint_still_finds_the_flow(self):
        velo = self.use(FakeVelociraptor(500, {("C.0400", "F.OWNED"): ROWS}))
        _base._run_client_ids = lambda rid: ["C.0001", "C.0002"]
        all_results, _a, client_info = self.fetch(client_ids=["C.0007"])
        self.assertEqual(list(client_info), ["C.0400"])
        self.assertIn("Windows.EventLogs.RDPAuth", all_results)
        locates = [q for q in velo.queries if "LocCid" in q]
        self.assertEqual(3, len(locates), "hint, run's clients, then everyone")
        self.assertNotIn("WHERE", locates[-1])

    def test_the_runs_own_clients_are_tried_before_the_fleet(self):
        velo = self.use(FakeVelociraptor(500, {("C.0300", "F.OWNED"): ROWS}))
        _base._run_client_ids = lambda rid: ["C.0300"]
        self.fetch()
        locates = [q for q in velo.queries if "LocCid" in q]
        self.assertEqual(1, len(locates))
        self.assertIn("'C.0300'", locates[0])

    def test_a_missing_flow_is_reported_not_fatal(self):
        self.use(FakeVelociraptor(20, {}))
        self.assertEqual(self.fetch(), ({}, [], {}))
        self.assertTrue([m for lvl, m in self.logs if lvl == "warning" and "not found" in m])

    def test_several_flows_each_keep_their_client(self):
        self.use(FakeVelociraptor(100, {("C.0001", "F.A"): ROWS, ("C.0099", "F.B"): ROWS}))
        all_results, _a, client_info = _base.get_existing_collection_results(
            "run_1", flow_id=["F.A", "F.B"], only_artifacts={"windows.eventlogs.rdpauth"})
        self.assertEqual(list(client_info), ["C.0001", "C.0099"])
        self.assertEqual([r["_client_id"] for r in all_results["Windows.EventLogs.RDPAuth"]],
                         ["C.0001", "C.0001", "C.0099", "C.0099"])


if __name__ == "__main__":
    unittest.main()
