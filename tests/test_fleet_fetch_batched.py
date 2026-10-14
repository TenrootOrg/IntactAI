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

    def __init__(self, n_clients, flows, hostnames=None, hunts=None, batched="works"):
        self.clients = [f"C.{i:04d}" for i in range(n_clients)]
        self.flows = flows
        self.hostnames = hostnames or {}
        self.hunts = hunts or {}         # hunt_id -> [client_id, ...] (flow F.<id>.H each)
        self.batched = batched           # "works" | "empty" (unresolved vars) | "raises"
        #                                  | "cut" (a source stream ends partway, mid-flow)
        self.queries = []

    def _hunt_flows(self, vql):
        m = re.search(r"hunt_flows\(hunt_id='([^']+)'\)( WHERE ClientId IN \(([^)]*)\))?", vql)
        hid = m.group(1)
        cids = self.hunts.get(hid, [])
        if m.group(2):
            keep = set(re.findall(r"'([^']+)'", m.group(3)))
            cids = [c for c in cids if c in keep]
        return [(c, "F." + hid[2:] + ".H") for c in cids]

    def _enumerate(self, cid, fid):
        rows = [{"Type": "Upload", "Data": {"VFSPath": f"/clients/{cid}/collections/{fid}/uploads/x"}}]
        for src in self.flows.get((cid, fid), {}):
            art, _, sub = src.partition("/")
            tail = f"{fid}/{sub}.json" if sub else f"{fid}.json"
            rows.append({"Type": "Result", "Data": {"VFSPath": f"/clients/{cid}/artifacts/{art}/{tail}"}})
        return rows

    def _foreach(self, vql):
        if self.batched == "raises":
            raise RuntimeError("Symbol IntactCid not found")
        if self.batched == "empty":
            return []
        out = []
        for cid, fid in self._hunt_flows(vql):
            if "FROM enumerate_flow(" in vql:
                out += [dict(r, IntactCid=cid, IntactFid=fid)
                        for r in self._enumerate(cid, fid) if r["Type"] == "Result"]
            else:
                art = re.search(r"artifact='([^']+)'", vql).group(1)
                out += [dict(r, IntactCid=cid, IntactFid=fid)
                        for r in self.flows.get((cid, fid), {}).get(art, [])]
        if self.batched == "cut" and "FROM source(" in vql:
            return out[:len(out) // 2 + 1]       # odd cut: the last flow read is half there
        return out

    def _host(self, cid):
        return self.hostnames.get(cid, cid.lower())

    def _answer(self, vql):
        if "row={SELECT ClientId AS IntactCid" in vql:
            return self._foreach(vql)
        if vql.startswith("SELECT ClientId, FlowId FROM hunt_flows("):
            return [{"ClientId": c, "FlowId": f} for c, f in self._hunt_flows(vql)]
        m = re.search(r"enumerate_flow\(client_id='([^']+)', flow_id='([^']+)'\)", vql)
        if m:
            return self._enumerate(m.group(1), m.group(2))
        if "os_info.hostname as Hostname" in vql:
            keep = re.findall(r"'([^']+)'", vql)
            return [{"client_id": c, "Hostname": self._host(c)} for c in self.clients if c in keep]
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


def _hunt_fleet(n=40):
    """n clients in hunt H.HUNT; varied sources so ORDER is exercised: a source
    present but empty on one client, a sub-source, an unmapped artifact, and
    clients with nothing at all."""
    flows, cids = {}, [f"C.{i:04d}" for i in range(n)]
    for i, cid in enumerate(cids):
        if i % 7 == 3:
            continue                              # in the hunt, no results yet
        srcs = {}
        if i % 2:
            srcs["Windows.Forensics.SAM/Parsed"] = [{"User": f"u{i}"}]
        srcs["Windows.EventLogs.RDPAuth"] = [] if i == 0 else [{"EventID": 4624, "n": i},
                                                               {"EventID": 4625, "n": i}]
        srcs["Windows.NTFS.MFT"] = [{"FileName": f"f{i}"}]
        flows[(cid, "F.HUNT.H")] = srcs
    return flows, {"H.HUNT": cids}


def _hunt_velo(n, **kw):
    flows, hunts = _hunt_fleet(n)
    return FakeVelociraptor(n, flows, hunts=hunts, **kw)


class TestHuntFetch(_Harness):
    """F9: a hunt was read per client per source (enumerate_flow + source() per
    source per flow, ~9-16k sequential calls for 1,000 hosts) on every fuse."""
    ONLY = {"windows.eventlogs.rdpauth", "windows.forensics.sam"}

    def fetch(self, velo, **kw):
        self.use(velo)
        return _base.get_existing_collection_results("run_1", hunt_id="H.HUNT", **kw)

    def test_the_return_shape_is_unchanged(self):
        flows, hunts = _hunt_fleet(4)
        all_results, artifacts, client_info = self.fetch(
            FakeVelociraptor(4, flows, {"C.0001": "WKS-1"}, hunts), only_artifacts=self.ONLY)
        # C.0000's RDPAuth is present but empty, so SAM (first seen on C.0001)
        # comes first only if the per-flow order is kept.
        self.assertEqual(artifacts, ["Windows.Forensics.SAM/Parsed", "Windows.EventLogs.RDPAuth"])
        self.assertEqual(list(all_results), artifacts)
        self.assertEqual(all_results["Windows.Forensics.SAM/Parsed"],
                         [{"User": "u1", "_client_id": "C.0001", "_hostname": "WKS-1"}])
        self.assertEqual(all_results["Windows.EventLogs.RDPAuth"], [
            {"EventID": 4624, "n": 1, "_client_id": "C.0001", "_hostname": "WKS-1"},
            {"EventID": 4625, "n": 1, "_client_id": "C.0001", "_hostname": "WKS-1"},
            {"EventID": 4624, "n": 2, "_client_id": "C.0002", "_hostname": "c.0002"},
            {"EventID": 4625, "n": 2, "_client_id": "C.0002", "_hostname": "c.0002"}])
        # Every client in the hunt is listed, including the one with no results.
        self.assertEqual(client_info, {
            c: {"client_id": c, "hostname": h, "os": "Unknown"}
            for c, h in (("C.0000", "c.0000"), ("C.0001", "WKS-1"),
                         ("C.0002", "c.0002"), ("C.0003", "c.0003"))})

    def test_query_count_is_per_source_not_per_client(self):
        for n in (8, 600):
            with self.subTest(clients=n):
                velo = _hunt_velo(n)
                all_results, _a, _ci = self.fetch(velo, only_artifacts=self.ONLY)
                self.assertEqual(2, len(all_results))
                # hunt_flows + hostnames + source listing + one per wanted source,
                # + one re-read of C.0000, whose RDPAuth is listed but has no rows
                self.assertEqual(6, len(velo.queries), velo.queries)

    def test_one_log_line_per_artifact_not_per_client(self):
        self.fetch(_hunt_velo(300), only_artifacts=self.ONLY)
        self.assertLess(len(self.logs), 10, self.logs)

    def test_the_added_owner_columns_never_reach_a_row(self):
        all_results, _a, _ci = self.fetch(_hunt_velo(20))
        self.assertEqual(3, len(all_results))
        for rows in all_results.values():
            for r in rows:
                self.assertFalse({"IntactCid", "IntactFid"} & set(r), r)

    def test_client_scope_is_kept(self):
        velo = _hunt_velo(20)
        _r, _a, client_info = self.fetch(velo, client_ids=["C.0001", "C.0002"],
                                         only_artifacts=self.ONLY)
        self.assertEqual(list(client_info), ["C.0001", "C.0002"])
        self.assertTrue(all("WHERE ClientId IN ('C.0001', 'C.0002')" in q
                            for q in velo.queries if "hunt_flows(" in q))

    def test_a_broken_batched_query_falls_back_to_the_same_answer(self):
        good = self.fetch(_hunt_velo(15), only_artifacts=self.ONLY)
        for mode in ("empty", "raises"):
            with self.subTest(batched=mode):
                errors = []
                got = self.fetch(_hunt_velo(15, batched=mode),
                                 only_artifacts=self.ONLY, errors=errors)
                self.assertEqual(json.dumps(good), json.dumps(got))
                self.assertEqual([], errors)

    def test_a_stream_that_ends_early_is_completed_per_client(self):
        """A hunt-wide stream that the server ends early closes normally. The
        flows after the cut, and the half-read flow at it, were accepted as
        "no rows" and the report said complete. They are re-read per client."""
        good = self.fetch(_hunt_velo(15), only_artifacts=self.ONLY)
        errors, velo = [], _hunt_velo(15, batched="cut")
        got = self.fetch(velo, only_artifacts=self.ONLY, errors=errors)
        self.assertEqual(json.dumps(good), json.dumps(got))
        self.assertEqual([], errors)
        self.assertTrue(any(l == "warning" and "came back without" in m for l, m in self.logs), self.logs)
        per_client = [q for q in velo.queries if q.startswith("SELECT * FROM source(client_id='")]
        self.assertTrue(0 < len(per_client) < 15, "only the missing clients are re-read")

    def test_the_server_side_limit_is_set(self):
        velo = self.use(_hunt_velo(3))
        seen = []
        real = velo.Query
        velo.Query = lambda req, timeout=None: (seen.append(req), real(req, timeout))[1]
        _base.get_existing_collection_results("run_1", hunt_id="H.HUNT", only_artifacts=self.ONLY)
        batched = [r for r in seen if "IntactCid" in r["Query"][0]]
        self.assertTrue(batched)
        self.assertTrue(all(r.get("timeout", 0) > 0 for r in batched), batched)

    def test_a_hunt_nobody_has_answered_is_empty_not_a_fallback_storm(self):
        cids = [f"C.{i:04d}" for i in range(50)]
        velo = FakeVelociraptor(50, {}, hunts={"H.HUNT": cids})
        self.assertEqual(({}, [], {c: {"client_id": c, "hostname": c.lower(), "os": "Unknown"}
                                   for c in cids}), self.fetch(velo))
        self.assertLessEqual(len(velo.queries), 4, velo.queries)


if __name__ == "__main__":
    unittest.main()
