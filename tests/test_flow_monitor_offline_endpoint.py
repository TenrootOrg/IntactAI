"""A flow on an endpoint that is not connected says so.

2026-10-05: a memory capture of DESKTOP-2175T02 sat at "State: RUNNING -
Rows: 0" for 13 minutes (90 allowed) on a PC last seen 45 minutes earlier, and
nothing in the log said why. The monitor now asks Velociraptor when the client
last checked in and warns; it never aborts (the endpoint may come back).
"""
import json
import os
import sys
import types
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import kape_service as ks  # noqa: E402

CID, FID = "C.fcd78a013e981808", "F.DB1N9JS9P5OVE"


def run(last_seen_ago_s, finish_after_s=700):
    clock = {"t": 1_000_000.0}
    start = clock["t"]
    logs = []

    class Stub:
        def Query(self, req, timeout=None):
            vql = req["Query"][0]["VQL"]
            if "FROM clients(" in vql:
                row = {"last_seen_at": int((clock["t"] - last_seen_ago_s) * 1e6)}
            else:
                done = clock["t"] - start >= finish_after_s
                row = {"state": "FINISHED" if done else "RUNNING", "total_collected_rows": 1 if done else 0}
            yield types.SimpleNamespace(Response=json.dumps([row]))

    fake_time = types.SimpleNamespace(time=lambda: clock["t"],
                                      sleep=lambda s: clock.__setitem__("t", clock["t"] + s))
    pb = types.SimpleNamespace(VQLRequest=lambda **k: k, VQLCollectorArgs=lambda **k: k)
    with mock.patch.object(ks, "time", fake_time), mock.patch.object(ks, "api_pb2", pb), \
            mock.patch.object(ks, "api_pb2_grpc", types.SimpleNamespace(APIStub=lambda ch: Stub())), \
            mock.patch.object(ks, "setup_velociraptor_connection", lambda: mock.Mock()):
        state = ks.monitor_flow_completion(CID, FID, timeout_seconds=5400,
                                           logger=lambda m, lvl="info": logs.append((lvl, m)))
    return state, [m for lvl, m in logs if lvl == "warning"]


class OfflineEndpoint(unittest.TestCase):
    def test_an_endpoint_gone_for_an_hour_is_named_as_offline(self):
        state, warns = run(last_seen_ago_s=3600)
        self.assertEqual(state, "FINISHED")                    # never aborts: it may come back
        offline = [w for w in warns if "has not checked in" in w]
        self.assertTrue(offline, warns)
        self.assertIn("has not checked in for 60 min", offline[0])
        self.assertIn("starts when it reconnects", offline[0])
        self.assertLessEqual(len(offline), 2)                  # repeated every 10 min, not every poll

    def test_a_connected_endpoint_gets_no_warning(self):
        state, warns = run(last_seen_ago_s=5)
        self.assertEqual(state, "FINISHED")
        self.assertFalse([w for w in warns if "has not checked in" in w])


if __name__ == "__main__":
    unittest.main()
