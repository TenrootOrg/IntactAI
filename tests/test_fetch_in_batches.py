"""Large artifact results are fetched in small gRPC parts, never as one message.

VQLCollectorArgs.max_row is the rows per RESPONSE PART. It was 200,000, so an
imported 144,890-row Hayabusa collection (~640 MB) came as one message, hit the
channel's 100 MB limit (RESOURCE_EXHAUSTED) and the case silently got none of it.
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
from services.agentic.collectors import _base  # noqa: E402


class _Stub:
    def __init__(self, parts=None, fail=None):
        self.parts, self.fail, self.requests = parts or [], fail, []

    def Query(self, req, timeout=None):
        self.requests.append(req)
        if self.fail:
            raise self.fail
        for p in self.parts:
            yield types.SimpleNamespace(Response=json.dumps(p), log="")


class FetchInBatches(unittest.TestCase):
    def setUp(self):
        self._pb = _base.api_pb2
        _base.api_pb2 = types.SimpleNamespace(VQLCollectorArgs=lambda **kw: kw, VQLRequest=lambda VQL: VQL)

    def tearDown(self):
        _base.api_pb2 = self._pb

    def test_parts_are_small_and_all_collected(self):
        stub = _Stub(parts=[[{"n": i} for i in range(1000)], [{"n": i} for i in range(1000)], [{"n": 1}]])
        rows = _base.query_artifact_results(stub, "C.1", "F.1", "Windows.Hayabusa.Rules")
        self.assertEqual(2001, len(rows))
        self.assertLessEqual(stub.requests[0]["max_row"], 5000)

    def test_a_failed_fetch_is_logged(self):
        with self.assertLogs(_base.logger, level="WARNING") as cm:
            rows = _base.query_artifact_results(_Stub(fail=RuntimeError("RESOURCE_EXHAUSTED")),
                                                "C.1", "F.1", "Windows.Hayabusa.Rules")
        self.assertEqual([], rows)
        self.assertIn("Windows.Hayabusa.Rules", cm.output[0])


class NoFetchAsksForHugeParts(unittest.TestCase):
    """The import used a SECOND loop (max_row=50000 -> a 393 MB message): every
    VQLCollectorArgs in the collector module must ask for small parts."""
    def test_every_max_row_is_small(self):
        import re
        src = open(os.path.join(ROOT, "modules/backend/services/agentic/collectors/_base.py")).read()
        for m in re.finditer(r"max_row=([A-Za-z_0-9]+)", src):
            v = m.group(1)
            n = _base.VELO_FETCH_BATCH_ROWS if v == "VELO_FETCH_BATCH_ROWS" else int(v)
            self.assertLessEqual(n, 5000, f"max_row={v} at offset {m.start()}")


if __name__ == "__main__":
    unittest.main()
