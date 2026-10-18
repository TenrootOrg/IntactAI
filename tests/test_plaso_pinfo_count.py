"""run_pinfo's event count, on the real pinfo output of the Plaso versions we
ship. pinfo ends its per-parser section with "Total : N", which was summed with
the rows (19 events reported as 38); Plaso 20260720 adds a "per data type"
section before it. Executed against the real run_pinfo with a fake container."""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import plaso_service as P  # noqa: E402

PINFO_20260512 = """************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 9
             winevtx : 10
               Total : 19
--------------------------------------------------------------------------------

No events labels stored.
"""
PINFO_20260720 = """************************ Events generated per data type ************************
     Data type name : Number of events
--------------------------------------------------------------------------------
            fs:stat : 9
windows:evtx:record : 12
              Total : 21
--------------------------------------------------------------------------------

************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 9
             winevtx : 12
               Total : 21
--------------------------------------------------------------------------------

No events labels stored.
"""
NO_TOTAL = """************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 9
             winevtx : 10
--------------------------------------------------------------------------------

"""


class FakeProc:
    def __init__(self, text):
        self.stdout = iter(text.splitlines(keepends=True))
        self.returncode = 0

    def poll(self):
        return 0                                   # finished: everything comes from the drain


class Count(unittest.TestCase):
    def _count(self, text):
        with mock.patch.object(P.subprocess, "Popen", lambda *a, **k: FakeProc(text)), \
                mock.patch.object(P, "get_plaso_image", lambda: "log2timeline/plaso:test"), \
                mock.patch.object(P.os.path, "exists", lambda p: True):
            return P.run_pinfo("/x/f.plaso", logger=lambda *a, **k: None)

    def test_plaso_20260512(self):
        r = self._count(PINFO_20260512)
        self.assertEqual((19, True), (r["event_count"], r["count_reliable"]))

    def test_plaso_20260720(self):
        r = self._count(PINFO_20260720)
        self.assertEqual((21, True), (r["event_count"], r["count_reliable"]))

    def test_rows_still_sum_when_there_is_no_total(self):
        self.assertEqual(19, self._count(NO_TOTAL)["event_count"])


if __name__ == "__main__":
    unittest.main()
