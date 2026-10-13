"""With the Velociraptor API down, the client list must not claim the fleet is online.

The snapshot-file fallback stamped every client "seen now": the whole fleet
showed online and the pickers pre-selected all of it, while nothing could be
sent. It now lists clients as not seen, and an online-only request gets none.
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


class SnapshotFallbackNeverClaimsOnline(unittest.TestCase):
    def setUp(self):
        info = "C.1 DESKTOP-ABC12 windows 10.0.0.5".encode().hex()
        line = json.dumps({"client_id": "C.1", "info": info})
        self._run = vs.subprocess.run
        vs.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=line + "\n")

    def tearDown(self):
        vs.subprocess.run = self._run

    def test_all_clients_listed_as_not_seen(self):
        rows = vs.get_clients_from_snapshot_file(include_offline=True)
        self.assertEqual(["C.1"], [r["client_id"] for r in rows])
        self.assertEqual(0, rows[0]["last_seen_at"])

    def test_online_only_request_gets_none(self):
        self.assertEqual([], vs.get_clients_from_snapshot_file(include_offline=False))



class OnlineFilterUsesSeconds(unittest.TestCase):
    def test_last_seen_microseconds_are_converted(self):
        # clients() reports last_seen_at in MICROseconds; compared raw with now() - 600
        # every enrolled client passed (10 of 10 "online" on the lab box, 1 real).
        src = open(os.path.join(ROOT, "modules/backend/services/velociraptor_service.py")).read()
        self.assertIn("last_seen_at / 1000000 > now() - 600", src)
        self.assertNotIn('"  AND last_seen_at > now() - 600"', src)


if __name__ == "__main__":
    unittest.main()
