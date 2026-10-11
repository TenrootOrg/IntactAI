"""Settings → Velociraptor: which clients run the server's version.

The client upgrade (pilot first, never a downgrade) is driven by this
classification, so it must compare versions numerically ("0.9" < "0.77.2"), treat
a client that never reported a version as unknown -- not as behind -- and read
clients()' microsecond timestamps.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.velociraptor_clients import classify, version_key  # noqa: E402

NOW = 1_800_000_000


class Versions(unittest.TestCase):
    def test_numeric_not_text(self):
        self.assertLess(version_key("0.9.0"), version_key("0.77.2"))
        self.assertLess(version_key("0.77.1"), version_key("0.77.2"))
        self.assertEqual(version_key("v0.77.2"), (0, 77, 2))
        self.assertEqual(version_key("0.78.0-rc1"), (0, 78, 0))
        self.assertIsNone(version_key(""))
        self.assertIsNone(version_key(None))

    def test_classify(self):
        rows = [
            {"client_id": "C.1", "hostname": "WS-OLD", "os": "windows", "version": "0.77.1",
             "last_seen_at": (NOW - 30) * 1_000_000},                     # microseconds, online
            {"client_id": "C.2", "hostname": "WS-NOW", "os": "windows", "version": "0.77.2",
             "last_seen_at": NOW - 7200},                                 # seconds, offline
            {"client_id": "C.3", "hostname": "ALDC02", "os": "", "version": "", "last_seen_at": 0},
            {"client_id": "C.4", "hostname": "LAB", "os": "linux", "version": "0.78.0",
             "last_seen_at": NOW - 10},
        ]
        out = classify(rows, "0.77.2", now=NOW)
        by = {c["client_id"]: c for c in out["clients"]}
        self.assertEqual([by[k]["state"] for k in ("C.1", "C.2", "C.3", "C.4")],
                         ["behind", "current", "unknown", "ahead"])
        self.assertTrue(by["C.1"]["online"])
        self.assertFalse(by["C.2"]["online"])
        self.assertIsNone(by["C.3"]["last_seen"])
        self.assertEqual(out["counts"], {"current": 1, "behind": 1, "ahead": 1, "unknown": 1, "online": 2})
        self.assertEqual(out["clients"][0]["client_id"], "C.1")          # behind first
        self.assertEqual(out["server_version"], "0.77.2")

    def test_no_server_version_means_nothing_is_called_behind(self):
        out = classify([{"client_id": "C.1", "version": "0.77.1"}], "", now=NOW)
        self.assertEqual(out["clients"][0]["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
