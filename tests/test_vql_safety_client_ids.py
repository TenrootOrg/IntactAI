"""Client IDs: what Velociraptor really generates is accepted, injection shapes are not.

Velociraptor 0.77.3 names a client imported from an offline collection after the
collection's HostID (the machine GUID, '-' turned into '_'). The old check allowed
only hex, rejected that ID, and the upload fused nothing ("Rejecting invalid
client_ids: ['C.c14d3891_8930_4a05_8cfa_3baf34a79201']").
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.vql_safety import is_valid_client_id  # noqa: E402


class ClientIds(unittest.TestCase):
    def test_enrolled_client(self):
        self.assertTrue(is_valid_client_id("C.0c578d701ef920b9"))

    def test_imported_offline_collection(self):
        self.assertTrue(is_valid_client_id("C.c14d3891_8930_4a05_8cfa_3baf34a79201"))

    def test_injection_shapes_still_rejected(self):
        for bad in ("C.abc'", "C.abc) OR 1", "C.abc def", "C.abc/../x", "C.abc-def",
                    "C.ABC", "C.", "", None, "F.ABC", "C." + "a" * 41):
            self.assertFalse(is_valid_client_id(bad), bad)


if __name__ == "__main__":
    unittest.main()
