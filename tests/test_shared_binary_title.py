"""A "Shared binary" row names the file.

Found in the audit (jev_test): five rows read "Shared binary seen on 2 hosts",
identical, and could only be told apart by opening each one.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, schema  # noqa: E402


class SharedBinary(unittest.TestCase):
    def test_title_names_file_and_hash(self):
        ents = [schema.Entity(id=f"asset:{h}", type="asset", label=h) for h in ("A", "B")]
        ents.append(schema.Entity(id="ioc:h", type="ioc", label="16f41386" + "0" * 56, anomaly=10,
                                  first_seen="2026-06-01T10:00:00Z",
                                  attrs={"_assets": ["asset:A", "asset:B"], "ioc_kind": "hash",
                                         "source_name": "procdump64.exe"}))
        g = correlate.assemble("c", [(ents, [])], ["r1"])
        titles = [f.title for f in g.findings if f.title.startswith("Shared binary")]
        self.assertEqual(titles, ["Shared binary: procdump64.exe (sha256 16f41386…) seen on 2 hosts"])


if __name__ == "__main__":
    unittest.main()
