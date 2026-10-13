"""An imported offline collection must land on ITS OWN Velociraptor client.

The importer read the host from the file name with Collection-([^-]+)-, which cut
'Collection-DESKTOP-2175T02.localdomain-2026-10-07T09_52_00Z.zip' to 'DESKTOP';
then 'host:' -- a PREFIX search -- took the first match, so a collection could merge
into another machine's client (host:ALClient0 returned five clients on the lab box).
"""
import io
import json
import os
import sys
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.offline_collector import importer  # noqa: E402


class HostnameFromTheFileName(unittest.TestCase):
    def test_real_collector_names(self):
        f = importer._hostname_from_filename
        self.assertEqual("DESKTOP-2175T02.localdomain",
                         f("Collection-DESKTOP-2175T02.localdomain-2026-10-07T09_52_00Z.zip"))
        self.assertEqual("CITADEL-DC01.C137.local", f("Collection-CITADEL-DC01.C137.local-2026-10-13T10_00_00Z.zip"))
        self.assertEqual("WS1", f("Collection-WS1-2026-10-07T09_52_00Z.zip"))
        self.assertEqual("ALDC02", f("Collection-ALDC02-1791715456.zip"))

    def test_unsafe_or_unknown_names_fall_back(self):
        f = importer._hostname_from_filename
        self.assertEqual("OfflineClient", f("export.zip"))
        self.assertEqual("OfflineClient", f("Collection-x'),evil(-2026-10-07T09_52_00Z.zip"))


class HostnameFromTheCollection(unittest.TestCase):
    def _zip(self, info):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("client_info.json", json.dumps(info))
            z.writestr("collection_context.json", "{}")
        return zipfile.ZipFile(io.BytesIO(buf.getvalue()))

    def test_fqdn_then_hostname_and_unsafe_rejected(self):
        self.assertEqual("NASHUA.dmevals.local",
                         importer._hostname_from_zip(self._zip({"Hostname": "NASHUA", "Fqdn": "NASHUA.dmevals.local"})))
        self.assertEqual("NASHUA", importer._hostname_from_zip(self._zip({"Hostname": "NASHUA"})))
        self.assertIsNone(importer._hostname_from_zip(self._zip({"Hostname": "a'b"})))

    def test_the_lookup_demands_an_exact_name(self):
        src = open(os.path.join(ROOT, "modules/backend/services/offline_collector/importer.py")).read()
        self.assertIn("lowcase(string=os_info.fqdn) = lowcase(string='{hostname}')", src)
        self.assertIn("lowcase(string=os_info.hostname) = lowcase(string='{short}')", src)


if __name__ == "__main__":
    unittest.main()
