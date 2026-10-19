"""The install's offline-collector binary check knows the Linux build is musl now.

Since 0.77.3 the Linux collector binary is the static musl build. The check looked
only for the plain name and warned "1 platform(s) missing" on every fresh install,
while the collector had its binary. The legacy pin's musl build in the same folder
must not count: it is not what the collector runs.
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.tools_download_service import ensure_offline_collector_binaries  # noqa: E402


def _files(d, names):
    for n in names:
        with open(os.path.join(d, n), "wb") as f:
            f.truncate(2 * 1024 * 1024)            # sparse, passes the 1 MB floor


class LinuxCollectorBinary(unittest.TestCase):
    def check(self, names):
        with tempfile.TemporaryDirectory() as d:
            _files(d, names)
            return ensure_offline_collector_binaries(d, logger=lambda *a, **k: None)["missing"]

    def test_fresh_install_layout_is_complete(self):
        self.assertEqual([], self.check(["velociraptor-v0.77.3-windows-amd64.exe",
                                         "velociraptor-v0.77.3-linux-amd64-musl",
                                         "velociraptor-v0.77.3-darwin-amd64",
                                         "velociraptor-v0.7.1-linux-amd64-musl"]))

    def test_only_the_legacy_musl_build_is_still_missing(self):
        missing = self.check(["velociraptor-v0.77.3-windows-amd64.exe",
                              "velociraptor-v0.77.3-darwin-amd64",
                              "velociraptor-v0.7.1-linux-amd64-musl"])
        self.assertEqual(1, len(missing))
        self.assertIn("linux", missing[0])

    def test_older_box_with_the_plain_build(self):
        self.assertEqual([], self.check(["velociraptor-v0.77.2-windows-amd64.exe",
                                         "velociraptor-v0.77.2-linux-amd64",
                                         "velociraptor-v0.77.2-darwin-amd64"]))


if __name__ == "__main__":
    unittest.main()
