"""The volweb asset carries the CI-built kernel pack beside windows.zip.

Runs the real _bundle_kernel_pack from scripts/ci/packager/package.py -- it only
ever executes inside a release build on GitHub, where a bug would surface as a
published release without the tables an air-gapped box needs (2026-10-06).
"""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "scripts", "ci"), os.path.join(ROOT, "modules", "backend"),
                os.path.dirname(os.path.abspath(__file__))]
import _optional_deps  # noqa: F401,E402
from packager import package  # noqa: E402

WINDOWS_ZIP = {"file": "volweb_symbols/windows.zip", "sha256": "231d6973", "size": 839727133,
               "tables": 3014, "source_url": "u"}


class Bundle(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.sym_dir = os.path.join(self.d, "volweb_symbols")
        self.logs = []
        self.manifest = {"contents": {"volweb_symbols": dict(WINDOWS_ZIP)}}

    def pack(self, names):
        p = os.path.join(self.d, "built.zip")
        with zipfile.ZipFile(p, "w") as z:
            for n in names:
                z.writestr(n, b"t")
        return p

    def run_it(self, kpack, in_ci):
        package._bundle_kernel_pack(self.sym_dir, self.manifest, lambda m, lvl="info": self.logs.append((lvl, m)),
                                    kpack=kpack, in_ci=in_ci)

    def test_the_pack_rides_beside_windows_zip_with_both_named_in_the_manifest(self):
        src = self.pack(["windows/ntkrnlmp.pdb/A-1.json.xz", "windows/tcpip.pdb/B-1.json.xz", "codeview.json"])
        self.run_it(src, in_ci=True)
        dst = os.path.join(self.sym_dir, "intact-windows-kernels.zip")
        self.assertTrue(os.path.isfile(dst))
        files = self.manifest["contents"]["volweb_symbols_files"]
        with open(dst, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(files["intact-windows-kernels.zip"], {"sha256": sha, "size": os.path.getsize(dst),
                                                               "tables": 2})
        self.assertEqual(files["windows.zip"]["sha256"], "231d6973")

    def test_in_ci_a_release_without_the_pack_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_it("", in_ci=True)
        with self.assertRaises(RuntimeError):                     # a zip with no tables is not a pack
            self.run_it(self.pack(["README.txt"]), in_ci=True)

    def test_a_boxs_own_prepare_upgrade_only_warns(self):
        self.run_it("", in_ci=False)
        self.assertTrue(any(lvl == "warning" and "not bundled" in m for lvl, m in self.logs))
        self.assertNotIn("intact-windows-kernels.zip", self.manifest["contents"]["volweb_symbols_files"])


if __name__ == "__main__":
    unittest.main()
