"""The release's symbols asset: both packs, in the tree install and upgrade read.

2026-10-06: "pack it out of the volweb and insert it from the outside so we
wont pass the limit". Runs the real builder on two small packs.
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "ci"))
import build_symbols_asset as b  # noqa: E402


class SymbolsAsset(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def zip(self, name, members):
        p = os.path.join(self.d, name)
        with zipfile.ZipFile(p, "w") as z:
            for m in members:
                z.writestr(m, b"t")
        return p

    def test_both_packs_land_where_install_and_upgrade_look(self):
        wz = self.zip("windows.zip", ["windows/ntkrnlmp.pdb/A-1.json.xz"])
        kp = self.zip("intact-windows-kernels.zip", ["windows/ntkrnlmp.pdb/B-1.json.xz",
                                                     "windows/tcpip.pdb/C-1.json.xz", "codeview.json"])
        out = os.path.join(self.d, "out")
        r = subprocess.run([sys.executable, b.__file__, "--tag", "intact-20261101", "--out", out,
                            "--pack", wz, "--pack", kp], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        tar = os.path.join(out, "intact-20261101-volweb_symbols.tar")
        with tarfile.open(tar) as t:
            names = t.getnames()
        self.assertIn("intact-upgrade-intact-20261101/volweb_symbols/windows.zip", names)
        self.assertIn("intact-upgrade-intact-20261101/volweb_symbols/intact-windows-kernels.zip", names)
        self.assertFalse([n for n in names if "manifest" in n])     # not a module asset: no manifests
        with open(tar + ".meta.json") as fh:
            meta = json.load(fh)
        self.assertEqual(meta["asset"], "intact-20261101-volweb_symbols.tar")
        self.assertEqual(meta["tables"], {"windows.zip": 1, "intact-windows-kernels.zip": 2})
        self.assertEqual(set(meta["files"]), {"windows.zip", "intact-windows-kernels.zip"})
        self.assertEqual(meta["sha256"], b._sha256(tar))

    def test_a_zip_without_tables_is_refused(self):
        bad = self.zip("photos.zip", ["cat.jpg"])
        with self.assertRaises(SystemExit):
            b.build("t", [bad], os.path.join(self.d, "out"))


if __name__ == "__main__":
    unittest.main()
