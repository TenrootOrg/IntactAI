"""Symbol tables by hand, for air-gapped boxes: find which one an image needs,
upload it, and it lands where VolWeb's Volatility looks — named by its own
metadata, never by the uploaded file name.
"""
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import symbols  # noqa: E402

# GUID {3844DBB9-2017-4967-BE7A-A4A2C20430FA}, age 2 — as it sits in an RSDS record
_GUID_RAW = struct.pack("<IHH", 0x3844DBB9, 0x2017, 0x4967) + bytes.fromhex("BE7AA4A2C20430FA")


def _rsds(name, age=2, raw=_GUID_RAW):
    return b"RSDS" + raw + struct.pack("<I", age) + name + b"\x00"


class Required(unittest.TestCase):
    def setUp(self):
        symbols._FOUND_CACHE.clear()

    def test_the_image_says_which_kernel_table_it_needs(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(os.urandom(4096) + _rsds(b"ntkrnlmp.pdb") + os.urandom(4096)
                     + _rsds(b"tcpip.pdb", age=1) + b"RSDS" + os.urandom(40) + _rsds(b"other.pdb"))
        self.addCleanup(os.unlink, fh.name)
        with mock.patch.object(symbols, "library_ids", return_value=["tcpip.pdb/3844DBB920174967BE7AA4A2C20430FA-1"]):
            req = symbols.required(fh.name)
        k = req[0]
        self.assertEqual((k["pdb"], k["guid"], k["age"], k["have"]),
                         ("ntkrnlmp.pdb", "3844DBB920174967BE7AA4A2C20430FA", 2, False))
        self.assertEqual(k["file"], "windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz")
        # Microsoft's server: GUID then age in HEX, no separator
        self.assertEqual(k["url"], "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/"
                                   "3844DBB920174967BE7AA4A2C20430FA2/ntkrnlmp.pdb")
        self.assertEqual([(r["pdb"], r["have"]) for r in req], [("ntkrnlmp.pdb", False), ("tcpip.pdb", True)])

    def test_other_kernel_variants_are_not_asked_for_once_one_is_present(self):
        # DESKTOP-3LRFS8Q: ntkrnlmp present (9 plugins ran), two ntoskrnl copies
        # in memory were shown as "missing — needed for any plugin output"
        other = struct.pack("<IHH", 0x6F84D35E, 0x575B, 0x43B9) + bytes.fromhex("BFD71AFAB89033C3")
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(_rsds(b"ntkrnlmp.pdb") + _rsds(b"ntoskrnl.pdb", 1, other) + _rsds(b"tcpip.pdb", 1))
        self.addCleanup(os.unlink, fh.name)
        with mock.patch.object(symbols, "library_ids", return_value=["ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2"]):
            req = symbols.required(fh.name)
        self.assertEqual([(r["pdb"], r["have"]) for r in req], [("ntkrnlmp.pdb", True), ("tcpip.pdb", False)])
        with mock.patch.object(symbols, "library_ids", return_value=[]):
            req = symbols.required(fh.name)
        self.assertEqual([r["pdb"] for r in req][:2], ["ntkrnlmp.pdb", "ntoskrnl.pdb"])   # ntkrnlmp first
        self.assertTrue(all(r.get("alternative") for r in req if r["pdb"] != "tcpip.pdb"))

    def test_it_stops_reading_once_it_has_what_it_needs_and_remembers(self):
        # a Check read all 5 GB (20–30 s) and the button looked stuck
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(_rsds(b"ntkrnlmp.pdb") + _rsds(b"tcpip.pdb", 1) + b"\x00" * 64 + _rsds(b"ntoskrnl.pdb", 1))
        self.addCleanup(os.unlink, fh.name)
        symbols._FOUND_CACHE.clear()
        recs = symbols._records(fh.name)
        self.assertEqual(sorted(b for b, _g, _a in recs), ["ntkrnlmp.pdb", "tcpip.pdb"])   # stopped early
        with mock.patch.object(symbols.mmap, "mmap", side_effect=AssertionError("read again")):
            self.assertIs(symbols._records(fh.name), recs)                              # remembered

    def test_age_above_nine_is_hex_in_the_link_and_decimal_in_the_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(_rsds(b"ntkrnlmp.pdb", age=12))
        self.addCleanup(os.unlink, fh.name)
        with mock.patch.object(symbols, "library_ids", return_value=[]):
            k = symbols.required(fh.name)[0]
        self.assertTrue(k["url"].endswith("30FAC/ntkrnlmp.pdb"))
        self.assertTrue(k["file"].endswith("-12.json.xz"))


class Place(unittest.TestCase):
    """The script that runs inside VolWeb's worker, run here on real ISF files."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.lib = os.path.join(self.d, "symbols")

    def run_place(self, path, kind):
        r = subprocess.run([sys.executable, "-c", symbols._PLACE, path, kind, self.lib],
                           capture_output=True, text=True, check=True)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def isf(self, name, meta):
        p = os.path.join(self.d, name)
        doc = {"metadata": {"windows": {"pdb": meta}}, "symbols": {}}
        if name.endswith(".xz"):
            with lzma.open(p, "wt") as fh:
                json.dump(doc, fh)
        else:
            with open(p, "w") as fh:
                json.dump(doc, fh)
        return p

    def test_named_by_its_own_metadata_not_the_upload_name(self):
        p = self.isf("whatever.json.xz", {"GUID": "3844dbb920174967be7aa4a2c20430fa", "age": 2,
                                          "database": "NtKrnlMp.pdb"})
        res = self.run_place(p, "xz")
        self.assertEqual(res["file"], "windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz")
        self.assertTrue(os.path.isfile(os.path.join(self.lib, res["file"])))
        self.assertFalse(res["already_had"])

    def test_a_plain_json_is_compressed_and_a_second_copy_is_not_added(self):
        meta = {"GUID": "A1C414A488BC6DE9308B5D3D7579D109", "age": 1, "database": "tcpip.pdb"}
        res = self.run_place(self.isf("t.json", meta), "json")
        with lzma.open(os.path.join(self.lib, res["file"])) as fh:
            self.assertEqual(json.load(fh)["metadata"]["windows"]["pdb"]["database"], "tcpip.pdb")
        again = self.run_place(self.isf("t2.json", meta), "json")
        self.assertTrue(again["already_had"])

    def test_something_that_is_not_a_symbol_table_is_refused(self):
        p = os.path.join(self.d, "bad.json")
        with open(p, "w") as fh:
            fh.write('{"hello": 1}')
        self.assertIn("not a Windows symbol table", self.run_place(p, "json")["error"])


class Add(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def upload(self, name):
        p = os.path.join(self.d, "up.bin")
        with open(p, "wb") as fh:
            fh.write(b"x")
        return p

    def test_only_symbol_files_are_accepted(self):
        self.assertIn("error", symbols.add(self.upload("x"), "notes.txt", dumps_dir=self.d))

    def test_the_staged_copy_is_always_removed(self):
        out = subprocess.CompletedProcess([], 0, stdout='{"file": "windows/ntkrnlmp.pdb/X-1.json.xz"}\n', stderr="")
        with mock.patch.object(symbols, "_exec", return_value=out) as ex:
            res = symbols.add(self.upload("k"), "ntkrnlmp.pdb", dumps_dir=self.d)
        self.assertEqual(res["file"], "windows/ntkrnlmp.pdb/X-1.json.xz")
        self.assertIn(" pdb ", ex.call_args.args[0])                     # converted, not copied
        self.assertEqual(os.listdir(os.path.join(self.d, symbols.INCOMING)), [])

    def test_a_pack_goes_in_whole(self):
        ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(symbols, "_exec", return_value=ok) as ex:
            res = symbols.add(self.upload("z"), "windows.zip", dumps_dir=self.d)
        self.assertTrue(res["pack"])
        self.assertIn("cp ", ex.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
