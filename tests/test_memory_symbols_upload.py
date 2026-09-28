"""Symbol tables by hand, for air-gapped boxes: an uploaded table lands where
VolWeb's Volatility looks — named by its own metadata, never by the file name.
"""
import json
import lzma
import os
import shutil
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
