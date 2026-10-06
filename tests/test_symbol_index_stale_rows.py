"""A symbol pack replaced under the same name is re-indexed now, not in 3 days.

2026-10-06, the air-gap proof: the kernel pack's tcpip tables were first
converted with the database name "unknown.pdb". The corrected pack replaced it
under the same file name -- and Volatility went on looking the tables up under
the old name, because it re-reads a location it already knows only after
SQLITE_CACHE_PERIOD (3 days). The index build now drops the rows of any zip that
changed after they were indexed, before Volatility's own update().

Runs the REAL snippet (services/memory/symbols.py:_PREWARM, the same text as
lib/modules/volweb.sh) against a stand-in volatility3 package and a real SQLite
index.
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")]
import _optional_deps  # noqa: F401,E402
from services.memory import symbols  # noqa: E402

STUB = {
    "volatility3/__init__.py": "",
    "volatility3/symbols/__init__.py": "",
    "volatility3/framework/__init__.py": "",
    "volatility3/framework/constants.py":
        "import os\nCACHE_PATH = os.environ['STUB_CACHE']\nIDENTIFIERS_FILENAME = 'identifier.cache'\n",
    "volatility3/framework/automagic/__init__.py": "",
    "volatility3/framework/automagic/symbol_cache.py":
        "import os\nclass SqliteCache:\n    def __init__(self, path): self.path = path\n"
        "    def update(self): open(self.path + '.updated', 'w').close()\n",
}


class StaleRows(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        for rel, text in STUB.items():
            os.makedirs(os.path.dirname(os.path.join(self.d, "stub", rel)), exist_ok=True)
            with open(os.path.join(self.d, "stub", rel), "w") as fh:
                fh.write(text)
        self.lib = os.path.join(self.d, "web", "media", "symbols")
        os.makedirs(self.lib)
        for z in ("intact-windows-kernels.zip", "windows.zip"):
            open(os.path.join(self.lib, z), "w").close()
        old = time.time() - 86400                                  # windows.zip untouched for a day
        os.utime(os.path.join(self.lib, "windows.zip"), (old, old))
        self.cache = os.path.join(self.d, "cache")
        os.makedirs(self.cache)
        con = sqlite3.connect(os.path.join(self.cache, "identifier.cache"))
        con.execute("CREATE TABLE cache (location TEXT, cached TEXT)")
        kp = "jar:file:" + os.path.join(self.lib, "intact-windows-kernels.zip") + "!windows/tcpip.pdb/X-1.json.xz"
        wz = "jar:file:" + os.path.join(self.lib, "windows.zip") + "!windows/ntkrnlmp.pdb/Y-1.json.xz"
        con.executemany("INSERT INTO cache VALUES (?, ?)", [
            (kp, "2000-01-01 00:00:00"),                           # indexed before the pack changed
            (wz, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())),   # indexed after windows.zip changed
            ("file:" + os.path.join(self.lib, "windows/x.json.xz"), "2000-01-01 00:00:00")])  # loose table
        con.commit()
        con.close()
        r = subprocess.run([sys.executable, "-c", symbols._PREWARM], cwd=os.path.join(self.d, "web"),
                           env=dict(os.environ, PYTHONPATH=os.path.join(self.d, "stub"), STUB_CACHE=self.cache),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        con = sqlite3.connect(os.path.join(self.cache, "identifier.cache"))
        self.left = [row[0] for row in con.execute("SELECT location FROM cache")]
        con.close()

    def test_a_pack_changed_after_indexing_is_read_again(self):
        self.assertFalse([x for x in self.left if "intact-windows-kernels.zip" in x])

    def test_a_pack_indexed_after_its_last_change_is_left_alone(self):
        self.assertTrue([x for x in self.left if "windows.zip" in x])

    def test_loose_tables_are_volatilitys_own_business(self):
        self.assertTrue([x for x in self.left if x.startswith("file:")])

    def test_then_volatility_updates(self):
        self.assertTrue(os.path.exists(os.path.join(self.cache, "identifier.cache.updated")))


if __name__ == "__main__":
    unittest.main()
