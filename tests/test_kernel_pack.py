"""The CI kernel pack: symbol tables for every supported Windows build, made the
way VolWeb makes one, so an air-gapped box can analyse a current Windows image.

2026-10-05: DESKTOP-2175T02 (Windows 11 IoT Enterprise LTSC 24H2) runs kernel
10.0.26100.1742 and needs ntkrnlmp.pdb/953A8DE880B0818C32DA2DEC1D79C2D9-1, which
Volatility's 2019 windows.zip does not have. Offline here: Winbindex data, the
symbol server and pdbconv are all faked; the real network path was checked by
hand (53 Windows 11 24H2 kernels resolved, the table above rebuilt identical to
the one VolWeb downloaded itself).
"""
import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "ci"))
import build_kernel_pack as k  # noqa: E402

GUID = "953A8DE880B0818C32DA2DEC1D79C2D9"


def winbindex(*rows):
    """{sha: {fileInfo, windowsVersions}} from (machine, version keys, release date)."""
    out = {}
    for i, (machine, versions, released) in enumerate(rows):
        out[f"sha{i}"] = {"fileInfo": {"machineType": machine, "timestamp": 1000 + i, "virtualSize": 0x1000,
                                       "version": f"10.0.{i}"},
                          "windowsVersions": {v: {"KB1": {"updateInfo": {"releaseDate": released}}}
                                              for v in versions}}
    out["noinfo"] = {"windowsVersions": {}}                    # Winbindex has one of these: tolerate it
    return out


def pe_with_codeview(guid_hex: str, age: int, pdb: str) -> bytes:
    """A minimal PE32+ image whose debug directory holds one RSDS record."""
    b = bytearray(0x600)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)                      # e_lfanew
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", b, 0x86, 1)                         # one section
    struct.pack_into("<H", b, 0x94, 240)                       # SizeOfOptionalHeader
    opt = 0x98
    struct.pack_into("<H", b, opt, 0x20B)                      # PE32+
    struct.pack_into("<II", b, opt + 112 + 6 * 8, 0x2000, 28)  # debug dir: RVA 0x2000, 1 entry
    sec = opt + 240
    struct.pack_into("<IIII", b, sec + 8, 0x1000, 0x2000, 0x1000, 0x400)   # vsize, va, rawsize, rawptr
    dbg = 0x400                                                # RVA 0x2000 -> file 0x400
    cv = b"RSDS" + bytes.fromhex(guid_hex[:8])[::-1] + bytes.fromhex(guid_hex[8:12])[::-1] \
        + bytes.fromhex(guid_hex[12:16])[::-1] + bytes.fromhex(guid_hex[16:]) + struct.pack("<I", age) \
        + pdb.encode() + b"\0"
    struct.pack_into("<IIII", b, dbg + 12, 2, len(cv), 0, 0x500)   # type CODEVIEW, size, rva, ptr
    b[0x500:0x500 + len(cv)] = cv
    return bytes(b)


class TheLinksAreComputed(unittest.TestCase):
    """2026-10-06: "the link is generic and it will always work and not
    hardcoded". Every symbol-server link comes from the build being processed;
    the Winbindex list from the file name. Checked against two real builds."""

    def test_a_binary_is_addressed_by_its_own_timestamp_and_size(self):
        # Winbindex's own record for Windows 10 1507 10.0.10240.17914 (KB4338829)
        b = {"file": "ntoskrnl.exe", "timestamp": 1530169124, "virtualSize": 8744960}
        self.assertEqual(k.binary_url(b), "https://msdl.microsoft.com/download/symbols/"
                                          "ntoskrnl.exe/5B348724857000/ntoskrnl.exe")

    def test_a_pdb_is_addressed_by_its_own_guid_and_age(self):
        # the exact URL VolWeb itself downloaded for that PC on 2026-09-28
        self.assertEqual(k.pdb_url("ntkrnlmp.pdb", GUID, 1),
                         "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/"
                         "953A8DE880B0818C32DA2DEC1D79C2D91/ntkrnlmp.pdb")
        self.assertTrue(k.pdb_url("tcpip.pdb", "AB", 26).endswith("/tcpip.pdb/AB1A/tcpip.pdb"))  # age in hex

    def test_the_build_list_is_per_file_never_per_version(self):
        self.assertEqual(k.WINBINDEX.format("tcpip.sys"),
                         "https://winbindex.m417z.com/data/by_filename_compressed/tcpip.sys.json.gz")

    def test_no_link_names_a_build_a_version_or_a_date(self):
        import re
        src = open(k.__file__).read()
        for url in re.findall(r"https://[^\s\"']+", src):
            self.assertNotRegex(url, r"10\.0\.\d|20\d\d-\d\d|[0-9A-F]{32}", url)


class WhichBuilds(unittest.TestCase):
    DATA = winbindex((34404, ["11-24H2"], "2024-09-10"),       # the LTSC base build: in
                     (34404, ["1709"], "2019-04-09"),          # out of support: still in
                     (332, ["11-24H2"], "2025-01-01"),         # x86: out
                     (34404, ["1809", "1607"], "2021-01-12"))  # LTSC/Server lines: in

    def test_every_x64_build_of_every_version_whatever_its_age(self):
        # 2026-10-06: "most organizations maybe dont have the newest windows version
        # but we do need to support the latest" -- out-of-support 1709 included.
        got = k.builds("ntoskrnl.exe", "2000-01-01", self.DATA)
        self.assertEqual(sorted(b["version"] for b in got), ["10.0.0", "10.0.1", "10.0.3"])

    def test_a_windows_version_shipped_tomorrow_needs_no_change(self):
        data = winbindex((34404, ["11-27H1"], "2027-03-01"))
        self.assertEqual([b["windows"] for b in k.builds("ntoskrnl.exe", "2000-01-01", data)], [["11-27H1"]])

    def test_an_explicit_version_list_still_narrows(self):
        got = k.builds("ntoskrnl.exe", "2000-01-01", self.DATA, versions=("11-24H2",))
        self.assertEqual([b["version"] for b in got], ["10.0.0"])

    def test_since_still_narrows_when_asked(self):
        self.assertEqual([b["version"] for b in k.builds("ntoskrnl.exe", "2024-01-01", self.DATA)], ["10.0.0"])


class TheCodeViewRecord(unittest.TestCase):
    def test_guid_age_and_pdb_come_out_of_the_pe(self):
        pe = pe_with_codeview(GUID, 1, "ntkrnlmp.pdb")
        with mock.patch.object(k, "_get", lambda url, rng=None, timeout=0: pe[rng[0]:rng[1] + 1] if rng else pe):
            self.assertEqual(k.codeview({"file": "ntoskrnl.exe", "timestamp": 1, "virtualSize": 2}),
                             ("ntkrnlmp.pdb", GUID, 1))


class TheConversion(unittest.TestCase):
    """2026-10-06, the air-gap proof: tcpip tables converted without -p were
    written as database "unknown.pdb"; Volatility indexed them under that name
    and NetStat could not find a table that was in the pack."""

    def run_convert(self, written_as):
        import json, lzma
        calls = []

        def fake_pdbconv(cmd, **kw):
            calls.append(cmd)
            out = cmd[cmd.index("-o") + 1]
            with lzma.open(out, "wt") as fh:
                json.dump({"metadata": {"windows": {"pdb": {"GUID": GUID, "age": 1, "database": written_as}}}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        cache = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cache, ignore_errors=True)
        with mock.patch.object(k, "_get", lambda *a, **kw: b"pdb"), \
                mock.patch.object(k.subprocess, "run", fake_pdbconv):
            rel = k.convert("tcpip.pdb", GUID, 1, cache)
        return calls, rel

    def test_the_database_name_is_given_to_pdbconv(self):
        calls, rel = self.run_convert("tcpip.pdb")
        self.assertEqual(calls[0][calls[0].index("-p") + 1], "tcpip.pdb")
        self.assertEqual(rel, f"windows/tcpip.pdb/{GUID}-1.json.xz")

    def test_a_table_volatility_could_not_look_up_is_refused(self):
        with self.assertRaises(RuntimeError) as e:
            self.run_convert("unknown.pdb")
        self.assertIn("unknown.pdb", str(e.exception))


class ThePack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.cache, self.out = os.path.join(self.d, "cache"), os.path.join(self.d, "out")
        self.skip = os.path.join(self.d, "windows.zip")
        with zipfile.ZipFile(self.skip, "w") as z:              # Volatility's pack already has OLD
            z.writestr("windows/ntkrnlmp.pdb/OLD-1.json.xz", b"x")
        guids = iter([("ntkrnlmp.pdb", GUID, 1), ("ntkrnlmp.pdb", "OLD", 1)])
        self.converted = []

        def fake_convert(pdb, guid, age, cache):
            rel = f"windows/{pdb}/{guid}-{age}.json.xz"
            os.makedirs(os.path.dirname(os.path.join(cache, rel)), exist_ok=True)
            with open(os.path.join(cache, rel), "wb") as fh:
                fh.write(b"table")
            self.converted.append(rel)
            return rel
        data = {"ntoskrnl.exe": winbindex((34404, ["11-24H2"], "2024-09-10"), (34404, ["1607"], "2017-01-01")),
                "tcpip.sys": {}}
        with mock.patch.object(k, "codeview", lambda b: next(guids)), \
                mock.patch.object(k, "convert", fake_convert):
            self.res = k.build(self.out, self.cache, "2000-01-01", 1, data, skip_zip=self.skip, log=lambda m: None)

    def test_the_pack_holds_the_table_the_windows_11_image_needs(self):
        names = zipfile.ZipFile(self.res["pack"]).namelist()
        self.assertIn(f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz", names)
        self.assertEqual(os.path.basename(self.res["pack"]), "intact-windows-kernels.zip")

    def test_a_table_windows_zip_already_has_is_not_built_or_shipped_again(self):
        self.assertNotIn("windows/ntkrnlmp.pdb/OLD-1.json.xz", self.converted)
        self.assertNotIn("windows/ntkrnlmp.pdb/OLD-1.json.xz", zipfile.ZipFile(self.res["pack"]).namelist())

    def test_the_pack_says_which_windows_each_table_is_for(self):
        import json
        meta = json.loads(zipfile.ZipFile(self.res["pack"]).read("intact-kernel-pack.json"))
        self.assertEqual(meta["tables"][f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz"]["windows"], ["11-24H2"])

    def test_a_warm_cache_asks_the_symbol_server_nothing(self):
        data = {"ntoskrnl.exe": winbindex((34404, ["11-24H2"], "2024-09-10"), (34404, ["1607"], "2017-01-01")),
                "tcpip.sys": {}}

        def no_network(b):
            raise AssertionError("codeview() called for a build already in the cache")
        with mock.patch.object(k, "codeview", no_network), \
                mock.patch.object(k, "convert", lambda pdb, guid, age, cache: f"windows/{pdb}/{guid}-{age}.json.xz"):
            res = k.build(self.out, self.cache, "2000-01-01", 1, data, skip_zip=self.skip, log=lambda m: None)
        self.assertEqual(res["failed"], [])

    def test_nothing_built_is_a_failure_not_an_empty_pack(self):
        with mock.patch.object(k, "builds", lambda *a, **kw: []), self.assertRaises(SystemExit):
            k.build(self.out, self.cache, "2000-01-01", 1, {}, log=lambda m: None)


class SeedingFromThePreviousRelease(unittest.TestCase):
    """A release starts from the previous release's pack: its tables and the PDB
    identities it was built from are reused, so only new builds are converted --
    no schedule, no CI cache (2026-10-06)."""

    def setUp(self):
        import json
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.prev = os.path.join(self.d, "previous.zip")
        with zipfile.ZipFile(self.prev, "w") as z:
            z.writestr(f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz", b"old-release-table")
            z.writestr("codeview.json", json.dumps({"ntoskrnl.exe:1000:4096": ["ntkrnlmp.pdb", GUID, 1]}))
            z.writestr("intact-kernel-pack.json", "{}")
        self.cache = os.path.join(self.d, "cache")
        os.makedirs(self.cache)

    def test_tables_and_identities_come_back(self):
        import json
        self.assertEqual(k.seed(self.cache, self.prev, log=lambda m: None), 1)
        with open(os.path.join(self.cache, f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz"), "rb") as fh:
            self.assertEqual(fh.read(), b"old-release-table")
        with open(os.path.join(self.cache, "codeview.json")) as fh:
            self.assertEqual(json.load(fh)["ntoskrnl.exe:1000:4096"], ["ntkrnlmp.pdb", GUID, 1])

    def test_a_seeded_build_asks_microsoft_nothing_and_converts_nothing(self):
        k.seed(self.cache, self.prev, log=lambda m: None)
        data = {"ntoskrnl.exe": winbindex((34404, ["11-24H2"], "2024-09-10")), "tcpip.sys": {}}

        def boom(*a, **kw):
            raise AssertionError("network or conversion for a build the previous release had")
        with mock.patch.object(k, "codeview", boom), mock.patch.object(k, "_get", boom), \
                mock.patch.object(k.subprocess, "run", boom):
            res = k.build(os.path.join(self.d, "out"), self.cache, "2000-01-01", 1, data, log=lambda m: None)
        self.assertEqual((res["tables"], res["failed"]), (1, []))
        self.assertIn(f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz", zipfile.ZipFile(res["pack"]).namelist())
        self.assertIn("codeview.json", zipfile.ZipFile(res["pack"]).namelist())   # handed to the next release

    def test_a_table_already_in_the_cache_is_not_overwritten(self):
        dest = os.path.join(self.cache, f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz")
        os.makedirs(os.path.dirname(dest))
        with open(dest, "wb") as fh:
            fh.write(b"fresh")
        self.assertEqual(k.seed(self.cache, self.prev, log=lambda m: None), 0)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"fresh")


class ProgressAndFanOut(unittest.TestCase):
    """2026-10-06: "we need more logs and progress bar" and "try to optimize it
    it takes very long". A CI log shows every table as it lands, with where the
    build is and when it ends; the conversion fans out over N jobs and the
    assembling build converts nothing they did."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.converted = []

    def fake_convert(self, pdb, guid, age, cache):
        rel = f"windows/{pdb}/{guid}-{age}.json.xz"
        os.makedirs(os.path.dirname(os.path.join(cache, rel)), exist_ok=True)
        with open(os.path.join(cache, rel), "wb") as fh:
            fh.write(b"table")
        self.converted.append(rel)
        return rel

    # 5 kernel builds; builds 1000 and 1001 share one PDB (the same table)
    BUILDS = [{"file": "ntoskrnl.exe", "timestamp": t, "virtualSize": 1, "version": str(t),
               "released": "2025-01-01", "windows": ["11-24H2"]} for t in range(1000, 1005)]
    IDS = {1000: ("ntkrnlmp.pdb", "AA", 1), 1001: ("ntkrnlmp.pdb", "AA", 1), 1002: ("ntkrnlmp.pdb", "BB", 1),
           1003: ("ntkrnlmp.pdb", "CC", 1), 1004: ("ntkrnlmp.pdb", "DD", 1)}

    def patched(self):
        return (mock.patch.object(k, "builds", lambda name, *a, **kw: self.BUILDS if name == "ntoskrnl.exe" else []),
                mock.patch.object(k, "codeview", lambda b: self.IDS[b["timestamp"]]),
                mock.patch.object(k, "convert", self.fake_convert))

    def test_every_table_logs_a_progress_line_with_an_eta(self):
        lines = []
        b, c, v = self.patched()
        with b, c, v:
            k.build(os.path.join(self.d, "out"), os.path.join(self.d, "cache"), "2000-01-01", 1, log=lines.append)
        prog = [l for l in lines if "/4 " in l and "ok   ntkrnlmp.pdb/" in l]
        self.assertEqual(len(prog), 4, lines)
        self.assertIn("ETA", prog[0])
        self.assertIn("[####################] 4/4 100%", prog[-1])

    def test_a_table_two_builds_share_is_converted_once(self):
        b, c, v = self.patched()
        with b, c, v:
            k.build(os.path.join(self.d, "out"), os.path.join(self.d, "cache"), "2000-01-01", 4, log=lambda m: None)
        self.assertEqual(sorted(self.converted), sorted(set(self.converted)))
        self.assertEqual(len(self.converted), 4)

    def test_plan_shards_and_assembly_convert_each_table_exactly_once(self):
        import contextlib
        import io
        import json
        base, plan = os.path.join(self.d, "base"), os.path.join(self.d, "plan.json")
        b, c, v = self.patched()
        with b, c, v, contextlib.redirect_stdout(io.StringIO()):
            k.main(["--cache", base, "--plan-out", plan])
            self.assertEqual(self.converted, [])                  # planning converts nothing
            for i in range(3):
                k.main(["--cache", os.path.join(self.d, f"shard{i}"), "--plan", plan, "--shard", f"{i}/3"])
            self.assertEqual(len(self.converted), 4)
            self.assertEqual(len(set(self.converted)), 4)         # no table twice across shards
            for i in range(3):                                    # the assembling job merges the shards
                src = os.path.join(self.d, f"shard{i}")
                for root, _dirs, files in os.walk(src):
                    for f in files:
                        dst = os.path.join(base, os.path.relpath(os.path.join(root, f), src))
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.copyfile(os.path.join(root, f), dst)
            k.main(["--cache", base, "--out", os.path.join(self.d, "out")])
        self.assertEqual(len(self.converted), 4)                  # the assembly converted nothing
        z = zipfile.ZipFile(os.path.join(self.d, "out", "intact-windows-kernels.zip"))
        self.assertEqual(len(json.loads(z.read("intact-kernel-pack.json"))["tables"]), 4)


if __name__ == "__main__":
    unittest.main()
