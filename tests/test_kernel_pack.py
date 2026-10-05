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


class WhichBuilds(unittest.TestCase):
    DATA = winbindex((34404, ["11-24H2"], "2024-09-10"),       # the LTSC base build: in
                     (34404, ["1709"], "2019-04-09"),          # out of support: out
                     (332, ["11-24H2"], "2025-01-01"),         # x86: out
                     (34404, ["1809", "1607"], "2021-01-12"))  # LTSC/Server lines: in

    def test_every_build_of_a_supported_version_whatever_its_age(self):
        got = k.builds("ntoskrnl.exe", "2000-01-01", self.DATA)
        self.assertEqual(sorted(b["version"] for b in got), ["10.0.0", "10.0.3"])

    def test_since_still_narrows_when_asked(self):
        self.assertEqual([b["version"] for b in k.builds("ntoskrnl.exe", "2024-01-01", self.DATA)], ["10.0.0"])


class TheCodeViewRecord(unittest.TestCase):
    def test_guid_age_and_pdb_come_out_of_the_pe(self):
        pe = pe_with_codeview(GUID, 1, "ntkrnlmp.pdb")
        with mock.patch.object(k, "_get", lambda url, rng=None, timeout=0: pe[rng[0]:rng[1] + 1] if rng else pe):
            self.assertEqual(k.codeview({"file": "ntoskrnl.exe", "timestamp": 1, "virtualSize": 2}),
                             ("ntkrnlmp.pdb", GUID, 1))


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

    def test_nothing_built_is_a_failure_not_an_empty_pack(self):
        with mock.patch.object(k, "builds", lambda *a, **kw: []), self.assertRaises(SystemExit):
            k.build(self.out, self.cache, "2000-01-01", 1, {}, log=lambda m: None)


if __name__ == "__main__":
    unittest.main()
