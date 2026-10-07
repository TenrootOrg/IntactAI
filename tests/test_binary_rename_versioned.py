"""A versioned / installer copy of a program is not a renamed binary.

2026-10-07, a real case: every WinRAR installer (winrar-x64-611.exe,
winrar-x64-700b3 (1).exe ...) was a HIGH "Renamed binary" (masquerading,
T1036.003) because its version info says WinRAR.exe. The on-disk name still
STARTS with the original name -- the same program, versioned. A masquerade
renames to a different name (svchost.exe <- mimikatz.exe) and stays high.
Generic: no program is named in code.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import _same_program, map_agentic  # noqa: E402

ART = "DetectRaptor.Windows.Detection.BinaryRename"
SHA = "e0a76fd8" + "0" * 56


def row(name, original, sha=SHA, host="SRV1"):
    return {"Name": name, "OSPath": f"C:\\Users\\a\\Downloads\\{name}", "Hash": {"SHA256": sha},
            "VersionInformation": {"OriginalFilename": original}, "Btime": "2026-08-24T10:00:00Z",
            "_hostname": host, "_client_id": f"C.{host}"}


class TheRule(unittest.TestCase):
    def test_versioned_and_installer_names_are_the_same_program(self):
        for name in ("winrar-x64-611.exe", "winrar-x64-700b3 (1).exe", "WinRAR_7.01.exe", "putty-64bit-0.81-installer.msi"):
            orig = "WinRAR.exe" if "inrar" in name.lower() else "PuTTY.exe"
            self.assertTrue(_same_program(name, orig), name)

    def test_a_different_name_is_still_a_rename(self):
        self.assertFalse(_same_program("svchost.exe", "mimikatz.exe"))
        self.assertFalse(_same_program("update.exe", "WinRAR.exe"))

    def test_a_short_original_never_excuses_a_rename(self):
        self.assertFalse(_same_program("cmdhelper.exe", "cmd.exe"))

    def test_the_same_name_is_not_a_versioned_copy(self):
        self.assertFalse(_same_program("WinRAR.exe", "WinRAR.exe"))


class InTheGraph(unittest.TestCase):
    def fuse(self, rows):
        ents, rels = map_agentic({ART: rows}, run_id="r1")
        return correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="informational")

    def test_an_installer_copy_is_informational_not_masquerading(self):
        g = self.fuse([row("winrar-x64-611.exe", "WinRAR.exe")])
        ev = [e for e in g.entities.values() if e.type == "event"]
        self.assertTrue(ev)
        self.assertTrue(all(e.severity == "informational" and "masquerading" not in e.flags for e in ev))
        self.assertFalse([f for f in g.findings if f.severity in ("high", "critical")])

    def test_the_same_installer_on_two_hosts_is_not_a_shared_binary_finding(self):
        # Its hash is context (IOC appendix only), not "Shared binary seen on 2 hosts".
        g = self.fuse([row("winrar-x64-611.exe", "WinRAR.exe", host=h) for h in ("SRV1", "SRV2")])
        self.assertEqual([f.title for f in g.findings if f.kind == "cross_host"], [])

    def test_a_real_masquerade_stays_high(self):
        g = self.fuse([row("svchost.exe", "mimikatz.exe", sha="ab" * 32)])
        self.assertTrue([f for f in g.findings if f.severity == "high"])


if __name__ == "__main__":
    unittest.main()
