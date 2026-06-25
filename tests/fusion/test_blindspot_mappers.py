"""Blind-spot detection typing — LolDrivers (BYOVD), HijackLibs (DLL sideload),
Bootloaders (firmware). Synthetic rows from the real DetectRaptor schemas (these
return 0 rows on a clean box, so they're schema-accurate, not live capture).
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate, keys  # noqa: E402
from services.fusion.mappers import map_agentic  # noqa: E402

HN = {"C.z": "H"}


def _fuse(cd):
    return correlate.assemble("bs", [map_agentic(cd, run_id="a", hostnames=HN)], ["a"])


def test_loldrivers_malicious_is_byovd_finding():
    cd = {"DetectRaptor.Windows.Detection.LolDriversMalicious": [
        {"Name": "evil.sys", "SHA1": "b" * 40, "SHA256": "a" * 64,
         "OSPath": "C:\\Windows\\System32\\drivers\\evil.sys", "_client_id": "C.z", "_hostname": "H"}]}
    g = _fuse(cd)
    mods = [e for e in g.by_type("module") if "byovd" in e.flags]
    assert mods, "malicious driver -> module with byovd flag"
    f = [x for x in g.findings if "T1068" in x.mitre]
    assert f and f[0].severity == "high"
    assert mods[0].attrs.get("full_hash") == "a" * 64  # hash-bridge fuel


def test_loldrivers_vulnerable_is_lower_severity_no_byovd():
    cd = {"DetectRaptor.Windows.Detection.LolDriversVulnerable": [
        {"Name": "vuln.sys", "SHA256": "c" * 64, "_client_id": "C.z", "_hostname": "H"}]}
    g = _fuse(cd)
    mods = [e for e in g.by_type("module") if "loldriver" in e.flags]
    assert mods and "byovd" not in mods[0].flags
    f = [x for x in g.findings if "T1068" in x.mitre]
    assert f and f[0].severity == "medium", "vulnerable (present != exploited) is medium"


def test_hijacklibs_dll_sideload_finding():
    cd = {"DetectRaptor.Windows.Detection.HijackLibsEnv": [
        {"HijackLibInfo": {"DllName": "dbghelp.dll", "Type": "Sideloading"},
         "OSPath": "C:\\Users\\x\\dbghelp.dll", "_client_id": "C.z", "_hostname": "H"}]}
    g = _fuse(cd)
    ev = [e for e in g.by_type("event") if "dll_hijack" in e.flags]
    assert ev and "dbghelp.dll" in ev[0].label
    assert any("T1574" in f.mitre for f in g.findings)


def test_hijacklibs_mft_is_lower_confidence_anomaly():
    cd = {"DetectRaptor.Windows.Detection.HijackLibsMFT": [
        {"DllName": "madhcnet32.dll", "OSPath": "C:\\x\\madhcnet32.dll",
         "_client_id": "C.z", "_hostname": "H"}]}
    g = _fuse(cd)
    ev = [e for e in g.by_type("event") if "dll_hijack" in e.flags]
    assert ev and ev[0].anomaly == 15  # historical/MFT -> lower than Env(40)


def test_bootloader_only_finds_on_bad_verdict():
    benign = {"DetectRaptor.Windows.Detection.Bootloaders": [
        {"Name": "bootmgfw.efi", "OSPath": "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
         "_client_id": "C.z", "_hostname": "H"}]}
    bad = {"DetectRaptor.Windows.Detection.Bootloaders": [
        {"Name": "evilboot.efi", "Revoked": True, "_client_id": "C.z", "_hostname": "H"}]}
    gb = _fuse(benign); gx = _fuse(bad)
    assert not [f for f in gb.findings if "bootloader" in f.title.lower()], "benign bootloader = no finding"
    assert [f for f in gx.findings if "bootloader" in f.title.lower()], "revoked bootloader = finding"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
