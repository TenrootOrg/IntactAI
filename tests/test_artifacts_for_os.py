"""OS-aware artifact selection for offline collectors.

Regression guard for the Linux-collector bug: the blueprints are Windows-centric,
the collector *binary* is chosen per-OS, but the artifact list used to always be the
Windows ``DEFAULT_ARTIFACTS``. Running Windows artifacts on a Linux binary produced
``Symbol Memory not found`` / ``token() not implemented for linux_amd64_cgo`` /
``Unknown filesystem accessor ntfs`` errors and a ~1h full-filesystem crawl over
/proc + /sys + docker overlay mounts. ``artifacts_for_os`` fixes that.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.offline_collector.constants import (  # noqa: E402
    artifacts_for_os,
    DEFAULT_ARTIFACTS,
    LINUX_DEFAULT_ARTIFACTS,
    DARWIN_DEFAULT_ARTIFACTS,
    HEAVY_FS_SCAN_ARTIFACTS,
)


def test_windows_target_unchanged():
    """Windows collectors keep their configured Windows artifact list verbatim."""
    assert artifacts_for_os("windows", DEFAULT_ARTIFACTS) == DEFAULT_ARTIFACTS


def test_windows_blueprint_on_linux_falls_back_to_linux_set():
    """The reported bug: a Windows blueprint pointed at a Linux host. No Linux.*
    artifact survives the filter, so we fall back to the curated Linux triage set."""
    got = artifacts_for_os("linux", DEFAULT_ARTIFACTS)
    assert got == LINUX_DEFAULT_ARTIFACTS
    # Never ship Windows VQL to a Linux binary.
    assert not any(a.startswith("Windows.") for a in got)


def test_linux_result_has_no_heavy_fs_scanners():
    """The /proc + /sys + docker crawl came from broad Generic.* scanners; they
    must never appear in a non-Windows collector."""
    for os_type in ("linux", "darwin"):
        got = artifacts_for_os(os_type, DEFAULT_ARTIFACTS)
        assert not (set(got) & HEAVY_FS_SCAN_ARTIFACTS), os_type


def test_linux_blueprint_keeps_native_and_light_generic():
    """A genuine Linux blueprint keeps its Linux.* + light Generic.* artifacts, and
    still drops the heavy filesystem scanners."""
    mixed = [
        "Linux.Sys.Pslist",
        "Windows.NTFS.MFT",            # foreign OS -> dropped
        "Generic.System.Pstree",       # light generic -> kept
        "Generic.Collectors.File",     # heavy scanner -> dropped
    ]
    got = artifacts_for_os("linux", mixed)
    assert got == ["Linux.Sys.Pslist", "Generic.System.Pstree"]


def test_darwin_blueprint_on_windows_set_falls_back():
    got = artifacts_for_os("darwin", DEFAULT_ARTIFACTS)
    assert got == DARWIN_DEFAULT_ARTIFACTS
    assert not any(a.startswith(("Windows.", "Linux.")) for a in got)


def test_empty_configured_defaults_to_windows_then_adapts():
    """No configured artifacts -> treat as the Windows default, then adapt per OS."""
    assert artifacts_for_os("windows", None) == DEFAULT_ARTIFACTS
    assert artifacts_for_os("linux", []) == LINUX_DEFAULT_ARTIFACTS


def test_linux_blueprint_on_windows_drops_foreign_and_falls_back():
    """Symmetric case: the dedicated Linux blueprint built for a Windows target.
    Linux.* artifacts are foreign on Windows; nothing Windows-native survives, so we
    fall back to the Windows triage set rather than ship Linux VQL to a win binary."""
    got = artifacts_for_os("windows", LINUX_DEFAULT_ARTIFACTS)
    assert got == DEFAULT_ARTIFACTS
    assert not any(a.startswith(("Linux.", "MacOS.")) for a in got)


def test_windows_keeps_heavy_generic_scanners():
    """Heavy Generic scanners are only dropped on non-Windows targets — on Windows
    they're scoped and fast, so they must stay."""
    cfg = ["Windows.NTFS.MFT", "Generic.Forensic.SQLiteHunter", "Generic.Collectors.File"]
    assert artifacts_for_os("windows", cfg) == cfg


def test_unknown_os_returns_configured_unchanged():
    """Defensive: an unexpected os_type doesn't mangle the artifact list."""
    cfg = ["Windows.NTFS.MFT", "Generic.System.Pstree"]
    assert artifacts_for_os("solaris", cfg) == cfg


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
