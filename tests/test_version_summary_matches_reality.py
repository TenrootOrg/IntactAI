"""The VERSION SUMMARY must not promise work the module loop will not do.

run_offline_upgrade_workflow warns about manifest entries this installer does
not know -- they are never dispatched, because the module loop walks
UPGRADE_ORDER rather than the manifest:

    WARNING: package contains module(s) this installer does not know and
             will NOT apply: velociraptor_legacy

...and then the VERSION SUMMARY, built by iterating the whole manifest, printed

    VELOCIRAPTOR_LEGACY: installing 0.7.1 (fresh install)

Two views of the same decision, computed at different points, contradicting
each other on the same screen. An operator reading the summary would believe a
module was installed that the previous lines said was skipped.

Observed 2026-08-02 with a hand-built manifest carrying `velociraptor_legacy`
in `versions:` (it is a version PIN, not a module -- but the summary cannot
know that, and must not claim work it will not do).

The same-version branch already had this right, and says so in its own comment:
"Say what actually happens." The 2026-07-23 air-gap run printed "VOLWEB:
reinstalling 3.16.0" and then never showed an UPGRADING: VOLWEB section, which
reads as a module that silently vanished rather than one correctly skipped.
This applies that principle to the unknown-module case.

Run: docker exec intact_backend python /app/workdir/tests/test_version_summary_matches_reality.py
"""

import inspect
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import run_offline_upgrade_workflow  # noqa: E402
from services.upgrade import UPGRADE_ORDER  # noqa: E402

SRC = inspect.getsource(run_offline_upgrade_workflow)
SUMMARY = SRC[SRC.index('log("VERSION SUMMARY:"'):SRC.index("offline_upgrade_functions")]


def test_unknown_modules_are_reported_as_not_applied():
    """The whole bug: the summary must branch on unknown-ness before it can
    reach the 'installing (fresh install)' line."""
    assert "_unknown_manifest_modules" in SUMMARY, (
        "the VERSION SUMMARY no longer consults the unknown-module list — it "
        "will again advertise 'installing X (fresh install)' for a module the "
        "warning directly above says will NOT be applied")


def test_the_unknown_branch_comes_before_the_fresh_install_branch():
    """Order matters: `elif current_ver in ('Not installed', ...)` is true for
    every unknown module, so the unknown check has to win."""
    unknown_at = SUMMARY.index("_unknown_manifest_modules")
    fresh_at = SUMMARY.index("(fresh install)")
    assert unknown_at < fresh_at, (
        "the unknown-module branch is after the fresh-install branch — an "
        "unknown module is always 'Not installed', so it would take the wrong "
        "branch first")


def test_the_unknown_line_does_not_claim_an_install():
    """Wording is the whole point of this fix. It must not read as work done."""
    line = next(l for l in SUMMARY.splitlines() if "NOT APPLIED" in l)
    assert "installing" not in line.lower(), line


def test_the_unknown_line_is_a_warning_not_info():
    """It sits among info lines; at info level it reads as routine."""
    block = SUMMARY[SUMMARY.index("_unknown_manifest_modules"):]
    block = block[:block.index("elif")]
    assert '"warning"' in block, (
        "an unapplied module is logged at info level, so it reads as routine "
        "among the modules that WILL be applied")


def test_the_guard_that_computes_the_list_still_exists():
    """The summary now depends on it; losing the guard would raise NameError
    mid-run rather than merely degrading the message."""
    assert "_unknown_manifest_modules = [" in SRC, (
        "the unknown-module guard is gone but the summary still references it")


def test_the_list_is_derived_from_upgrade_order():
    """It must be 'not dispatchable', not a hardcoded denylist — the module loop
    walks UPGRADE_ORDER, so that is the only correct source."""
    guard = SRC[SRC.index("_unknown_manifest_modules = ["):]
    guard = guard[:guard.index("\n")]
    assert "UPGRADE_ORDER" in guard, guard


def test_a_real_module_is_not_flagged_unknown():
    """Sanity: the modules this installer genuinely dispatches must not trip the
    guard, or every upgrade would report everything as unapplied."""
    for m in ("timesketch", "velociraptor", "plaso", "volweb", "intact"):
        assert m in UPGRADE_ORDER, f"{m} vanished from UPGRADE_ORDER"


def test_velociraptor_legacy_is_not_a_dispatchable_module():
    """Pins the fact that produced the bug. velociraptor_legacy is a VERSION
    PIN carried in contents.velociraptor_legacy, never a module — if it ever
    becomes one, this test should fail and be deleted deliberately."""
    assert "velociraptor_legacy" not in UPGRADE_ORDER, (
        "velociraptor_legacy is now in UPGRADE_ORDER — if that is intended, "
        "packages may legitimately carry it in versions: and this test is stale")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
