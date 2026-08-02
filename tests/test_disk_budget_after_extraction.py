"""The post-extraction disk check must not re-charge for bytes already spent.

run_offline_upgrade_workflow ran its second disk check through
required_free_gb_for_manifest(), which sizes the WHOLE job from a clean start:
package + extracted tree + loaded images. That is right for the check that runs
BEFORE anything is downloaded.

It is wrong where it was used. verify_upgrade_package() extracts the package
well before that check, so by then the tarball AND the extracted tree are on
disk and have already been subtracted from `free`. Charging for them again
compares a from-scratch total against post-extraction free space and
double-counts every byte already spent.

Observed 2026-08-02 upgrading 20260726 -> 20260802: a 5.8 GB, 10-module
package demanded 37.7 GiB from a box with 23.1 GiB free, while the work
actually remaining -- loading the staged tars -- needed a fraction of that.

required_free_gb_after_extraction() sizes only what is still to come, measured
from the tars ACTUALLY on disk rather than from the manifest, so it also picks
up the unselected-module prune and any tar a previous attempt already loaded
and reclaimed.

The dangerous direction is still UNDER-budgeting: too small a number means
ENOSPC partway through `docker load`, with modules half-applied. So the floor
survives, an unreadable directory falls back to the floor, and the model stays
conservative about the one tar in flight.

Run: docker exec intact_backend python /app/workdir/tests/test_disk_budget_after_extraction.py
"""

import inspect
import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import run_offline_upgrade_workflow  # noqa: E402
from services.upgrade.config_validate import (  # noqa: E402
    APPLY_MIN_FREE_GB, required_free_gb_after_extraction,
    required_free_gb_for_manifest)

GiB = 1024 ** 3
SRC = inspect.getsource(run_offline_upgrade_workflow)


def _images(*sizes_gib):
    d = tempfile.mkdtemp(prefix="imgs-")
    for i, g in enumerate(sizes_gib):
        with open(os.path.join(d, f"img-{i}.tar"), "wb") as f:
            f.truncate(int(g * GiB))
    return d


# ---------------------------------------------------------------------------
# The sizing model
# ---------------------------------------------------------------------------

def test_the_real_case_now_fits():
    """The 2026-08-02 refusal. ~13.6 GiB of staged tars, largest ~1.6 GiB, on a
    box with 23.1 GiB free. The old call wanted 37.7 GiB."""
    d = _images(1.6, 1.5, 1.4, 1.3, 1.1, 1.0, 0.9, 0.8, 0.7, 0.7, 0.6, 0.5,
                0.3, 0.2, 0.1, 0.1)
    need = required_free_gb_after_extraction(d)
    assert need <= 23.1, f"still refuses the box it should now accept: {need}"


def test_never_below_the_floor():
    """Module upgrades do more than load images -- pg_dump backups, compose
    churn, rollback snapshots. That work needs room the image maths cannot see."""
    assert required_free_gb_after_extraction(_images(0.01)) == float(APPLY_MIN_FREE_GB)
    assert required_free_gb_after_extraction(_images()) == float(APPLY_MIN_FREE_GB)


def test_unreadable_directory_falls_back_to_the_floor():
    """Never return 0 for a path we could not read -- that would wave through
    an apply with no disk check at all."""
    assert required_free_gb_after_extraction(
        "/nonexistent/images") == float(APPLY_MIN_FREE_GB)


def test_a_genuinely_huge_load_still_exceeds_the_floor():
    """The check must keep biting when the remaining work really is large."""
    need = required_free_gb_after_extraction(_images(8, 8, 8, 8))
    assert need > APPLY_MIN_FREE_GB, need


def test_it_is_cheaper_than_the_from_scratch_estimate():
    """The whole point: post-extraction is strictly less than from-scratch for
    the same images, because the package and the tree are already on disk."""
    sizes = [2.0, 1.5, 1.0]
    d = _images(*sizes)
    after = required_free_gb_after_extraction(d)
    manifest = {"contents": {"image_sizes": {f"img-{i}.tar": int(g * GiB)
                                             for i, g in enumerate(sizes)}}}
    scratch = required_free_gb_for_manifest(manifest, package_bytes=int(2.5 * GiB))
    assert after <= scratch, (after, scratch)


def test_larger_staged_set_costs_more():
    """Monotonic -- a bigger remaining load must never budget less."""
    small = required_free_gb_after_extraction(_images(6, 6))
    big = required_free_gb_after_extraction(_images(6, 6, 6, 6, 6))
    assert big > small, (small, big)


def test_a_reclaimed_images_dir_costs_only_the_floor():
    """Phase 2 after a Phase-1 pre-load with cleanup_after_load=True: the tars
    are gone, so there is nothing left to load and only the floor applies."""
    assert required_free_gb_after_extraction(_images()) == float(APPLY_MIN_FREE_GB)


# ---------------------------------------------------------------------------
# Wiring: both post-extraction checks must use it
# ---------------------------------------------------------------------------

def test_phase1_post_extraction_check_uses_the_new_sizing():
    assert "required_free_gb_after_extraction" in SRC, (
        "the post-extraction disk check no longer uses "
        "required_free_gb_after_extraction — it is double-counting the package "
        "and the extracted tree again")


def test_phase1_check_no_longer_uses_the_from_scratch_estimate():
    """Scan CODE, not comments. The explanation of why this changed names the
    old function, and matching that prose would pass or fail on documentation
    rather than on behaviour."""
    code = "\n".join(l for l in SRC.splitlines()
                     if not l.lstrip().startswith("#"))
    assert "required_free_gb_for_manifest(" not in code, (
        "run_offline_upgrade_workflow still calls required_free_gb_for_manifest "
        "after extraction, which charges for bytes already on disk")


def test_the_early_pre_download_check_still_uses_from_scratch_sizing():
    """The check that runs BEFORE anything is unpacked must keep budgeting the
    whole job -- that one is not double-counting anything."""
    from services.upgrade import __init__ as _mod  # noqa: F401
    import services.upgrade as up
    whole = inspect.getsource(up)
    assert "required_free_gb_for_manifest" in whole, (
        "the from-scratch estimator is gone entirely — the pre-download check "
        "needs it")


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
