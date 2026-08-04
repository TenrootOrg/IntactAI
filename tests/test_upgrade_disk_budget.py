"""Disk budget + image pruning for an offline apply.

A release package ships EVERY module, but an apply installs only what the
operator ticked. Until now the disk preflight charged for the whole package
and the extracted tars for unselected modules sat on disk for the entire run.
On the real intact-20260728 package (5.77 GB, ~13 GiB of images) that demanded
~37 GiB free and refused an upgrade on a box with 33 GiB — for work that
actually needed about 25.

Two changes, pinned here:
  * images_by_module() attributes each bundled tar to its module, so the
    budget and the prune both know what belongs to whom;
  * required_free_gb_for_manifest(selected_modules=...) charges only for what
    will be loaded.

The dangerous direction is UNDER-budgeting: too small a number means ENOSPC
partway through `docker load`, with modules half-applied. So anything that
cannot be attributed is deliberately counted, and never pruned.

Run: docker exec intact_backend python /app/workdir/tests/test_upgrade_disk_budget.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade.package import images_by_module, image_owner_prefixes  # noqa: E402
from services.upgrade.config_validate import (  # noqa: E402
    required_free_gb_for_manifest, APPLY_MIN_FREE_GB)

GiB = 1024 ** 3

# The real inventory of intact-20260728.
IMAGES = {
    "intact-backend-intact-20260728.tar": 1.40, "tusd-v2.9.2.tar": 0.03,
    "elasticsearch-9.4.2.tar": 1.60, "kibana-9.4.2.tar": 1.64,
    "logstash-9.4.2.tar": 1.20,
    "timesketch-20260630.tar": 1.07, "postgres-13.0-alpine.tar": 0.08,
    "opensearch-2.19.5.tar": 1.47, "redis-7.2.11-alpine.tar": 0.04,
    "nginx-1.25.5-alpine-slim.tar": 0.04,
    "plaso-20260512.tar": 0.90,
    "iris-app-v2.4.27.tar": 1.38, "iris-nginx-v2.4.27.tar": 0.06,
    "iris-db-v2.4.27.tar": 0.40, "rabbitmq-3-management-alpine.tar": 0.20,
    "velociraptor-0.77.1.tar": 0.57, "dfir-o365rc-latest.tar": 0.50,
    "volweb-backend-3.16.0.tar": 1.33, "volweb-frontend-3.16.0.tar": 0.30,
    "volweb-postgres-14.1.tar": 0.40, "volweb-redis-7.4.9.tar": 0.11,
    "portainer-ce-2.39.5.tar": 0.15, "portainer-agent-2.39.5.tar": 0.11,
}
MANIFEST = {"contents": {"image_sizes": {k: int(v * GiB) for k, v in IMAGES.items()}}}
PKG = int(5.77 * GiB)


def test_every_bundled_image_has_an_owner():
    """An unowned image is never pruned and always billed, so it silently
    inflates every budget. That is a packaging bug worth failing on."""
    orphans = images_by_module(list(IMAGES)).get(None) or []
    assert not orphans, (
        f"no module owns {orphans} — add its tar prefix in "
        f"package.image_owner_prefixes(), or the disk budget over-charges "
        f"every apply and the prune can never reclaim it")


def test_sidecar_names_do_not_cross_modules():
    """volweb-redis- must not land under timesketch's redis-, and iris-nginx-
    must not land under timesketch's nginx-. Misattribution here deletes an
    image a selected module needs."""
    owned = images_by_module([
        "redis-7.2.11-alpine.tar", "volweb-redis-7.4.9.tar",
        "nginx-1.25.5-alpine-slim.tar", "iris-nginx-v2.4.27.tar",
        "postgres-13.0-alpine.tar", "volweb-postgres-14.1.tar",
    ])
    assert owned["timesketch"] == ["redis-7.2.11-alpine.tar",
                                   "nginx-1.25.5-alpine-slim.tar",
                                   "postgres-13.0-alpine.tar"], owned
    assert sorted(owned["volweb"]) == ["volweb-postgres-14.1.tar",
                                       "volweb-redis-7.4.9.tar"], owned
    assert owned["iris"] == ["iris-nginx-v2.4.27.tar"], owned


def test_locally_built_images_are_attributed():
    """velociraptor's server image is built, not pulled, so it is in neither
    packaging table — it needs an explicit prefix or it orphans."""
    assert images_by_module(["velociraptor-0.77.1.tar"])["velociraptor"]
    assert images_by_module(["intact-backend-x.tar", "tusd-v2.9.2.tar"])["intact"]


def test_selecting_fewer_modules_lowers_the_requirement():
    whole = required_free_gb_for_manifest(MANIFEST, PKG)
    some = required_free_gb_for_manifest(
        MANIFEST, PKG, selected_modules=["intact", "timesketch", "velociraptor",
                                         "iris", "plaso", "portainer"])
    assert some < whole, f"scoped budget ({some}) not below whole-package ({whole})"
    assert whole - some > 10, (
        f"expected a large saving on a package this size; got {whole} -> {some}")


def test_default_still_budgets_the_whole_package():
    """None means the selection is not known yet (the pre-extraction check).
    Budgeting only part of the package there would under-charge."""
    assert (required_free_gb_for_manifest(MANIFEST, PKG)
            == required_free_gb_for_manifest(MANIFEST, PKG, selected_modules=None))


def test_unattributable_images_are_still_charged():
    """Under-budgeting ends in ENOSPC mid-load, so an unowned image counts
    even when it belongs to no selected module."""
    m = {"contents": {"image_sizes": {"intact-backend-x.tar": int(1 * GiB),
                                      "mystery-thing-1.0.tar": int(8 * GiB)}}}
    need = required_free_gb_for_manifest(m, int(1 * GiB), selected_modules=["intact"])
    assert need > 15, (
        f"the 8 GiB unattributable image was dropped from the budget ({need} GiB)")


def test_floor_is_never_undercut():
    """A tiny selection must not claim an implausibly small requirement."""
    need = required_free_gb_for_manifest(MANIFEST, PKG, selected_modules=["intact"])
    assert need >= APPLY_MIN_FREE_GB, need


def test_unknown_module_selection_charges_only_unowned():
    """A selection naming nothing in the package still budgets the package
    itself plus anything unattributed — never zero."""
    need = required_free_gb_for_manifest(MANIFEST, PKG, selected_modules=["nope"])
    assert need >= APPLY_MIN_FREE_GB, need


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
