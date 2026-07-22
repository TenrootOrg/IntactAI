#!/usr/bin/env python3
"""CI entrypoint — build a version-pinned release upgrade package.

Runs the SAME prepare_upgrade_package() the on-box online upgrade uses, but
headless (GitHub Actions), so the artifact is built by the TARGET release's
OWN code. That's the real fix for the factor-5 / "Unknown module" class: the
package is never constructed by an older, module-blind backend — it's built
by the release that actually contains every module, then downloaded + applied.

Meant to run INSIDE a container built from the release's backend image, with:
  - the docker socket mounted (it docker build/pull/save's the images),
  - /opt/sigma-rules populated (CI clones SigmaHQ) for the aws_sigma rule pack,
  - INTACT_PATH / INTACT_HOST_PATH set to the release checkout,
  - an output dir mounted for the finished tarball.

Module set = every primary module in the release config.yaml `versions:` block,
at its pinned version, so any customer can upgrade any module they run. `intact`
is pinned to the release tag (so the backend image is `intact-backend:<tag>`).
`cve_scan` is SKIPPED: its ~300MB CVE DB is rolling data fetched fresh at apply
time, never baked into a release.

Usage:
  build_release_package.py --tag intact-20260720 --out /output
"""
import argparse
import os
import shutil
import sys

# The backend package is at /app inside the image.
if "/app" not in sys.path:
    sys.path.insert(0, "/app")


# LEAN RELEASE SCOPE (2026-07-21, per operator request):
# ship a package with ONLY the core platform + the actively-needed DFIR
# modules — intact (backend + frontend/nginx), velociraptor, aws_sigma, and
# cve_scan. The heavier/less-used modules are commented out below; to build a
# FULL release again, just un-comment them (no other change needed — the
# loop below reads this set).
RELEASE_MODULES = {
    "intact",         # backend + frontend (nginx) platform source + image
    "velociraptor",
    "aws_sigma",      # SigmaHQ AWS CloudTrail rule pack
    "cve_scan",       # ships the prebuilt CVE SQLite DB if the build host has one
    "timesketch",
    "plaso",
    # "elk",
    # "iris",
    # "volweb",
    # "portainer",
    # "o365rc",
}


def release_module_set(tag: str) -> dict:
    """{module: version} for the modules this (lean) release ships.

    intact is pinned to `tag`; cve_scan carries a truthy version only to pass the
    packager's version gate (its real artifact is the bundled CVE DB, not a
    version pin). Scope is controlled by :data:`RELEASE_MODULES` above."""
    import yaml
    from services.upgrade import UPGRADE_ORDER
    cfg_path = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"), "config.yaml")
    versions = (yaml.safe_load(open(cfg_path)) or {}).get("versions") or {}
    modules = {}
    for m in UPGRADE_ORDER:
        if m not in RELEASE_MODULES:
            continue  # excluded from this release — see RELEASE_MODULES
        if m == "intact":
            modules["intact"] = tag  # -> builds intact-backend:<tag>
        elif m == "cve_scan":
            # rolling data: the packager bakes the current CVE SQLite DB when it
            # exists on the build host. A truthy version keeps cve_scan past the
            # version-gated packaging loop.
            modules["cve_scan"] = versions.get("cve_scan") or "rolling"
        elif m in versions:
            modules[m] = versions[m]
    return modules


def _verify_package_usable(result: dict, tag: str):
    """Return an error string if the built package would not be usable by a box
    upgrading to ``tag``, else None.

    Checks the two things that make a package silently useless rather than
    obviously broken:

    1. **Backend image present and correctly named.** For a Full-mode release
       (target compose runs code from the image), the target resolves the image
       via ``backend_target_tag()`` — config ``versions.backend`` → ``VERSION``
       → 'development'. Both of those land on the release tag, so the bundled
       image MUST be ``intact-backend-<tag>.tar``. Any other name is invisible
       to the target and forces an on-box rebuild.
    2. **intact pinned to the release tag** in the manifest, since that is what
       the target reads to decide what it is upgrading to.
    """
    manifest = result.get("manifest") or {}
    versions = manifest.get("versions") or {}
    images = ((manifest.get("contents") or {}).get("images") or [])

    if versions.get("intact") != tag:
        return (f"manifest versions.intact is {versions.get('intact')!r}, "
                f"expected {tag!r}")

    # Full-mode is decided by the TARGET release's own backend compose, the same
    # way prepare decided whether to bake. Reuse that helper rather than
    # re-deriving the rule here.
    try:
        from services.upgrade.intact import backend_full_mode
        src_root = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"))
        target_compose = os.path.join(src_root, "modules", "backend",
                                      "docker-compose.yaml")
        full_mode = backend_full_mode(target_compose)
    except Exception as e:                                    # pragma: no cover
        return f"could not determine backend deploy mode ({type(e).__name__}: {e})"

    if not full_mode:
        print("[ci-package] self-check: legacy source-mounted release — "
              "no backend image expected.", flush=True)
        return None

    expected = f"intact-backend-{tag}.tar"
    if expected not in images:
        backend_imgs = [i for i in images if i.startswith("intact-backend-")]
        return (f"Full-mode release but {expected} is not in the package "
                f"(backend images present: {backend_imgs or 'NONE'}). The target "
                f"would not find its image and would rebuild from source.")
    print(f"[ci-package] self-check: {expected} bundled — the target will load "
          f"it, not rebuild.", flush=True)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True, help="release tag, e.g. intact-20260720")
    ap.add_argument("--out", required=True, help="dir to copy the finished package into")
    ap.add_argument("--print-modules", action="store_true",
                    help="print the resolved module set and exit (no build)")
    args = ap.parse_args()

    modules = release_module_set(args.tag)
    if args.print_modules:
        for m, v in modules.items():
            print(f"{m}={v}")
        return 0

    from services.upgrade.package import prepare_upgrade_package
    print(f"[ci-package] release {args.tag}: building {', '.join(modules)}", flush=True)

    result = prepare_upgrade_package(
        modules,
        run_id=f"ci_release_{args.tag}",
        logger=lambda m, l="info": print(f"[{l}] {m}", flush=True),
        compress=True,
    )
    if not result.get("success"):
        print(f"[ci-package] FAILED: {result.get('error')}", flush=True)
        return 1

    # ── Self-check: the package must be USABLE by the target, not merely built.
    # A Full-mode release whose backend image is missing — or baked under a tag
    # the target won't look for — is a package that silently forces the customer
    # box to rebuild the backend from source at convergence. That is exactly what
    # shipped in intact-20260721: the image was baked as `intact-backend:development`
    # while the box resolved `intact-backend:intact-20260721`, so the bundled image
    # was invisible. Nothing caught it until a real upgrade limped and hung.
    # Assert it here, in CI, where it costs nothing to fix.
    err = _verify_package_usable(result, args.tag)
    if err:
        print(f"[ci-package] SELF-CHECK FAILED: {err}", flush=True)
        return 1

    src = result["package_path"]
    os.makedirs(args.out, exist_ok=True)
    dest = os.path.join(args.out, f"intact-upgrade-{args.tag}.tar.gz")
    shutil.copy2(src, dest)
    man = src + ".manifest.json"
    if os.path.exists(man):
        shutil.copy2(man, dest + ".manifest.json")
    print(f"[ci-package] wrote {dest} "
          f"({os.path.getsize(dest) / (1024 * 1024):.1f} MB)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
