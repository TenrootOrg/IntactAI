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


def release_module_set(tag: str) -> dict:
    """{module: version} for every primary module the release ships (intact
    pinned to `tag`; cve_scan skipped as rolling data)."""
    import yaml
    from services.upgrade import UPGRADE_ORDER
    cfg_path = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"), "config.yaml")
    versions = (yaml.safe_load(open(cfg_path)) or {}).get("versions") or {}

    # TEMPORARY — velociraptor CI packaging is being debugged. Build ONLY the
    # module(s) in _ONLY_MODULES so each run is fast and isolates the failure,
    # instead of saving the whole ~5.5 GB fleet every iteration. To restore the
    # full package, set `_ONLY_MODULES = None` (or delete it + the guard below).
    _ONLY_MODULES = {"velociraptor"}

    modules = {}
    for m in UPGRADE_ORDER:
        if m == "cve_scan":
            continue  # rolling: fetched at apply time, not baked into a release
        if _ONLY_MODULES is not None and m not in _ONLY_MODULES:
            continue  # TEMPORARY velo-only restriction — see _ONLY_MODULES above
        if m == "intact":
            modules["intact"] = tag  # -> builds intact-backend:<tag>
        elif m in versions:
            modules[m] = versions[m]
    return modules


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
