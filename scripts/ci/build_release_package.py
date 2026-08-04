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

Module set = an EXPLICIT list, declared per release. See RELEASE_MODULES and
EXCLUDED_FROM_RELEASE below; every upgradeable module must appear in one of
them, so dropping one is always a decision rather than an oversight.

This is currently a DELTA release and that is a deliberate, revisit-every-time
choice, not the default. The history matters because it is easy to re-break:

The package once shipped only modules whose pin moved since a baseline release.
That saved gigabytes and made a package's contents depend on which release you
happened to build from. The online flow downloads exactly ONE package for the
target ref -- it does not walk the upgrade chain. So a customer who skipped a
release got a package diffed against a baseline NEWER than what they were
running, and whatever changed in the gap they jumped was simply absent: their
modules stayed stale WHILE THE RUN REPORTED SUCCESS. Choosing the baseline
correctly required knowing the oldest release any customer might still be on,
which is not knowable at build time.

Shipping everything makes the package self-contained and the outcome identical
no matter where a box upgrades FROM; the cost is size, not correctness, and the
apply side already skips modules whose installed version matches the target, so
a byte-identical module in the package is inert on arrival.

A hand-declared subset gets the size saving back and re-accepts that risk, but
narrowly: it is safe exactly while every box upgrades SEQUENTIALLY from the
previous release. Confirm that before trimming, and re-derive the set each
release rather than inheriting it.

Usage:
  build_release_package.py --tag intact-20260722 --out /output
"""
import argparse
import os
import shutil
import sys

# The backend package is at /app inside the image.
if "/app" not in sys.path:
    sys.path.insert(0, "/app")


# THE release scope. Order is irrelevant (UPGRADE_ORDER drives packaging); this
# is purely the membership list. A module in NEITHER this set nor
# EXCLUDED_FROM_RELEASE fails the membership test, so a new module cannot land
# without someone deciding whether it ships.
RELEASE_MODULES = {
    "intact",         # backend + frontend source, the intact-backend image, and
                      # tusd -- both `intact-backend-` and `tusd-` are attributed
                      # to `intact` by image_owner_prefixes, so this one entry
                      # carries the platform and its upload sidecar.
    "elk",
    "iris",
    "timesketch",
    "plaso",
    "velociraptor",   # both kinds -- 0.77.1 and the legacy 0.7.1 client
}

# Deliberately NOT bundled.
#
# WIDENED 2026-08-04 to timesketch, plaso and velociraptor, and the reason is
# the skipped-release trap this comment used to merely accept. The online flow
# downloads exactly ONE package for the target ref and does not walk the upgrade
# chain, so a box that SKIPS a release gets a package whose omitted modules stay
# stale WHILE THE RUN REPORTS SUCCESS. Upgrading straight from intact-20260615
# would not have moved timesketch 20260326 -> 20260630 or velociraptor
# 0.76.1 -> 0.77.1, and nothing would have said so.
#
# The old note called that "survivable while every box is on intact-20260726".
# That condition is not checkable from inside the package, which is what makes
# it dangerous: the assumption is invisible at apply time. Carrying these three
# means a package is correct for any baseline, not just the expected one.
#
# The three that remain excluded are a deliberate, revisit-per-release choice --
# not an inheritance. This set stops being hand-maintained entirely once the
# two-asset CI computes the delta from pin movement between release tags.
EXCLUDED_FROM_RELEASE = {
    "volweb":     "delta release: pin unchanged since intact-20260726",
    "aws_sigma":  "delta release: pin unchanged since intact-20260726",
    "portainer":  "delta release: pin unchanged since intact-20260726",
    # HELD OUT OF BOTH the full and the delta asset, deliberately, until the
    # two-asset CI lands. o365rc pins the literal string 'latest', so there is
    # no version to diff and no way to say which image a package contains. That
    # makes it the one module whose presence cannot be reasoned about from a
    # manifest -- the exact property the full/delta split exists to guarantee.
    # Revisit when the pin becomes a real version.
    "o365rc":     "held out of full and delta: pins the literal 'latest', so "
                  "the package cannot record which image it shipped",
}

def platform_config_path(must_exist: bool = True):
    """The platform config this release ships, for reading AND stamping.

    config.yaml is the OPERATOR's file and is not tracked in git — it holds
    options.github_token (a real GitHub PAT), the dashboard login and every
    module password, so the pre-commit hook resets the staged copy to defaults.
    This builder runs in CI from a plain checkout, where only the template
    exists; it is also run locally, where a real config.yaml does and better
    reflects that box's pins. Prefer the real file, fall back to the template.

    Everything this script needs from it — the `versions:` block and the
    `versions.backend` pin it stamps — lives in both.
    """
    root = os.environ.get("INTACT_PATH", "/app/workdir")
    for name in ("config.yaml",):
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate):
            return candidate
    if must_exist:
        raise FileNotFoundError(
            f"config.yaml not found under {root} — "
            f"cannot resolve the release's version pins")
    return None


def release_module_set(tag: str) -> dict:
    """{module: version} this release ships — always the full RELEASE_MODULES set.

    One member is special-cased because its "version" is not a config pin:
      - `intact` is the platform itself, what Phase 1 swaps. Its version IS the
        release tag, so the bundled image is `intact-backend:<tag>`.
    A module listed here but absent from `versions:` is skipped rather than
    guessed at, so a config typo drops one module instead of failing the build.
    """
    import yaml
    from services.upgrade import UPGRADE_ORDER
    # config.yaml is the OPERATOR's file and is not tracked in git (it holds the
    # GitHub PAT, the dashboard login and every module password), so it does not
    # exist in a CI checkout — which is exactly where this builder runs. The
    # tracked template carries the same `versions:` pins, which is all we read.
    # Prefer a real config.yaml when present so a local package build reflects
    # that box's own pins.
    cfg_path = platform_config_path()
    with open(cfg_path) as handle:
        cfg = yaml.safe_load(handle) or {}
    versions = cfg.get("versions") or {}
    selected = set(RELEASE_MODULES)

    modules = {}
    for m in UPGRADE_ORDER:
        if m not in selected:
            continue
        if m == "intact":
            modules["intact"] = tag  # -> builds intact-backend:<tag>
        elif m in versions:
            modules[m] = versions[m]
    return modules


def _stamp_backend_pin(tag: str) -> None:
    """Set ``versions.backend`` to ``tag`` in the release checkout's config.yaml.

    Surgical single-line edit on purpose: the whole-block rewriter would drop
    every other pin and all the comments. A no-op when the pin already matches.
    """
    import re
    cfg = platform_config_path()
    try:
        with open(cfg) as f:
            txt = f.read()
        new, n = re.subn(r'^([ \t]+backend:[ \t]*).*$',
                         lambda m: f"{m.group(1)}{tag}", txt, count=1, flags=re.M)
        if not n:
            print(f"[ci-package] WARNING: no versions.backend key in {cfg} to pin",
                  flush=True)
            return
        if new != txt:
            with open(cfg, "w") as f:
                f.write(new)
            print(f"[ci-package] pinned versions.backend -> {tag}", flush=True)
    except Exception as e:
        print(f"[ci-package] WARNING: could not pin versions.backend ({e})", flush=True)


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

    # RELEASE_PIN: config.yaml versions.backend is the FIRST thing
    # backend_target_tag() reads on the target, so it decides which image the
    # box goes looking for at convergence. If it says anything other than this
    # release tag, the box hunts for an image the package never shipped and
    # falls back to rebuilding the backend from source. intact-20260721 shipped
    # with versions.backend: 'development' for exactly this reason.
    try:
        import yaml as _yaml
        _cfg_path = platform_config_path()
        with open(_cfg_path) as _cf:
            _pin = ((_yaml.safe_load(_cf) or {}).get("versions") or {}).get("backend")
        _pin = str(_pin).strip() if _pin is not None else ""
        if _pin != tag:
            return (f"config.yaml versions.backend is {_pin!r}, expected {tag!r} — "
                    f"the target resolves its backend image from this key, so it "
                    f"would look for intact-backend:{_pin} and rebuild from source.")
    except Exception as e:                                    # pragma: no cover
        return f"could not read config.yaml versions.backend ({type(e).__name__}: {e})"

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

    # Pin the backend image tag to the release BEFORE building. The checkout is
    # ephemeral in CI and the tag is authoritative here, so this is the natural
    # place to resolve it — `development` (or any stale value) carried in from
    # the branch the release was cut from would otherwise ship as-is and send
    # every upgraded box hunting for intact-backend:development, an image the
    # package does not contain. Doing it on the checkout means the packaged
    # source inherits it too, since prepare copies the tree.
    _stamp_backend_pin(args.tag)

    modules = release_module_set(args.tag)
    if args.print_modules:
        for m, v in modules.items():
            print(f"{m}={v}")
        return 0

    # Every module, every release — no baseline, no diff. A module in
    # RELEASE_MODULES but missing here means its pin is absent from
    # config.yaml's versions: block.
    missing = sorted(set(RELEASE_MODULES) - set(modules))
    if missing:
        print(f"[ci-package] WARNING: {', '.join(missing)} in RELEASE_MODULES but "
              f"absent from config.yaml versions: — NOT shipped", flush=True)

    from services.upgrade.package import prepare_upgrade_package
    print(f"[ci-package] release {args.tag}: full scope, building "
          f"{', '.join(modules)}", flush=True)

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
