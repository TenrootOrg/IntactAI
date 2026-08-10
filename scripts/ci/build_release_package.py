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

PER-MODULE ASSETS
-----------------
With `--module <name>` this builds ONE module's asset. CI runs it once per
module in a matrix; the box then downloads only what it needs.

The point is not the size saving, it is that a module asset is ABSOLUTE. It
says "this is elk 9.4.4" and nothing more. The scheme it replaces shipped a
DELTA -- "the modules whose pins moved since release X" -- and that relativity
was the whole problem: the online flow downloads exactly one artifact for the
target ref and does not walk the upgrade chain, so a customer who SKIPPED a
release got a package diffed against a baseline newer than the one they were
running, and everything that changed in the gap was simply absent WHILE THE RUN
REPORTED SUCCESS. Making that safe needed a recorded baseline and an apply-time
guard. An absolute asset needs neither: the box compares what it has against
what it wants and fetches the difference itself.

THE MERGE CONTRACT. Every module asset's tarball uses the SAME top-level
directory, `intact-upgrade-<tag>/`, so extracting N of them into one directory
yields exactly the single `package_dir` the apply side already expects. That is
what `--work-dir` is for, and it is not optional: without it the root is named
from a build timestamp and two assets extract into two sibling directories, of
which the apply side silently picks one (`base.py` subdirs[0]).

The file sets are disjoint by construction -- image tar names are unique per
module (volweb ships `volweb-postgres-*.tar` precisely so it cannot collide
with timesketch's `postgres-*.tar`), `source/` comes only from intact,
`binaries/` only from velociraptor, `migrations/` only from timesketch. The one
genuine collision is the root manifest, so each asset ALSO carries
`manifests/<module>.json` and the assembler merges those into the root
manifest.json at apply time.

Usage:
  build_release_package.py --tag intact-20260722 --out /output            # bundle
  build_release_package.py --tag intact-20260722 --module elk --out /out  # one module
  build_release_package.py --tag intact-20260722 --emit-matrix            # CI matrix
"""
import argparse
import os
import shutil
import sys

# The backend package is at /app inside the image (needed by packager/package.py's
# `from services.image_map import ...` and its guarded tools_download_service
# import -- see that file's docstring for why those stay backend imports).
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

# `packager/` is a sibling of this script (scripts/ci/packager/), which is
# already on sys.path[0] when this runs as `python3 .../build_release_package.py`
# -- no extra path manipulation needed for `from packager... import ...` below.


def _upgrade_order():
    """UPGRADE_ORDER, read from lib/upgrade/plan.sh -- the definition that
    actually drives the module loop. See packager/order.py's docstring for why
    parsing bash beats importing Python here: this used to fake a `services`
    package in sys.modules to dodge services/__init__.py's eager grpc import,
    which was fragile (grpc is nowhere near this question) and broke outright
    once services/upgrade/ -- what that stub was reaching for -- was deleted.
    """
    from packager.order import upgrade_order
    return upgrade_order()


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
    "volweb",
    "aws_sigma",
    "portainer",
}

# Deliberately NOT shipped.
#
# This list used to carry a size argument -- modules were held back because the
# release was a DELTA and their pins had not moved. That reasoning is gone:
# per-module assets mean a box downloads only what it needs regardless of how
# many exist, so holding a module back no longer saves anyone anything. It only
# means an air-gapped box CANNOT install that module at all, since there is no
# registry fallback.
#
# So the bar for exclusion is now: the module cannot be described by an asset.
# Exactly one qualifies.
EXCLUDED_FROM_RELEASE = {
    # o365rc pins the literal string 'latest'. There is no version for a
    # manifest to record and no way to tell which image an asset contains, which
    # defeats the property every other asset provides -- that its contents are
    # knowable from its metadata. Revisit the moment it gets a real pin.
    "o365rc":     "pins the literal 'latest', so an asset cannot record which "
                  "image it shipped",
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


def release_module_set(tag: str, only: str = None) -> dict:
    """{module: version} this release ships.

    `only` narrows it to a single module for a per-module asset build. The
    membership test still applies: a name in neither RELEASE_MODULES nor
    EXCLUDED_FROM_RELEASE is rejected rather than silently built, so a typo in
    the CI matrix fails the job instead of publishing an asset nobody expects.

    One member is special-cased because its "version" is not a config pin:
      - `intact` is the platform itself, what Phase 1 swaps. Its version IS the
        release tag, so the bundled image is `intact-backend:<tag>`.

    A module in RELEASE_MODULES but absent from `versions:` cannot be built --
    there is no pin to build. Callers decide what that means: `--module` and
    `--emit-matrix` treat it as fatal (see below and in main()), because both
    are release-planning operations and a forgotten pin would otherwise ship a
    release that is quietly one module short while every job reports success.
    A manual bundle build only warns, since a partial bundle is sometimes
    exactly what you asked for.
    """
    import yaml
    UPGRADE_ORDER = _upgrade_order()
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
    if only:
        if only in EXCLUDED_FROM_RELEASE:
            raise SystemExit(
                f"[ci-package] {only!r} is excluded from releases: "
                f"{EXCLUDED_FROM_RELEASE[only]}")
        if only not in selected:
            raise SystemExit(
                f"[ci-package] {only!r} is in neither RELEASE_MODULES nor "
                f"EXCLUDED_FROM_RELEASE — add it to one before building it")
        selected = {only}

    modules = {}
    for m in UPGRADE_ORDER:
        if m not in selected:
            continue
        if m == "intact":
            modules["intact"] = tag  # -> builds intact-backend:<tag>
        elif m in versions:
            modules[m] = versions[m]

    # A per-module build that resolves to nothing would produce a perfectly
    # valid, perfectly EMPTY asset: right filename, right merged root, zero
    # images, and a manifest whose `versions` block simply does not mention the
    # module. The box would extract it, find nothing to do for that module, and
    # report success. Fail here instead.
    if only and only not in modules:
        raise SystemExit(
            f"[ci-package] {only!r} has no pin under `versions:` in {cfg_path} "
            f"— there is nothing to build. Add the pin, or move it to "
            f"EXCLUDED_FROM_RELEASE.")
    return modules


def _git(*args, timeout: int = 120):
    """Run git with ownership checks relaxed.

    The builder runs as ROOT inside a container while the checkout is owned by
    the host/runner user, and modern git refuses that with "detected dubious
    ownership" -- exit 128, on every command. Caught by running the delta scope
    against a real clone: `git tag --list` failed, previous_release_tag()
    returned None, and the build quietly produced a FULL package under a
    delta's name. It fails safe, which is exactly what makes it dangerous: the
    delta would have degraded to full on every CI run and nothing would have
    said so.

    -c is used rather than `git config --global` so nothing is mutated outside
    this process.
    """
    import subprocess
    return subprocess.run(
        ["git", "-c", "safe.directory=*", *args],
        capture_output=True, text=True, timeout=timeout)


def commit_of(ref: str) -> str:
    """The commit ``ref`` resolves to right now, or '' if it cannot be read.

    Recorded in the manifest for both the release tag and the delta baseline,
    because a TAG IS NOT AN IDENTITY. intact-20260803 was rebuilt against a
    moved tag and the two packages were indistinguishable from the outside --
    same name, same manifest, different code. Diagnosing it took comparing a
    shipped tusd-v2.9.2 against a pinned v2.10.0. A commit makes the same
    question a glance.
    """
    try:
        res = _git("rev-list", "-n1", ref)
        return res.stdout.strip() if res.returncode == 0 else ""
    except Exception:
        return ""


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
        from packager.backend_mode import backend_full_mode
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
    ap.add_argument("--out", help="dir to copy the finished asset into")
    ap.add_argument("--module", help="build ONE module's asset instead of the "
                                     "whole bundle (per-module CI matrix)")
    ap.add_argument("--work-dir", help="build directory. Its BASENAME becomes the "
                                       "tarball's top-level dir, which is what "
                                       "lets N module assets extract into one "
                                       "merged package_dir. CI must pass "
                                       "/…/intact-upgrade-<tag>.")
    ap.add_argument("--commit", help="the commit this tag resolved to, decided "
                                     "ONCE by CI. Asserted rather than "
                                     "re-resolved, so a tag re-cut mid-matrix "
                                     "cannot produce divergent assets.")
    ap.add_argument("--print-modules", action="store_true",
                    help="print the resolved module set and exit (no build)")
    ap.add_argument("--emit-matrix", action="store_true",
                    help="print the module list as JSON for a CI build matrix "
                         "and exit")
    args = ap.parse_args()

    if args.emit_matrix:
        import json as _json
        resolved = release_module_set(args.tag)
        # THE RELEASE CONTRACT IS DECIDED HERE. Whatever this prints becomes the
        # build matrix, and whatever the matrix builds becomes the index, and
        # the index is what a box believes the release contains. So a module in
        # RELEASE_MODULES that has no pin must not simply fall out of the list:
        # every downstream job would be green, the index would be internally
        # coherent, and the release would just be one module short with nobody
        # ever saying so. That is the same silent-skip the delta scheme died
        # for, arriving through the config file instead of the baseline.
        missing = sorted(set(RELEASE_MODULES) - set(resolved))
        if missing:
            print(f"[ci-package] FAILED: {', '.join(missing)} in RELEASE_MODULES "
                  f"but absent from `versions:` in {platform_config_path()}. A "
                  f"release cannot ship a module it has no pin for, and dropping "
                  f"it silently is worse than failing. Add the pin, or move it "
                  f"to EXCLUDED_FROM_RELEASE.", flush=True)
            return 1
        print(_json.dumps(sorted(resolved)))
        return 0

    modules = release_module_set(args.tag, only=args.module)

    # Query modes answer and exit. They must not touch the checkout: CI calls
    # --emit-matrix and --print-modules to plan the build, and a query that
    # edits config.yaml as a side effect leaves a dirty tree behind and makes
    # "what would this build?" a question you cannot ask twice.
    if args.print_modules:
        for m, v in modules.items():
            print(f"{m}={v}")
        return 0

    if not args.out:
        ap.error("--out is required unless --print-modules/--emit-matrix")

    # Pin the backend image tag to the release BEFORE building. The checkout is
    # ephemeral in CI and the tag is authoritative here, so this is the natural
    # place to resolve it — `development` (or any stale value) carried in from
    # the branch the release was cut from would otherwise ship as-is and send
    # every upgraded box hunting for intact-backend:development, an image the
    # package does not contain. Doing it on the checkout means the packaged
    # source inherits it too, since prepare copies the tree.
    _stamp_backend_pin(args.tag)

    if not args.module:
        # Bundle build: a module in RELEASE_MODULES whose pin is missing from
        # config.yaml silently does not ship, so say so.
        missing = sorted(set(RELEASE_MODULES) - set(modules))
        if missing:
            print(f"[ci-package] WARNING: {', '.join(missing)} in RELEASE_MODULES "
                  f"but absent from config.yaml versions: — NOT shipped",
                  flush=True)

    # A TAG IS NOT AN IDENTITY. intact-20260803 was re-cut and moved
    # 6316e05 -> 25effd5, and the two packages were indistinguishable from
    # outside. In a matrix each job would resolve the tag independently, so a
    # re-cut mid-build could produce assets from two different commits that
    # nothing downstream could tell apart. CI resolves once and passes --commit;
    # this asserts rather than re-resolves.
    resolved = commit_of(args.tag)
    commit = args.commit or resolved
    if args.commit and resolved and args.commit != resolved:
        print(f"[ci-package] FAILED: --commit {args.commit[:12]} does not match "
              f"what {args.tag} resolves to here ({resolved[:12]}). The tag moved "
              f"mid-build; assets from two commits must never ship together.",
              flush=True)
        return 1

    from packager.package import prepare_upgrade_package
    scope = f"module {args.module}" if args.module else "bundle"
    print(f"[ci-package] release {args.tag} ({scope}) @ {commit[:12] or '?'}: "
          f"building {', '.join(modules)}", flush=True)

    # Provenance, recorded INSIDE the tarball rather than only in a sidecar --
    # a sidecar can be regenerated or replaced independently of the artifact it
    # claims to describe, and the apply side reads the manifest out of the
    # archive it is about to install.
    manifest_extra = {
        "package_kind": "module" if args.module else "bundle",
        "release_tag": args.tag,
        "source_commit": commit,
        "backend_pin": args.tag,      # what _stamp_backend_pin just wrote
    }
    if args.module:
        manifest_extra["module"] = args.module

    os.makedirs(args.out, exist_ok=True)

    result = prepare_upgrade_package(
        modules,
        run_id=f"ci_release_{args.tag}",
        logger=lambda m, l="info": print(f"[{l}] {m}", flush=True),
        compress=True,
        work_dir=args.work_dir,
        manifest_extra=manifest_extra,
        manifest_sidecar_name=(f"manifests/{args.module}.json"
                               if args.module else None),
        # Package the source we are already standing in. Prepare's default is
        # to fetch it from GitHub by ref, which on a box is the only option and
        # in CI is a hole: every other asset is built from the commit `resolve`
        # pinned, while a codeload fetch is by REF and would follow a tag that
        # moved mid-run. It also cannot work before the tag is pushed.
        source_dir=os.environ.get("INTACT_PATH") or None,
        source_commit=commit or None,
        # Write the archive straight into the output dir. The default is the
        # operator's persistent packages dir, which would mean building the
        # asset there and then copying it out -- two copies of several GB on a
        # runner, for nothing.
        packages_dir=args.out,
    )
    if not result.get("success"):
        print(f"[ci-package] FAILED: {result.get('error')}", flush=True)
        return 1

    # ── Self-check: the package must be USABLE by the target, not merely built.
    # A release whose backend image is missing — or baked under a tag the target
    # won't look for — silently forces the customer box to rebuild the backend
    # from source at convergence. That is exactly what shipped in
    # intact-20260721: the image was baked as `intact-backend:development` while
    # the box resolved `intact-backend:intact-20260721`, so the bundled image was
    # invisible. Nothing caught it until a real upgrade limped and hung.
    #
    # Only meaningful for the asset that CARRIES the backend. On an `elk` asset
    # both assertions are false by construction and would fail the build for the
    # wrong reason.
    if args.module in (None, "intact"):
        err = _verify_package_usable(result, args.tag)
        if err:
            print(f"[ci-package] SELF-CHECK FAILED: {err}", flush=True)
            return 1

    # MOVE, not copy. prepare wrote into args.out (see packages_dir above), so
    # this is a same-filesystem rename: instant, and no second copy of a
    # multi-GB asset. It also has to happen -- prepare names its output
    # intact-upgrade-latest.<ext>, and leaving that behind in the output dir
    # would give CI's asset glob two files to choose between.
    #
    # The extension is taken from what prepare ACTUALLY wrote rather than
    # hardcoded. _compress_with_progress stopped gzipping (the payload is
    # docker layers, already compressed at rest: measured 0.55% for a full
    # deflate pass over 5.4 GB), and this line still said ".tar.gz" -- which
    # would have published plain tars under a .tar.gz name. Green build,
    # mislabelled release, and every consumer that trusts the extension rather
    # than sniffing the magic bytes broken by a file that is not what it says.
    # Deriving it here means this stays correct whichever way that decision
    # goes, including if the outer gzip is ever restored.
    src = result["package_path"]
    _ext = ".tar.gz" if src.endswith(".tar.gz") else ".tar"
    name = (f"{args.tag}-{args.module}{_ext}" if args.module
            else f"intact-upgrade-{args.tag}{_ext}")
    dest = os.path.join(args.out, name)
    shutil.move(src, dest)
    man = src + ".manifest.json"
    if os.path.exists(man):
        shutil.move(man, dest + ".manifest.json")

    # A tiny sidecar so the index job can assert coherence across every asset
    # without downloading gigabytes of them.
    import hashlib as _hashlib
    import json as _json
    _h = _hashlib.sha256()
    with open(dest, "rb") as _f:
        for _chunk in iter(lambda: _f.read(4 * 1024 * 1024), b""):
            _h.update(_chunk)
    meta = {
        "asset": name,
        "module": args.module,
        "modules": modules,
        "release_tag": args.tag,
        "source_commit": commit,
        "backend_pin": args.tag,
        "size": os.path.getsize(dest),
        "sha256": _h.hexdigest(),
    }
    with open(dest + ".meta.json", "w") as _f:
        _json.dump(meta, _f, indent=2)

    print(f"[ci-package] wrote {dest} "
          f"({os.path.getsize(dest) / (1024 * 1024):.1f} MB)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
