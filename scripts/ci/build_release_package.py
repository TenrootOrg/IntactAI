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

Module set = the DIFF against the PREVIOUS packaged release (auto-resolved; see
_previous_release, override with `--since`): only modules whose pin actually
moved, plus `intact` (the platform itself, pinned to the release tag so the
backend image is `intact-backend:<tag>`). Shipping a module whose pin is
byte-identical costs gigabytes and buys nothing, since the apply side skips
same-version modules anyway.

A sidecar bump drags its parent module in: transitive pins like
`timesketch_opensearch` live only in `versions:` but their images are bundled
per MODULE, so matching the literal key would ship an opensearch CVE fix with
no timesketch to carry it. See _changed_since.

Usage:
  build_release_package.py --tag intact-20260722 --out /output
  build_release_package.py --tag intact-20260722 --out /output \\
      --since intact-20260615      # explicit baseline
  build_release_package.py --tag intact-20260722 --out /output \\
      --since ''                   # no diff: full fallback allowlist
"""
import argparse
import os
import shutil
import sys

# The backend package is at /app inside the image.
if "/app" not in sys.path:
    sys.path.insert(0, "/app")


# FALLBACK SCOPE — used only when --since is NOT given (an unanchored build,
# e.g. the very first release, where there is no baseline to diff against).
# The normal path is --since: see release_module_set().
RELEASE_MODULES = {
    "intact",         # backend + frontend (nginx) platform source + image
    "velociraptor",
    "aws_sigma",      # SigmaHQ AWS CloudTrail rule pack
    "timesketch",
    "plaso",
    "elk",
    "iris",
    "volweb",
    "portainer",
    # "o365rc",
}

# Shipped in EVERY release, diff or not — a version comparison structurally
# cannot tell whether these changed. See release_module_set().
ALWAYS_SHIP = {"intact"}

def _previous_release(tag: str) -> str:
    """The most recent published release BEFORE `tag`.

    Drafts are excluded (nobody can be running one); everything else counts.
    Deliberately NOT filtered to releases that shipped a package: a box can be
    running a release it installed from source via install.sh, and the diff
    only needs that release's config.yaml — which is readable from the tag
    whether or not a tarball was ever attached. An earlier draft of this
    function required package assets and picked NOTHING for intact-20260722,
    because intact-20260615 is a real published release with no assets; the
    build then silently fell back to shipping all ten modules.

    Release tags are `intact-YYYYMMDD`, which sorts lexicographically in date
    order, so string comparison is the ordering.

    Returns None when no earlier release exists (the first release ever),
    which the caller treats as "no diff — ship the full scope".

    CAVEAT, deliberately accepted: the online flow downloads ONE package for
    the target and does not walk the upgrade chain. So a customer who skips a
    release gets a package diffed against a baseline NEWER than what they are
    running, and whatever changed in the gap they jumped is not bundled —
    their modules stay stale while the run reports success. Diffing against
    the OLDEST supported release avoids that at the cost of larger packages;
    this build ships the operator's chosen trade-off. If release-skipping ever
    needs supporting, either switch the baseline or make the online flow apply
    each package in the chain.
    """
    import json
    import urllib.request
    from services.upgrade.resolver import GITHUB_REPO, _github_token

    req = urllib.request.Request(
        f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=100",
        headers={"Accept": "application/vnd.github.v3+json"})
    token = _github_token()
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        releases = json.load(resp)

    candidates = []
    for rel in releases:
        rtag = rel.get("tag_name") or ""
        if not rtag.startswith("intact-") or rel.get("draft"):
            continue
        if rtag >= tag:                      # itself, or anything newer
            continue
        candidates.append(rtag)
    return max(candidates) if candidates else None


# Version keys that belong to a module but do not carry its name as a prefix.
# Everything else follows the `<module>_<sidecar>` convention and is resolved
# automatically (timesketch_opensearch -> timesketch, volweb_redis -> volweb).
_PIN_OWNER = {
    "sigma_rules": "aws_sigma",   # the SIGMA rule pack IS the aws_sigma artifact
    "backend_tusd": "intact",     # tusd ships inside the platform stack
    "nginx": "intact",            # top-level reverse proxy, part of the platform
    "backend": "intact",          # the backend image tag IS intact's own pin
}


def _owning_module(pin: str, known_modules: set) -> str:
    """Which module a `versions:` key belongs to, or None if it owns nothing.

    Sidecar pins live ONLY in `versions:`, never in `modules:` — but bundling
    is decided per MODULE, so a sidecar bump has to drag its parent in or the
    new image never gets packaged.
    """
    if pin in known_modules:
        return pin
    if pin in _PIN_OWNER:
        return _PIN_OWNER[pin]
    for m in known_modules:
        if pin.startswith(f"{m}_"):
            return m
    return None


def _changed_since(since_ref: str, versions: dict, known_modules: set) -> set:
    """Modules to ship: those whose OWN pin moved, or any of whose sidecars did.

    A release only needs to carry what an operator on `since_ref` would
    actually have to change. Bundling a module whose pin is byte-identical
    costs gigabytes — elk and volweb alone dominate a full package — and buys
    nothing: the apply side skips same-version modules anyway.

    Sidecar attribution is load-bearing, not a nicety. Transitive pins
    (`timesketch_opensearch`, `iris_rabbitmq`, `volweb_postgres`,
    `velociraptor_legacy`, `sigma_rules`, ...) live only in `versions:`, and
    their images are bundled as part of their PARENT module. Matching on the
    literal key alone means a release that bumps ONLY a sidecar — say
    opensearch 2.11 -> 2.19 for a CVE — ships no timesketch, so the patched
    image never reaches the customer while the upgrade reports success. That
    is the same silent-skew class this codebase keeps getting bitten by, so it
    is covered by simulation tests rather than left to review.

    The baseline's config.yaml is fetched from GitHub rather than read from
    disk on purpose: the CI checkout is a single ref, and `git show <other-ref>`
    is not reliably available inside the build container (a worktree's .git is
    a file pointing outside the mount).

    Deliberately raises on a failed fetch. Falling back to "ship everything"
    would turn a network blip into a 6 GB package, and falling back to "ship
    nothing" would produce a package that upgrades the platform and quietly
    leaves every module behind. Fail the build loudly instead.
    """
    from services.upgrade.resolver import fetch_upstream_config
    base = (fetch_upstream_config(since_ref, user_action="ci-release-diff")
            or {}).get("versions") or {}
    ship = set()
    for pin, new_v in versions.items():
        if base.get(pin) == new_v:
            continue
        owner = _owning_module(pin, known_modules)
        if owner:
            ship.add(owner)
        else:
            # An unattributable pin is not silently dropped: a new sidecar
            # naming scheme would otherwise quietly stop reaching customers.
            print(f"[ci-package] WARNING: version pin {pin!r} changed but maps "
                  f"to no module — nothing will bundle it. Add it to "
                  f"_PIN_OWNER if it belongs to one.", flush=True)
    return ship


def release_module_set(tag: str, since_ref: str = None) -> dict:
    """{module: version} this release ships.

    With `since_ref`, the set is the DIFF against that release: only modules
    whose pin actually moved (plus brand-new ones) are bundled. Without it,
    falls back to the static RELEASE_MODULES allowlist.

    ALWAYS_SHIP members are added regardless of the diff, because a version
    comparison structurally cannot detect whether they changed:
      - `intact` is the platform itself — what Phase 1 swaps — and its
        "version" is the release tag, not a config pin.
    """
    import yaml
    from services.upgrade import UPGRADE_ORDER
    cfg_path = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"), "config.yaml")
    cfg = yaml.safe_load(open(cfg_path)) or {}
    versions = cfg.get("versions") or {}
    # `modules:` is the operator-facing module set; `versions:` also holds
    # sidecar pins, which is exactly what _owning_module has to resolve.
    known_modules = set(cfg.get("modules") or {}) | {"intact"}

    if since_ref:
        selected = _changed_since(since_ref, versions, known_modules) | ALWAYS_SHIP
    else:
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
    cfg = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"), "config.yaml")
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
        _cfg_path = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"),
                                 "config.yaml")
        _pin = ((_yaml.safe_load(open(_cfg_path)) or {}).get("versions") or {}).get("backend")
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
    ap.add_argument("--since", default=None, metavar="REF",
                    help="baseline release tag to diff against. Ship only modules "
                         "whose pin changed since it, plus intact. "
                         "Default: auto-resolve the most recent PREVIOUS release "
                         "that ships a package. Pass --since '' to disable "
                         "diffing and build the full fallback allowlist.")
    args = ap.parse_args()

    # Pin the backend image tag to the release BEFORE building. The checkout is
    # ephemeral in CI and the tag is authoritative here, so this is the natural
    # place to resolve it — `development` (or any stale value) carried in from
    # the branch the release was cut from would otherwise ship as-is and send
    # every upgraded box hunting for intact-backend:development, an image the
    # package does not contain. Doing it on the checkout means the packaged
    # source inherits it too, since prepare copies the tree.
    _stamp_backend_pin(args.tag)

    # `--since REF` -> explicit; `--since ''` -> opt out of diffing entirely;
    # unset -> auto-resolve the previous packaged release.
    if args.since is None:
        since_ref = _previous_release(args.tag)
        if since_ref:
            print(f"[ci-package] auto baseline: previous release {since_ref}", flush=True)
        else:
            print("[ci-package] no earlier release found — building the "
                  "FULL fallback scope", flush=True)
    else:
        since_ref = args.since or None
    modules = release_module_set(args.tag, since_ref=since_ref)
    if args.print_modules:
        for m, v in modules.items():
            print(f"{m}={v}")
        return 0

    from services.upgrade.package import prepare_upgrade_package
    if since_ref:
        print(f"[ci-package] diff scope vs {since_ref}: shipping "
              f"{', '.join(sorted(modules))}", flush=True)
    else:
        print("[ci-package] NO diff baseline — full fallback scope", flush=True)
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
