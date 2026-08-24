#!/usr/bin/env python3
"""Merge a release's per-module assets into ONE file.

    python3 scripts/make_single_package.py --tag intact-20260804
    python3 scripts/make_single_package.py --tag intact-20260804 --from-dir data/tmp/install-pkg/
    python3 scripts/make_single_package.py --tag intact-20260804 --modules intact,elk,iris

Releases ship one asset per module plus an index. That is right for the
common case -- a box downloads only what it needs, in parallel -- but wrong
for the one case it cannot serve: carrying a release through an air gap by
hand, where nine files and an index is nine chances to copy the wrong set,
and where "did I get all of them?" has no good answer at the far end. This
produces the single file that case wants, and `install.sh --package <file>`
takes it directly.

WHAT IT IS NOT: a second build. Nothing is rebuilt, re-pulled or
re-compressed from source -- the module assets ARE the inputs, so the output
is content-identical to them by construction. `build_release_package.py`
without --module also emits a single file, but by building everything from
scratch (docker socket, registry access, ~90 min). Use that to CREATE a
release; use this to RESHAPE one that already exists.

THE MODULE LIST COMES FROM THE INDEX, never a hardcoded set. A release that
adds a tenth module is picked up with no change here -- that is the whole
point of the index being the contract.

Reuses the on-box machinery rather than reimplementing it:
  * download.py:find_release_index / download_release_assets -- parallel
    fetch, Range-resume, and the sha256 check against the index.
  * base.py:assemble_manifest -- the union-with-ABORT-on-conflict merge.
    Deliberately NOT a fresh hash walk of the merged tree: re-hashing what
    is on disk would launder a silent tar overwrite into a self-consistent
    manifest that verifies perfectly. See that function's docstring.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

# The backend package is importable straight from a checkout; only
# services.upgrade is needed and it reads nothing but config.yaml + the
# filesystem. Mirrors the sys.path/stub dance in scripts/ci/build_release_package.py.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO, "modules", "backend"))


def _import_upgrade_bits():
    """Import the two helpers we reuse, without dragging in the rest of the
    backend's service graph (which wants a database, a docker socket, ...).

    services/__init__.py is stubbed the same way build_release_package.py does
    it, and stdout is captured during the import because the storage layer
    prints banners on load -- this script's stdout is meant to be readable.
    """
    import io
    import types

    if "services" not in sys.modules:
        real = os.path.join(_REPO, "modules", "backend", "services")
        if not os.path.isfile(os.path.join(real, "upgrade", "__init__.py")):
            raise RuntimeError(
                f"cannot find services/upgrade under {real} -- run this from a "
                f"checkout, or set INTACT_PATH")
        stub = types.ModuleType("services")
        stub.__path__ = [real]
        sys.modules["services"] = stub

    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        from services.upgrade.base import assemble_manifest
        from services.upgrade.download import (find_release_index,
                                               download_release_assets)
    finally:
        sys.stdout = old
    return assemble_manifest, find_release_index, download_release_assets


def _log(msg, level="info"):
    print(f"[{level}] {msg}", flush=True)


def _human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024


def _assets_from_dir(src_dir, tag):
    """Per-module asset paths already on disk, plus a reassembled copy of any
    that arrived split into .part-NN pieces."""
    found = sorted(glob.glob(os.path.join(src_dir, f"{tag}-*.tar.gz")))
    parts = sorted(glob.glob(os.path.join(src_dir, f"{tag}-*.tar.gz.part-00")))
    for first in parts:
        whole = first[: -len(".part-00")]
        if os.path.exists(whole):
            continue
        pieces = sorted(glob.glob(whole + ".part-*"))
        _log(f"  Reassembling {os.path.basename(whole)} from {len(pieces)} part(s)")
        with open(whole, "wb") as out:
            for p in pieces:
                with open(p, "rb") as chunk:
                    shutil.copyfileobj(chunk, out, 8 * 1024 * 1024)
        found.append(whole)
    return sorted(set(found))


def main():
    ap = argparse.ArgumentParser(
        description="Merge a release's per-module assets into one file.")
    ap.add_argument("--tag", required=True,
                    help="release tag, e.g. intact-20260804")
    ap.add_argument("--out", default=".",
                    help="directory to write the merged package into (default: cwd)")
    ap.add_argument("--from-dir",
                    help="use per-module assets already in this directory instead "
                         "of downloading them (e.g. data/tmp/install-pkg/). Saves "
                         "re-fetching several GB.")
    ap.add_argument("--modules",
                    help="comma-separated subset to include. Default is every "
                         "module the release's index lists. A subset produces a "
                         "package that CANNOT install a box from scratch -- it is "
                         "for topping up an existing one.")
    ap.add_argument("--keep-work", action="store_true",
                    help="leave the extracted tree in place for inspection")
    args = ap.parse_args()

    tag = args.tag
    if not tag.startswith("intact-"):
        _log(f"{tag!r} is not an intact-* release tag", "error")
        return 2

    assemble_manifest, find_release_index, download_release_assets = \
        _import_upgrade_bits()

    os.makedirs(args.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix=f"intact-single-{tag}-", dir=args.out)
    dl_dir = os.path.join(work, "assets")
    extract_dir = os.path.join(work, "merged")
    os.makedirs(dl_dir, exist_ok=True)
    os.makedirs(extract_dir, exist_ok=True)

    try:
        # ---- 1. Which modules, and where are their assets -----------------
        if args.from_dir:
            assets = _assets_from_dir(args.from_dir, tag)
            if not assets:
                _log(f"no {tag}-*.tar.gz assets in {args.from_dir}", "error")
                return 1
            _log(f"Using {len(assets)} asset(s) already in {args.from_dir}")
            # The index is the module list, but a local dir may not have it and
            # an air-gapped operator may not be able to fetch it. The filenames
            # carry the same information, so fall back to them rather than fail.
            index = find_release_index(tag, logger=_log)
        else:
            index = find_release_index(tag, logger=_log)
            if not index:
                _log(f"release {tag} publishes no index ({tag}.index.json), so the "
                     f"module set is unknown. Use --from-dir with the assets you "
                     f"already have.", "error")
                return 1
            wanted = sorted((index.get("assets") or {}).keys())
            if args.modules:
                asked = [m.strip() for m in args.modules.split(",") if m.strip()]
                missing = sorted(set(asked) - set(wanted))
                if missing:
                    _log(f"release {tag} has no asset for: {', '.join(missing)}. "
                         f"It carries: {', '.join(wanted)}", "error")
                    return 1
                wanted = asked
            _log(f"Release {tag} carries {len(wanted)} module(s): {', '.join(wanted)}")
            assets, _idx = download_release_assets(tag, wanted, dl_dir, logger=_log)
            if not assets:
                _log("no assets downloaded", "error")
                return 1

        if args.modules and args.from_dir:
            asked = {m.strip() for m in args.modules.split(",") if m.strip()}
            assets = [a for a in assets
                      if os.path.basename(a)[len(tag) + 1:-len(".tar.gz")] in asked]

        # ---- 2. Extract them all into ONE directory -----------------------
        # Every module asset's tarball uses the same top-level directory name,
        # so extracting them into one place merges them by construction -- this
        # is the same contract install.sh and the on-box assembler rely on.
        _log(f"Extracting {len(assets)} asset(s)...")
        for i, a in enumerate(sorted(assets), 1):
            _log(f"  [{i}/{len(assets)}] {os.path.basename(a)} "
                 f"({_human(os.path.getsize(a))})")
            with tarfile.open(a, "r:gz") as tf:
                tf.extractall(extract_dir)

        roots = [d for d in os.listdir(extract_dir)
                 if os.path.isdir(os.path.join(extract_dir, d))]
        if len(roots) != 1:
            _log(f"the assets did not merge -- got {len(roots)} top-level "
                 f"directories ({', '.join(sorted(roots))}). They are not from "
                 f"the same release, or were built without a shared --work-dir.",
                 "error")
            return 1
        root = os.path.join(extract_dir, roots[0])

        # ---- 3. Merge the per-module manifests ----------------------------
        sidecars = sorted(glob.glob(os.path.join(root, "manifests", "*.json")))
        if not sidecars:
            _log(f"no manifests/*.json in the merged tree -- these do not look "
                 f"like per-module assets. A single bundle is already one file; "
                 f"nothing to do.", "error")
            return 1
        per_module = {}
        for s in sidecars:
            with open(s) as fh:
                per_module[os.path.splitext(os.path.basename(s))[0]] = json.load(fh)
        _log(f"Merging {len(per_module)} manifest(s): {', '.join(sorted(per_module))}")
        # Raises on any same-key/different-value disagreement -- that means the
        # assets were not built from the same commit, and merging them would
        # produce something nobody built. Caught so the operator gets the one
        # line that matters instead of a traceback; the condition is a mixed
        # asset set, which is a thing to fix, not a bug to report.
        try:
            merged = assemble_manifest(per_module, logger=_log)
        except ValueError as e:
            _log(str(e), "error")
            _log("", "error")
            _log("The assets in this set were not all built from the same "
                 "release. Re-fetch them for a single tag -- do not mix "
                 "directories from two releases.", "error")
            return 1
        with open(os.path.join(root, "manifest.json"), "w") as fh:
            json.dump(merged, fh, indent=2)

        # ---- 4. Repack ----------------------------------------------------
        out_path = os.path.abspath(
            os.path.join(args.out, f"{tag}-package.tar.gz"))
        _log(f"Repacking into {out_path} (this takes a few minutes)...")
        # Via the tar CLI, not tarfile: it streams through gzip in a separate
        # process and is markedly faster on a multi-GB tree.
        rc = subprocess.run(
            ["tar", "-czf", out_path, "-C", extract_dir, roots[0]],
            stderr=subprocess.PIPE, text=True)
        if rc.returncode != 0:
            _log(f"tar failed: {rc.stderr[:400]}", "error")
            return 1

        size = os.path.getsize(out_path)
        _log(f"Wrote {out_path} ({_human(size)})", "success")
        _log(f"  modules : {', '.join(sorted(per_module))}")
        _log(f"  images  : {len((merged.get('contents') or {}).get('images') or [])}")
        _log("")
        _log("Install from it with:")
        _log(f"    sudo bash install.sh --package {out_path}")
        if args.modules:
            _log("")
            _log("NOTE: this is a SUBSET package. An install has no baseline to "
                 "compare against, so it needs the complete module set -- this "
                 "file can only top up a box that is already installed.", "warning")
        return 0

    finally:
        if args.keep_work:
            _log(f"Left working tree at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
