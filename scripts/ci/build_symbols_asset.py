#!/usr/bin/env python3
"""Build the release's VolWeb symbols asset: <tag>-volweb_symbols.tar.

The Volatility symbol packs ride in their OWN release asset, not inside the
volweb module's (2026-10-06: "maybe we should pack it out of the volweb and
insert it from the outside so we wont pass the limit"). With the kernel pack the
volweb asset had grown past GitHub's 2 GiB per-file limit; on its own the volweb
asset is ~650 MB again, and the packs are fetched by an upgrade only when one of
them changed -- independent of VolWeb's version.

Layout -- the same tree every module asset uses, so install and upgrade extract
it into the one package root and find the packs where they always did:

    intact-upgrade-<tag>/volweb_symbols/windows.zip
    intact-upgrade-<tag>/volweb_symbols/intact-windows-kernels.zip

Writes <tag>-volweb_symbols.tar and <tag>-volweb_symbols.tar.meta.json ({asset, sha256, size,
parts, files: {name: sha256}, tables: {name: count}}); the release index carries
the meta as index["volweb_symbols"], outside index["assets"], so the module machinery
(--only, the version plan, completeness) never sees it.

    python3 scripts/ci/build_symbols_asset.py --tag intact-20261101 --out out \\
        --pack windows.zip --pack kernel-pack/intact-windows-kernels.zip
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tables(path: str) -> int:
    """Windows tables in a Volatility symbol pack; 0 for anything else."""
    try:
        with zipfile.ZipFile(path) as z:
            return sum(1 for n in z.namelist() if n.startswith("windows/") and n.endswith((".json.xz", ".json")))
    except (zipfile.BadZipFile, OSError):
        return 0


def build(tag: str, packs: list[str], out_dir: str) -> dict:
    files, counts = {}, {}
    for p in packs:
        n = tables(p)
        if not n:
            raise SystemExit(f"symbols asset: {p} is not a Volatility symbol pack (no windows/ tables)")
        files[os.path.basename(p)], counts[os.path.basename(p)] = _sha256(p), n
    os.makedirs(out_dir, exist_ok=True)
    asset = f"{tag}-volweb_symbols.tar"
    dest = os.path.join(out_dir, asset)
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, f"intact-upgrade-{tag}", "volweb_symbols")
        os.makedirs(root)
        for p in packs:
            shutil.copyfile(p, os.path.join(root, os.path.basename(p)))
        # .tar, not .tar.gz: the zips inside are already compressed, and every
        # module asset has been a plain .tar since 20260805.
        with tarfile.open(dest + ".tmp", "w") as t:
            t.add(os.path.join(tmp, f"intact-upgrade-{tag}"), arcname=f"intact-upgrade-{tag}")
    os.replace(dest + ".tmp", dest)
    meta = {"asset": asset, "sha256": _sha256(dest), "size": os.path.getsize(dest), "parts": [],
            "files": files, "tables": counts}
    with open(dest + ".meta.json", "w") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    return meta


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pack", action="append", required=True, help="a symbol pack zip; repeat")
    a = ap.parse_args(argv)
    m = build(a.tag, a.pack, a.out)
    print(f"symbols asset: {m['asset']} ({m['size'] / 1048576:.0f} MB) "
          + ", ".join(f"{n}: {c:,} tables" for n, c in m["tables"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
