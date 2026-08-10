"""Velociraptor release-tag resolution and build-file refresh for the CI
packager. Moved from services/upgrade/velociraptor.py -- these two functions
have nothing to do with the RUNNING server; they help the packager fetch the
right upstream client binaries and bake the right server image.
"""

import os
import shutil
from typing import Callable, Optional

import requests

from .proc import WORKDIR


def resolve_velociraptor_release_tag(clean_version: str,
                                     logger: Callable = None) -> str:
    """Return the GitHub release tag that actually hosts this version's assets.

    Velocidex's naming shifted: releases up through the v0.76 line shipped
    several patch builds under one rolling tag (`v0.76`); from roughly v0.76.6
    each patch gets its own tag. HEAD-probe the full-version tag first
    (`v0.76.6`); fall back to the rolling tag (`v0.76`) only on a 404. HEAD, not
    the releases API: no rate limit, no token, one round trip.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}", flush=True))
    parts = clean_version.split('.')
    full_tag = f"v{clean_version}"
    minor_tag = f"v{parts[0]}.{parts[1]}" if len(parts) >= 2 else full_tag

    binary = f"velociraptor-v{clean_version}-linux-amd64"
    for candidate in (full_tag, minor_tag):
        url = (f"https://github.com/Velocidex/velociraptor/releases/download/"
               f"{candidate}/{binary}")
        try:
            r = requests.head(url, allow_redirects=False, timeout=10)
            if r.status_code in (200, 302):
                log(f"  Release tag resolved: {candidate} (probed {r.status_code})",
                    "info")
                return candidate
        except requests.RequestException:
            continue
    log(f"  Release tag probe failed for both {full_tag} and {minor_tag}; "
        f"defaulting to {minor_tag} -- the download will fail loudly.", "warning")
    return minor_tag


def refresh_velociraptor_build_files(src_velo_dir: str,
                                     dst_velo_dir: Optional[str] = None,
                                     logger: Optional[Callable] = None) -> bool:
    """Copy the Dockerfile, entrypoint, .dockerignore and the whole
    bundled_artifacts/ pack from `src_velo_dir` into the build context before
    the image is baked.

    Velociraptor is the only module whose image is BUILT (not pulled), and the
    bake reads whatever is on disk at build time. No-op (returns False) when
    `src_velo_dir` is absent -- caller falls back to on-disk files.
    """
    log = logger or (lambda m, l="info": None)
    dst = dst_velo_dir or os.path.join(WORKDIR, 'modules', 'velociraptor')
    if not src_velo_dir or not os.path.isdir(src_velo_dir):
        log(f"  No fresh velociraptor source at {src_velo_dir} -- baking from "
            f"on-disk build files", "warning")
        return False
    copied = []
    try:
        os.makedirs(dst, exist_ok=True)
        for fname in ('Dockerfile', 'entrypoint.sh', '.dockerignore'):
            s = os.path.join(src_velo_dir, fname)
            if os.path.isfile(s):
                shutil.copy2(s, os.path.join(dst, fname))
                copied.append(fname)
        src_bundle = os.path.join(src_velo_dir, 'bundled_artifacts')
        if os.path.isdir(src_bundle):
            dst_bundle = os.path.join(dst, 'bundled_artifacts')
            shutil.rmtree(dst_bundle, ignore_errors=True)
            shutil.copytree(src_bundle, dst_bundle)
            copied.append(f"bundled_artifacts/ ({len(os.listdir(src_bundle))} YAMLs)")
    except OSError as e:
        log(f"  Could not refresh velociraptor build files "
            f"({type(e).__name__}: {e})", "warning")
        return False
    log(f"  Refreshed velociraptor build files from source: "
        f"{', '.join(copied) or '(nothing)'}", "success")
    return True
