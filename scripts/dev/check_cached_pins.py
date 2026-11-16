#!/usr/bin/env python3
"""DEV-ONLY. Used by scripts/dev/build_local_release.sh.

Usage: check_cached_pins.py <index.json> <config.yaml> <modules_csv>

Prints one line per module whose asset in a cached release bundle is not at
the checkout's config.yaml `versions:` pin, and exits 3 if there are any.
Checks the modules in modules_csv plus every module asset the index carries
(except `intact`, which build_local_release.sh rebuilds from source anyway).

Why: install.sh never pulls images, so a package built from a PUBLISHED
release's assets carries that release's images. When dev pins newer ones, an
offline install dies with "No such image: ...:9.5.6" (2026-11-16, elk/
portainer/plaso/presidio).
"""
import json
import sys

import yaml

index_path, config_path, modules_csv = sys.argv[1:4]
assets = json.load(open(index_path)).get("assets") or {}
pins = (yaml.safe_load(open(config_path)) or {}).get("versions") or {}

wanted = {m.strip() for m in modules_csv.split(",") if m.strip()} | set(assets)
drift = []
for m in sorted(wanted - {"intact"}):
    if m not in pins:
        continue
    have = (assets.get(m) or {}).get("version")
    if have is None:
        drift.append(f"{m}: not in the cached bundle (config.yaml pins {pins[m]})")
    elif str(have) != str(pins[m]):
        drift.append(f"{m}: cached {have}, config.yaml pins {pins[m]}")
print("\n".join(drift))
sys.exit(3 if drift else 0)
