#!/usr/bin/env python3
"""RETIRED 2026-11-23: it would have wiped the artifact bundle. Do not bring it back.

It deleted every YAML in modules/velociraptor/bundled_artifacts, then exported only
the server's non-built-in artifacts. Since the bundle loads through --definitions,
all 846 artifacts count as built-in, so that export is nearly empty; and it ran
against the real checkout, mounted read-write at /app/workdir.

Every release now refreshes the bundle itself: scripts/ci/refresh_artifacts.py.
"""
import sys

if __name__ == "__main__":
    print(__doc__, file=sys.stderr)
    sys.exit(2)
