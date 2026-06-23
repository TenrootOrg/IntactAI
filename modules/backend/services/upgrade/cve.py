#!/usr/bin/env python3
"""CVE Scan (NVD vulnerability matcher) upgrade functions.

CVE Scan has NO docker image and NO version pin: the scan engine runs
in-process inside the backend, and the CVE corpus is mirrored from the
community fkie-cad/nvd-json-data-feeds — always "latest" (upstream
publishes continuously and keeps the feed structure stable, so there's
no version to track). "Upgrading" cve_scan therefore means two things:

  1. Ensure ``modules.cve_scan`` exists + enabled in config.yaml so the
     sidebar item, routes, and the startup CVE-DB bootstrap are exposed.
  2. Refresh the local CVE database (`/app/data/cve_cache/cves.db`).

Online  -> download + reindex the latest year-feeds in place.
Offline -> install the prebuilt ``cves.db`` bundled in the package
           (air-gapped targets can't reach the upstream feeds).

The `version` parameter is accepted for dispatcher uniformity but ignored.
"""

import os
import shutil
from typing import Dict, Callable, Optional

from .base import ensure_module_enabled_in_config


def upgrade_cve(version: str = None, logger: Callable = None) -> Dict:
    """Enable cve_scan + refresh the local CVE DB from the latest feeds."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log("Starting CVE Scan upgrade (enable + refresh local CVE DB)...", "info")

    # 1. Enable in config.yaml (creates the block if the operator never had it).
    try:
        ensure_module_enabled_in_config('cve_scan', logger=log)
    except Exception as e:
        log(f"  config.yaml enable failed for cve_scan: {e}", "warning")

    # 2. Refresh the local CVE corpus to the latest upstream feeds. This is
    #    idempotent — a year is re-indexed only when its upstream timestamp
    #    changed — so on an existing install it's a quick delta.
    try:
        from services.cve_scan import local_db
        local_db.init_db()
        log("Downloading + indexing latest NVD CVE feeds (this can take a while "
            "on first run)...", "info")
        local_db.bulk_load(logger=log)
        stats = local_db.db_stats()
        log(f"CVE DB refreshed: {stats.get('cve_count')} CVEs "
            f"({stats.get('db_size_mb', 0):.0f} MB)", "success")
        return {"success": True, "version": "latest",
                "cve_count": stats.get('cve_count')}
    except Exception as e:
        # The enable already happened; a feed-refresh failure leaves any
        # pre-existing DB intact and is non-fatal — the module is usable and
        # the startup bootstrap / maintenance refresh retries later. Report
        # success so the upgrade run isn't marked MODULE_FAILED over a
        # transient network blip on data that's always re-fetchable.
        log(f"CVE DB refresh failed (module still enabled): {e}", "warning")
        return {"success": True, "version": "latest", "warning": str(e)}


def upgrade_cve_offline(package_dir: str, version: str = None,
                        logger: Callable = None,
                        run_id: Optional[str] = None) -> Dict:
    """Enable cve_scan + install the prebuilt cves.db bundled in the package."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    log("Starting CVE Scan offline upgrade...", "info")

    try:
        ensure_module_enabled_in_config('cve_scan', logger=log)
    except Exception as e:
        log(f"  config.yaml enable failed for cve_scan: {e}", "warning")

    # The bundle carries the prebuilt SQLite DB under cve/cves.db (only when
    # the operator ticked cve_scan at prepare time — see package.py).
    bundled_db = os.path.join(package_dir, 'cve', 'cves.db')
    if not os.path.exists(bundled_db):
        log(f"No bundled CVE database at {bundled_db} — cve_scan is enabled but "
            f"the local DB was not refreshed (package built without CVE data).",
            "warning")
        return {"success": True, "version": "latest", "warning": "no bundled cves.db"}

    try:
        from services.cve_scan import local_db
        dest = local_db._DEFAULT_DB
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        # Copy to a temp path then atomically rename, so a crash mid-copy
        # never leaves a truncated DB the backend would try to open. The
        # backend reopens the file on its next restart (offline applies end
        # with a backend restart), picking up the new corpus.
        tmp = f"{dest}.incoming"
        shutil.copy2(bundled_db, tmp)
        os.replace(tmp, dest)
        local_db.init_db()
        stats = local_db.db_stats()
        log(f"Installed bundled CVE DB: {stats.get('cve_count')} CVEs "
            f"({stats.get('db_size_mb', 0):.0f} MB)", "success")
        return {"success": True, "version": "latest",
                "cve_count": stats.get('cve_count')}
    except Exception as e:
        log(f"Failed to install bundled CVE DB: {e}", "error")
        return {"success": False, "error": str(e)}
