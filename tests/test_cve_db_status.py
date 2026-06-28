"""Tests for local_db.has_cves() — the CVE Scan install signal.

CVE Scan has no container; "installed/ready" means its local NVD database holds
CVEs. has_cves() is the cheap boolean the /api/system/containers status uses for
cve_scan, so the dashboard/sidebar reflect whether the DB is populated rather
than just the config flag.

Run:  docker exec intact_backend python /app/workdir/tests/test_cve_db_status.py
"""

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.cve_scan.local_db import has_cves   # noqa: E402


def _tmpdb():
    return Path(os.path.join(tempfile.mkdtemp(prefix="cvedb_"), "cves.db"))


def _make(rows=(), table="cve"):
    p = _tmpdb()
    con = sqlite3.connect(str(p))
    con.execute(f"CREATE TABLE {table} (id TEXT)")
    con.executemany(f"INSERT INTO {table} VALUES (?)", [(r,) for r in rows])
    con.commit(); con.close()
    return p


def test_missing_db_is_false():
    assert has_cves(_tmpdb()) is False   # file doesn't exist


def test_empty_cve_table_is_false():
    assert has_cves(_make(rows=())) is False


def test_populated_cve_table_is_true():
    assert has_cves(_make(rows=["CVE-2024-0001", "CVE-2024-0002"])) is True


def test_db_without_cve_table_is_false():
    # a db that exists but has no `cve` table -> not ready (and must not raise)
    assert has_cves(_make(rows=["x"], table="other")) is False


def test_single_row_is_enough():
    assert has_cves(_make(rows=["CVE-1999-0001"])) is True


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
