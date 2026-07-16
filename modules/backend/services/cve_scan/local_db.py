"""Local CVE database — replaces the per-product NVD REST calls with
an in-process SQLite index.

The pipeline used to do one HTTPS round-trip per (product, version)
pair at scan time. For a 946-pair enterprise hunt that meant 800-1300
NVD calls, bottlenecked by the 50 req/30s rate cap, per-call response
size for popular CPEs (Chrome with ~4k CVEs = multi-MB JSON), and
hang-prone urlopen calls. 1000-product scans took 10-30 minutes and
occasionally wedged entirely.

This module mirrors the full NVD CVE corpus once via the community
[fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds)
project (per-year XZ-compressed JSON files refreshed every 2 h from
NVD's API). Lookups at scan time become indexed SQLite queries —
sub-millisecond, deterministic, can't hang.

The matching semantics (`cpe_matches_version`, version-range gating,
magnitude sanity check) live in `nvd.py` and are reused as-is; this
module only changes the source of the cpeMatch rows from "parse a
fetched HTTPS response" to "read SELECT from SQLite."

Public API:
    init_db(path=None)                       # idempotent, called at import
    bulk_load(force=False, log=None)         # download + index full feed
    search_by_cpe(vendor, product) -> rows   # all cpeMatches for that CPE
    db_stats() -> {entries, last_modified, db_size_mb}
"""
from __future__ import annotations

import datetime
import json
import lzma
import os
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


_DEFAULT_DIR = Path("/app/data/cve_cache")
_DEFAULT_DB = _DEFAULT_DIR / "cves.db"
_FEED_URL_TMPL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
)

# NVD CVEs go back to 1999; the upstream project tracks the same range.
_OLDEST_YEAR = 1999

_init_lock = threading.Lock()
_initialized = False

# Per-thread SQLite connection cache. Without this, a 64-worker scan
# opens 64+ connections in parallel and blows past the container's
# file-descriptor limit (we hit [Errno 24] Too many open files in
# testing). Each thread reuses one read-only connection for the life
# of the request. WAL mode (set in bulk_load) handles concurrent
# readers natively.
_thread_local = threading.local()


def _get_thread_conn(db_path: Path) -> sqlite3.Connection:
    """Return this thread's SQLite connection, creating it on first
    use. Read-uncommitted isolation + WAL gives us cheap concurrent
    reads."""
    conn = getattr(_thread_local, "conn", None)
    if conn is None or getattr(_thread_local, "db_path", None) != str(db_path):
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro",
            uri=True,
            check_same_thread=False,
            timeout=10,
        )
        conn.row_factory = sqlite3.Row
        _thread_local.conn = conn
        _thread_local.db_path = str(db_path)
    return conn


def init_db(path: Optional[Path] = None) -> None:
    """Create the schema if missing. Idempotent — safe to call on
    every process start."""
    global _initialized
    with _init_lock:
        if _initialized:
            return
        p = path or _DEFAULT_DB
        p.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(p)) as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS cve (
                    cve_id        TEXT PRIMARY KEY,
                    cvss_score    REAL,
                    severity      TEXT,
                    last_modified TEXT
                );
                CREATE TABLE IF NOT EXISTS cpe_match (
                    cve_id              TEXT,
                    vendor              TEXT,
                    product             TEXT,
                    cpe_version         TEXT,
                    version_start       TEXT,
                    version_start_incl  INTEGER,
                    version_end         TEXT,
                    version_end_incl    INTEGER,
                    vulnerable          INTEGER
                );
                CREATE INDEX IF NOT EXISTS cpe_match_vp
                    ON cpe_match(vendor, product);
                CREATE TABLE IF NOT EXISTS feed_meta (
                    year       INTEGER PRIMARY KEY,
                    timestamp  TEXT,
                    cve_count  INTEGER
                );
            """)
            con.commit()
        _initialized = True


def _log(logger: Optional[Callable], msg: str, level: str = "info") -> None:
    """Forgiving log wrapper — accepts add_log_to_run-style (msg, level)
    callables OR plain print-style ones; falls back to stdout."""
    if logger:
        try:
            logger(msg, level)
            return
        except TypeError:
            try:
                logger(msg)
                return
            except Exception:
                pass
    print(msg, flush=True)


def _extract_cvss(metrics: Dict[str, Any]) -> Tuple[float, str]:
    """Pick the best available CVSS triple (score, severity) following
    the same v4 > v3.1 > v3.0 > v2 priority used by services/cve_scan/nvd.py."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get("cvssData") or {}
            score = d.get("baseScore")
            sev = (d.get("baseSeverity") or "").title()
            if score is not None:
                return float(score), sev
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        d = arr[0].get("cvssData") or {}
        score = d.get("baseScore")
        if score is not None:
            try:
                s = float(score)
            except Exception:
                s = 0.0
            sev = "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else ""
            return s, sev
    return 0.0, ""


def _parse_cpe_criteria(criteria: str) -> Tuple[str, str, str]:
    """`cpe:2.3:a:vendor:product:version:...` → (vendor, product, version).
    Returns ('', '', '') on malformed input."""
    if not criteria:
        return "", "", ""
    parts = criteria.split(":")
    if len(parts) < 6:
        return "", "", ""
    vendor = parts[3] or ""
    product = parts[4] or ""
    version = parts[5] or "*"
    return vendor, product, version


def _index_year_file(con: sqlite3.Connection, year: int, payload: bytes,
                     logger: Optional[Callable] = None) -> Tuple[int, int]:
    """Parse one decompressed feed file's JSON and INSERT its CVEs.
    Existing rows for the same CVE-IDs are replaced (last-modified
    overwrites). Returns (cves_indexed, cpe_matches_indexed)."""
    data = json.loads(payload)
    items = data.get("cve_items") or data.get("vulnerabilities") or []

    cve_rows: List[Tuple] = []
    match_rows: List[Tuple] = []
    cve_ids_seen: List[str] = []

    for item in items:
        # The feed wraps the CVE directly at top level (`id` is on the
        # item), unlike the REST API which nests under `cve.id`. Handle
        # both shapes defensively.
        cve = item.get("cve") if "cve" in item and isinstance(item.get("cve"), dict) else item
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cve_ids_seen.append(cve_id)
        score, sev = _extract_cvss(cve.get("metrics") or {})
        cve_rows.append((cve_id, score, sev, cve.get("lastModified") or ""))

        for cfg in cve.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    vendor, product, ver = _parse_cpe_criteria(m.get("criteria") or "")
                    if not (vendor and product):
                        continue
                    vstart = m.get("versionStartIncluding") or m.get("versionStartExcluding") or ""
                    vstart_incl = 1 if "versionStartIncluding" in m else 0
                    vend = m.get("versionEndIncluding") or m.get("versionEndExcluding") or ""
                    vend_incl = 1 if "versionEndIncluding" in m else 0
                    match_rows.append((
                        cve_id, vendor, product, ver,
                        vstart, vstart_incl, vend, vend_incl,
                        1 if m.get("vulnerable", True) else 0,
                    ))

    # Replace existing rows for any CVE we're re-indexing, then bulk-insert.
    if cve_ids_seen:
        placeholders = ",".join(["?"] * len(cve_ids_seen))
        con.execute(f"DELETE FROM cve WHERE cve_id IN ({placeholders})", cve_ids_seen)
        con.execute(f"DELETE FROM cpe_match WHERE cve_id IN ({placeholders})", cve_ids_seen)
    con.executemany("INSERT INTO cve VALUES (?, ?, ?, ?)", cve_rows)
    con.executemany("INSERT INTO cpe_match VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", match_rows)
    con.execute(
        "INSERT OR REPLACE INTO feed_meta VALUES (?, ?, ?)",
        (year, data.get("timestamp") or "", data.get("cve_count") or len(cve_rows)),
    )
    con.commit()
    return len(cve_rows), len(match_rows)


def _fetch_year(year: int, logger: Optional[Callable] = None,
                timeout: int = 120) -> Optional[bytes]:
    """Download one year's XZ-compressed feed file. Returns the
    decompressed JSON bytes, or None on error (logged but not raised
    so a single year miss doesn't abort the full load)."""
    url = _FEED_URL_TMPL.format(year=year)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "intact-cve-scan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            compressed = r.read()
        return lzma.decompress(compressed)
    except Exception as e:
        _log(logger, f"[LOCAL_DB] {year}: download/decompress failed ({e}); skipping", "warning")
        return None


def bulk_load(force: bool = False, logger: Optional[Callable] = None,
              path: Optional[Path] = None,
              start_year: int = _OLDEST_YEAR,
              end_year: Optional[int] = None) -> Dict[str, Any]:
    """Download + index every available year-feed. Idempotent in the
    sense that a year is re-indexed only when its upstream `timestamp`
    is newer than the row in `feed_meta` (or `force=True`).

    Initial run from an empty DB: downloads ~28 yearly files
    (~50 MB total compressed), takes ~10-30 min depending on parse
    time. Incremental run: typically only a handful of files differ
    (the current year + occasional backfill of older CVEs), takes a
    couple of minutes.

    Returns {ok, years_processed, cves_indexed, matches_indexed,
    elapsed_seconds}."""
    init_db(path)
    db = path or _DEFAULT_DB
    end = end_year or datetime.datetime.utcnow().year

    started = time.time()
    years_done = 0
    total_cves = 0
    total_matches = 0

    # Snapshot existing feed_meta timestamps so we can skip year-files
    # whose upstream timestamp hasn't moved.
    with sqlite3.connect(str(db)) as con:
        rows = list(con.execute("SELECT year, timestamp FROM feed_meta"))
    existing_ts = {y: ts for y, ts in rows}

    _log(logger, f"[LOCAL_DB] Starting bulk_load (force={force}, years {start_year}–{end})", "info")
    for year in range(start_year, end + 1):
        payload = _fetch_year(year, logger=logger)
        if payload is None:
            continue
        # Peek timestamp to decide if we need to re-index.
        try:
            head = json.loads(payload[:8192].decode("utf-8", errors="ignore").rsplit('},', 1)[0] + '}')
            ts = head.get("timestamp", "")
        except Exception:
            ts = ""
        if not force and ts and existing_ts.get(year) == ts:
            _log(logger, f"[LOCAL_DB] {year}: unchanged (timestamp {ts}); skipping", "info")
            years_done += 1
            continue
        with sqlite3.connect(str(db)) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            n_cve, n_match = _index_year_file(con, year, payload, logger=logger)
        total_cves += n_cve
        total_matches += n_match
        years_done += 1
        _log(logger, f"[LOCAL_DB] {year}: indexed {n_cve} CVEs / {n_match} cpe matches", "info")

    elapsed = time.time() - started
    stats = db_stats(path)
    _log(
        logger,
        f"[LOCAL_DB] bulk_load done — {years_done} years processed, "
        f"{total_cves} CVEs / {total_matches} matches re-indexed, "
        f"DB now has {stats['cve_count']} CVEs ({stats['db_size_mb']:.0f} MB) "
        f"in {elapsed:.1f}s",
        "success",
    )
    return {
        "ok": True,
        "years_processed": years_done,
        "cves_indexed": total_cves,
        "matches_indexed": total_matches,
        "elapsed_seconds": elapsed,
        **stats,
    }


def search_by_cpe(vendor: str, product: str,
                  path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return every `cpe_match` row that targets the given vendor:product,
    each enriched with its CVE's score+severity. Shape mirrors the
    cpeMatch entries that `_scan`/`cpe_matches_version` already consume,
    so it can be fed straight back into the existing matching logic.

    Empty list when nothing matches OR when the DB hasn't been loaded
    yet — caller decides whether to fall back to REST."""
    if not (vendor and product):
        return []
    init_db(path)
    db = path or _DEFAULT_DB
    if not db.exists():
        return []
    rows = []
    con = _get_thread_conn(db)
    for r in con.execute("""
        SELECT m.cve_id, m.vendor, m.product, m.cpe_version,
               m.version_start, m.version_start_incl,
               m.version_end, m.version_end_incl,
               m.vulnerable,
               c.cvss_score, c.severity
        FROM cpe_match m JOIN cve c ON c.cve_id = m.cve_id
        WHERE m.vendor = ? AND m.product = ?
    """, (vendor.lower(), product.lower())):
        cpe_match = {
            # Reconstruct the criteria string in the shape
            # `cpe_matches_version` expects (it splits on ':' and
            # reads parts[5] as the version slot).
            "criteria": f"cpe:2.3:a:{r['vendor']}:{r['product']}:{r['cpe_version'] or '*'}:*:*:*:*:*:*:*",
            "vulnerable": bool(r["vulnerable"]),
        }
        if r["version_start"]:
            key = "versionStartIncluding" if r["version_start_incl"] else "versionStartExcluding"
            cpe_match[key] = r["version_start"]
        if r["version_end"]:
            key = "versionEndIncluding" if r["version_end_incl"] else "versionEndExcluding"
            cpe_match[key] = r["version_end"]
        rows.append({
            "cve_id": r["cve_id"],
            "cvss_score": r["cvss_score"],
            "severity": r["severity"],
            "cpe_match": cpe_match,
        })
    return rows


def is_populated(path: Optional[Path] = None) -> bool:
    """Quick yes/no for fallback logic: do we have any CVE data
    locally?"""
    db = path or _DEFAULT_DB
    if not db.exists():
        return False
    try:
        with sqlite3.connect(str(db)) as con:
            (n,) = con.execute("SELECT count(*) FROM cve").fetchone()
        return n > 0
    except sqlite3.Error:
        return False


def has_cves(path: Optional[Path] = None) -> bool:
    """True iff the local NVD database exists and holds at least one CVE.

    The cheap O(1) signal behind CVE Scan's "installed" state: CVE Scan has no
    container, so being ready/installed simply means its database is populated —
    a scan can't run without it. Uses LIMIT 1 (not count(*)) so it's safe to
    call on every status poll. Returns False on a missing/locked/corrupt DB."""
    db = path or _DEFAULT_DB
    if not db.exists():
        return False
    try:
        with sqlite3.connect(str(db)) as con:
            return con.execute("SELECT 1 FROM cve LIMIT 1").fetchone() is not None
    except sqlite3.Error:
        return False


def db_stats(path: Optional[Path] = None) -> Dict[str, Any]:
    """For the maintenance UI / status surface."""
    db = path or _DEFAULT_DB
    if not db.exists():
        return {"cve_count": 0, "match_count": 0, "last_modified": "", "db_size_mb": 0.0, "years": []}
    with sqlite3.connect(str(db)) as con:
        (cve_count,) = con.execute("SELECT count(*) FROM cve").fetchone()
        (match_count,) = con.execute("SELECT count(*) FROM cpe_match").fetchone()
        years = [{"year": y, "timestamp": ts, "cve_count": n}
                 for y, ts, n in con.execute(
                     "SELECT year, timestamp, cve_count FROM feed_meta ORDER BY year")]
    return {
        "cve_count": cve_count,
        "match_count": match_count,
        "last_modified": (max((y["timestamp"] for y in years if y["timestamp"]), default="") or ""),
        "db_size_mb": os.path.getsize(db) / 1_000_000,
        "years": years,
    }
