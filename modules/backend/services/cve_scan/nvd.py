"""NVD CVE lookup logic — verbatim port of the matching code from the
standalone `nvd_check.py` side project, with the I/O surface refactored
so it's callable from a Flask background worker instead of a CLI:

- Hardcoded Windows paths replaced with function arguments / config.
- Hardcoded NVD API key replaced with `load_frontend_config()` lookup +
  `NVD_API_KEY` env var override.
- Cache JSON paths moved under `/app/data/cve_cache/` (persists via
  the existing data volume mount).
- All print() calls in the original kept but funnel through an
  optional `log` callback so the workflow row logs surface them.

The CVE-matching heuristics (CPE-vs-keyword fallback, version-range
matching, magnitude sanity check, "for X" suffix stripping,
independent CVE-detail validation pass) are unchanged — those are
the meat of the side project and they work well today.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"

# Caches live under the existing data volume mount so they persist
# across container restarts. The directory is created lazily on first
# use to avoid import-time side effects.
_DEFAULT_CACHE_DIR = Path("/app/data/cve_cache")


def _api_key() -> str:
    """NVD API key resolution: env var > frontend settings > empty.

    Empty key drops the rate limit from 50 req/30s to 5 req/30s but
    the script still works; we surface a warning in the pipeline log
    when no key is configured."""
    env = os.environ.get("NVD_API_KEY", "").strip()
    if env:
        return env
    try:
        from services.file_storage_service import load_frontend_config
        cfg = load_frontend_config() or {}
        key = (cfg.get('cve_scan') or {}).get('nvd_api_key') or ''
        return str(key).strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Text cleanup + version parsing — verbatim from the side project
# ---------------------------------------------------------------------------

NOISE_RE = re.compile(
    r"\b(x86|x64|win32|win64|64-bit|32-bit|"
    r"Redistributable|Additional|Minimum|Runtime|Component|"
    r"SPLA|release|version|"
    r"Click-to-Run|Click to Run|"
    r"Professional|Standard|Enterprise|Basic|Edition|Ultimate|Premium|"
    r"Plus|Home|Starter|"
    r"x64-based|based|Systems|"
    r"LTSC|RT|MUI"
    r")\b", re.I,
)
PARENS_RE = re.compile(r"\([^)]*\)")
VERSION_RE = re.compile(r"\bv?\d+\.\d+(?:\.\d+)*\b", re.I)
TRAILING_DASH_NUM_RE = re.compile(r"-\s*\d[\d.]*\s*$")
LOCALE_RE = re.compile(r"\b-?\s*(en-us|he-il|en_us|he_il)\b\s*", re.I)

VENDOR_PREFIXES = [
    "microsoft", "mozilla", "google", "apple", "adobe", "dell", "lenovo",
    "nvidia", "logitech", "logi", "sophos", "trend micro", "zoom",
    "oracle", "ibm", "cisco", "realtek", "amazon", "facebook", "meta",
    "duo security", "duo", "horizon datasys",
]


def clean_for_query(name: str) -> str:
    if not name:
        return ""
    s = LOCALE_RE.sub(" ", name)
    s = PARENS_RE.sub(" ", s)
    s = TRAILING_DASH_NUM_RE.sub(" ", s)
    s = VERSION_RE.sub(" ", s)
    s = NOISE_RE.sub(" ", s)
    s = re.sub(r"[^\w\s\.\+\-]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    s = s.rstrip("-").strip()
    low = s.lower()
    for v in VENDOR_PREFIXES:
        if low.startswith(v + " "):
            s = s[len(v):].strip()
            break
    words = s.split()
    if len(words) > 3:
        s = " ".join(words[:3])
    return s[:120]


def parse_version(v):
    if not v:
        return ()
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums)


def version_le(a, b):
    pa, pb = parse_version(a), parse_version(b)
    n = max(len(pa), len(pb))
    pa = pa + (0,) * (n - len(pa))
    pb = pb + (0,) * (n - len(pb))
    return pa <= pb


def version_lt(a, b):
    pa, pb = parse_version(a), parse_version(b)
    n = max(len(pa), len(pb))
    pa = pa + (0,) * (n - len(pa))
    pb = pb + (0,) * (n - len(pb))
    return pa < pb


def severity_bucket(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


# ---------------------------------------------------------------------------
# Cache + rate limiter
# ---------------------------------------------------------------------------

# Module-level rate limiter (50 req / 30s with key, 5 / 30s without).
# The pipeline picks the right rate at scan start.
_RATE_LIMIT = 50
_RATE_WINDOW = 30.0
_rate_lock = threading.Lock()
_rate_times: deque = deque()


def set_rate_limit(have_key: bool):
    """Toggle the rate limit between the keyed (50/30s) and anonymous
    (5/30s) NVD ceilings. Called by the pipeline once we've resolved
    the API key state."""
    global _RATE_LIMIT
    _RATE_LIMIT = 50 if have_key else 5


def _acquire_rate_slot():
    while True:
        with _rate_lock:
            now = time.time()
            while _rate_times and now - _rate_times[0] > _RATE_WINDOW:
                _rate_times.popleft()
            if len(_rate_times) < _RATE_LIMIT:
                _rate_times.append(now)
                return
            wait = _RATE_WINDOW - (now - _rate_times[0]) + 0.05
        time.sleep(wait)


def _cache_dir() -> Path:
    _DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _DEFAULT_CACHE_DIR


def load_cache(path: Optional[Path] = None) -> Dict:
    p = path or (_cache_dir() / "nvd_cache.json")
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_cache(cache: Dict, path: Optional[Path] = None):
    p = path or (_cache_dir() / "nvd_cache.json")
    p.write_text(json.dumps(cache), encoding="utf-8")


# ---------------------------------------------------------------------------
# NVD API access
# ---------------------------------------------------------------------------


def _nvd_headers():
    h = {"User-Agent": "intactai-cve-scan/1.0"}
    key = _api_key()
    if key:
        h["apiKey"] = key
    return h


def nvd_query_page(keyword, start_index=0, use_cpe=False, log: Optional[Callable] = None):
    if use_cpe:
        params = {
            "virtualMatchString": keyword,
            "resultsPerPage": "2000",
            "startIndex": str(start_index),
        }
    else:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": "2000",
            "startIndex": str(start_index),
        }
    qs = urllib.parse.urlencode(params)
    url = f"{NVD_URL}?{qs}"
    req = urllib.request.Request(url, headers=_nvd_headers())
    for attempt in range(3):
        _acquire_rate_slot()
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            wait = 2 ** attempt
            if log:
                log(f"[CVE] NVD error '{e}', retrying in {wait}s…", "warning")
            time.sleep(wait)
    return None


def nvd_query(keyword, use_cpe=False, log: Optional[Callable] = None):
    if not keyword:
        return None
    all_vulns = []
    idx = 0
    while True:
        data = nvd_query_page(keyword, idx, use_cpe=use_cpe, log=log)
        if data is None:
            break
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total = data.get("totalResults", 0)
        idx += len(vulns)
        if idx >= total or not vulns:
            break
    return {"vulnerabilities": all_vulns, "totalResults": len(all_vulns)}


# ---------------------------------------------------------------------------
# Product → CPE table — verbatim port
# ---------------------------------------------------------------------------

PRODUCT_TO_CPE = [
    ("windows 11 pro 25h2",         "cpe:2.3:o:microsoft:windows_11_25h2"),
    ("windows 11 pro 24h2",         "cpe:2.3:o:microsoft:windows_11_24h2"),
    ("windows 11 pro 23h2",         "cpe:2.3:o:microsoft:windows_11_23h2"),
    ("windows 11 pro 22h2",         "cpe:2.3:o:microsoft:windows_11_22h2"),
    ("windows 11 pro 21h2",         "cpe:2.3:o:microsoft:windows_11_21h2"),
    ("windows 11 25h2",             "cpe:2.3:o:microsoft:windows_11_25h2"),
    ("windows 11 24h2",             "cpe:2.3:o:microsoft:windows_11_24h2"),
    ("windows 11 23h2",             "cpe:2.3:o:microsoft:windows_11_23h2"),
    ("windows 11 22h2",             "cpe:2.3:o:microsoft:windows_11_22h2"),
    ("windows 11 21h2",             "cpe:2.3:o:microsoft:windows_11_21h2"),
    ("windows 10 pro 22h2",         "cpe:2.3:o:microsoft:windows_10_22h2"),
    ("windows 10 22h2",             "cpe:2.3:o:microsoft:windows_10_22h2"),
    ("windows 10 21h2",             "cpe:2.3:o:microsoft:windows_10_21h2"),
    ("microsoft office",            "cpe:2.3:a:microsoft:office"),
    ("microsoft project",           "cpe:2.3:a:microsoft:project"),
    ("microsoft visio",             "cpe:2.3:a:microsoft:visio"),
    ("office 16 click-to-run",      "cpe:2.3:a:microsoft:office"),
    ("microsoft onedrive",          "cpe:2.3:a:microsoft:onedrive"),
    ("microsoft edge",              "cpe:2.3:a:microsoft:edge"),
    ("microsoft visual studio code","cpe:2.3:a:microsoft:visual_studio_code"),
    ("microsoft visual c++",        "cpe:2.3:a:microsoft:visual_studio_2022"),
    ("microsoft .net runtime",      "cpe:2.3:a:microsoft:.net"),
    ("microsoft .net host",         "cpe:2.3:a:microsoft:.net"),
    ("microsoft windows desktop runtime", "cpe:2.3:a:microsoft:.net"),
    ("microsoft teams",             "cpe:2.3:a:microsoft:teams"),
    ("google chrome",               "cpe:2.3:a:google:chrome"),
    ("mozilla firefox",             "cpe:2.3:a:mozilla:firefox"),
    ("mozilla maintenance service", "cpe:2.3:a:mozilla:firefox"),
    ("adobe acrobat reader",        "cpe:2.3:a:adobe:acrobat_reader"),
    ("adobe acrobat",               "cpe:2.3:a:adobe:acrobat"),
    ("adobe refresh manager",       "cpe:2.3:a:adobe:download_manager"),
    ("winrar",                      "cpe:2.3:a:rarlab:winrar"),
    ("7-zip",                       "cpe:2.3:a:7-zip:7-zip"),
    ("putty",                       "cpe:2.3:a:putty:putty"),
    ("teamviewer",                  "cpe:2.3:a:teamviewer:teamviewer"),
    ("zoom workplace",              "cpe:2.3:a:zoom:zoom"),
    ("zoom",                        "cpe:2.3:a:zoom:zoom"),
    ("velociraptor",                "cpe:2.3:a:rapid7:velociraptor"),
    ("sophos connect",              "cpe:2.3:a:sophos:connect"),
    ("sophos ssl vpn",              "cpe:2.3:a:sophos:ssl_vpn_client"),
    ("trend micro apex one",        "cpe:2.3:a:trendmicro:apex_one"),
    ("dell supportassist",          "cpe:2.3:a:dell:supportassist"),
    ("duo authentication",          "cpe:2.3:a:cisco:duo_authentication_for_windows_logon_and_rdp"),
    ("openvpn connect",             "cpe:2.3:a:openvpn:connect"),
    ("nvidia graphics driver",      "cpe:2.3:a:nvidia:gpu_driver"),
    ("nvidia install application",  "cpe:2.3:a:nvidia:gpu_driver"),
    ("logitech options",            "cpe:2.3:a:logitech:options"),
    ("lenovo vantage",              "cpe:2.3:a:lenovo:vantage"),
    ("realtek audio",               "cpe:2.3:a:realtek:hd_audio_codec_drivers"),
    ("realtek usb audio",           "cpe:2.3:a:realtek:hd_audio_codec_drivers"),
    ("icloud",                      "cpe:2.3:a:apple:icloud"),
    ("grammarly",                   "cpe:2.3:a:grammarly:grammarly"),
    ("whatsapp",                    "cpe:2.3:a:whatsapp:whatsapp"),
]


def cpe_for(name):
    if not name:
        return None
    low = name.lower()
    for frag, cpe in PRODUCT_TO_CPE:
        if frag in low:
            return cpe
    return None


# ---------------------------------------------------------------------------
# CPE / CVE matching — verbatim port
# ---------------------------------------------------------------------------


def cpe_matches_version(cpe_match, version):
    if not cpe_match.get("vulnerable", True):
        return False

    criteria = cpe_match.get("criteria", "")
    parts = criteria.split(":")
    cpe_version = parts[5] if len(parts) > 5 else "*"

    if cpe_version not in ("*", "-", ""):
        return parse_version(cpe_version) == parse_version(version)

    has_range = False
    ok = True

    if "versionStartIncluding" in cpe_match:
        has_range = True
        ok &= version_le(cpe_match["versionStartIncluding"], version)
    if "versionStartExcluding" in cpe_match:
        has_range = True
        ok &= version_lt(cpe_match["versionStartExcluding"], version)
    if "versionEndIncluding" in cpe_match:
        has_range = True
        ok &= version_le(version, cpe_match["versionEndIncluding"])
    if "versionEndExcluding" in cpe_match:
        has_range = True
        ok &= version_lt(version, cpe_match["versionEndExcluding"])

    if not (has_range and ok):
        return False

    has_start = "versionStartIncluding" in cpe_match or "versionStartExcluding" in cpe_match
    if not has_start:
        end = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")
        if end:
            iv = parse_version(version)
            ev = parse_version(end)
            if iv and ev:
                imaj, emaj = iv[0], ev[0]
                if emaj > 0 and imaj * 2 < emaj:
                    return False
    return True


def cve_applies_to(cve_obj, name, version):
    lname = name.lower()
    for marker in (" for ", " plugin for ", " add-in for ", " addin for "):
        idx = lname.find(marker)
        if idx > 0:
            lname = lname[:idx]
            break
    name_tokens = set(re.findall(r"\w+", lname))
    if not name_tokens:
        return False

    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                criteria = m.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                product = parts[4].replace("_", " ").lower()
                if product in ("*", "-", ""):
                    continue
                prod_tokens = [t for t in re.findall(r"\w+", product) if len(t) >= 4]
                phrase_in_name = product in lname
                tokens_in_name = bool(prod_tokens) and all(t in name_tokens for t in prod_tokens)
                if not (phrase_in_name or tokens_in_name):
                    continue
                if cpe_matches_version(m, version):
                    return True
    return False


def best_cvss(cve_obj):
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or severity_bucket(score)
            if score is not None:
                return float(score), sev.title() if isinstance(sev, str) else sev
    arr = metrics.get("cvssMetricV2")
    if arr:
        data = arr[0].get("cvssData", {})
        score = data.get("baseScore")
        if score is not None:
            return float(score), severity_bucket(score)
    return 0.0, ""


# Per-key locks so two workers asking for the same product don't both fetch.
_cache_lock = threading.Lock()
_inflight_locks: Dict[str, threading.Lock] = {}


def _key_lock(key):
    with _cache_lock:
        lk = _inflight_locks.get(key)
        if lk is None:
            lk = threading.Lock()
            _inflight_locks[key] = lk
        return lk


def _fetch(query, use_cpe, cache, cache_path: Path, log: Optional[Callable] = None):
    cache_key = f"{'cpe' if use_cpe else 'kw'}::{query}"
    if cache_key in cache:
        return cache[cache_key]
    with _key_lock(cache_key):
        if cache_key in cache:
            return cache[cache_key]
        if log:
            log(f"[CVE] NVD <- {'CPE' if use_cpe else 'kw'} {query!r}", "info")
        data = nvd_query(query, use_cpe=use_cpe, log=log)
        blob = {"vulnerabilities": [], "totalResults": 0}
        if data is not None:
            blob = {
                "vulnerabilities": data.get("vulnerabilities", []),
                "totalResults": data.get("totalResults", 0),
            }
        with _cache_lock:
            cache[cache_key] = blob
            save_cache(cache, cache_path)
        return blob


def _scan(blob, name, version):
    best = (None, -1.0, "")
    for entry in blob.get("vulnerabilities", []):
        cve_obj = entry.get("cve", {})
        cve_id = cve_obj.get("id")
        if not cve_id:
            continue
        if not cve_applies_to(cve_obj, name, version):
            continue
        score, sev = best_cvss(cve_obj)
        if score > best[1]:
            best = (cve_id, score, sev)
    return best if best[0] is not None else None


def find_best_cve(name, version, cache, cache_path: Path, log: Optional[Callable] = None):
    if not (name and name.strip()) or not (version and version.strip()):
        return None, None, None

    cpe = cpe_for(name)
    if cpe:
        blob = _fetch(cpe, True, cache, cache_path, log=log)
        if blob.get("totalResults", 0) > 0:
            hit = _scan(blob, name, version)
            return hit if hit else (None, None, None)

    keyword = clean_for_query(name)
    if keyword:
        blob = _fetch(keyword, False, cache, cache_path, log=log)
        hit = _scan(blob, name, version)
        if hit:
            return hit

    return None, None, None


def _kernel_build(s):
    if not s:
        return ""
    return s.split(" Build ")[0].strip()


# ---------------------------------------------------------------------------
# CVE-detail validation pass
# ---------------------------------------------------------------------------

_detail_cache_lock = threading.Lock()
_detail_inflight: Dict[str, threading.Lock] = {}


def _load_cve_detail_cache(path: Optional[Path] = None) -> Dict:
    p = path or (_cache_dir() / "nvd_cve_detail_cache.json")
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_cve_detail_cache(cache: Dict, path: Optional[Path] = None):
    p = path or (_cache_dir() / "nvd_cve_detail_cache.json")
    p.write_text(json.dumps(cache), encoding="utf-8")


def _fetch_cve_detail(cve_id, cache, cache_path: Path, log: Optional[Callable] = None):
    if cve_id in cache:
        return cache[cve_id]
    with _detail_cache_lock:
        lk = _detail_inflight.setdefault(cve_id, threading.Lock())
    with lk:
        if cve_id in cache:
            return cache[cve_id]
        qs = urllib.parse.urlencode({"cveId": cve_id})
        req = urllib.request.Request(f"{NVD_URL}?{qs}", headers=_nvd_headers())
        for attempt in range(3):
            _acquire_rate_slot()
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    d = json.loads(r.read().decode("utf-8"))
                vulns = d.get("vulnerabilities", [])
                cve = vulns[0]["cve"] if vulns else None
                with _detail_cache_lock:
                    cache[cve_id] = cve
                    _save_cve_detail_cache(cache, cache_path)
                return cve
            except Exception as e:
                wait = 2 ** attempt
                if log:
                    log(f"[CVE] CVE-detail error {cve_id}: {e} (retry in {wait}s)", "warning")
                time.sleep(wait)
        cache[cve_id] = None
        return None


def _cpe_product_matches(m, product_name):
    parts = m.get("criteria", "").split(":")
    if len(parts) < 5:
        return False
    product = parts[4].replace("_", " ").lower()
    if product in ("*", "-", ""):
        return False
    name_low = product_name.lower()
    for marker in (" for ", " plugin for ", " add-in for ", " addin for "):
        idx = name_low.find(marker)
        if idx > 0:
            name_low = name_low[:idx]
            break
    name_tokens = set(re.findall(r"\w+", name_low))
    prod_tokens = [t for t in re.findall(r"\w+", product) if len(t) >= 4]
    if product in name_low:
        return True
    return bool(prod_tokens) and all(t in name_tokens for t in prod_tokens)


# ---------------------------------------------------------------------------
# CSV row helpers — verbatim port
# ---------------------------------------------------------------------------


def _row_name_version(row, header):
    has_dn = "DisplayName" in header and "DisplayVersion" in header
    has_event = "Event" in header
    has_platform = "Platform" in header and "KernelVersion" in header

    if has_dn:
        name = row[header.index("DisplayName")].strip()
        ver  = row[header.index("DisplayVersion")].strip()
    elif has_event:
        try:
            o = json.loads(row[header.index("Event")])
            name = (o.get("DisplayName") or "").strip()
            ver  = (o.get("DisplayVersion") or "").strip()
        except Exception:
            name, ver = "", ""
    elif has_platform:
        platform = row[header.index("Platform")].strip()
        chan = row[header.index("PlatformVersion")].strip() if "PlatformVersion" in header else ""
        kernel = _kernel_build(row[header.index("KernelVersion")].strip())
        name = (platform + " " + chan).strip() if chan else platform
        ver  = kernel
    else:
        name, ver = "", ""
    return name, ver


def _row_host(row, header):
    for col in ("Hostname", "Fqdn", "fqdn"):
        if col in header:
            v = row[header.index(col)].strip()
            if v:
                return v
    return ""


def collect_unique_pairs(paths: List[Path]) -> set:
    pairs = set()
    for p in paths:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                continue
            for row in reader:
                while len(row) < len(header):
                    row.append("")
                name, ver = _row_name_version(row, header)
                if name and ver:
                    pairs.add((name, ver))
    return pairs


def write_per_input_output(src: Path, dst: Path, lookup: Dict):
    with src.open("r", encoding="utf-8-sig", newline="") as fin:
        reader = csv.reader(fin)
        rows = list(reader)
    if not rows:
        return 0
    header = rows[0]

    out = [header + ["CVE_Link", "CVE_Severity"]]
    cve_count = 0
    for row in rows[1:]:
        while len(row) < len(header):
            row.append("")
        name, ver = _row_name_version(row, header)
        link, sev = "", ""
        hit = lookup.get((name, ver))
        if hit and hit[0]:
            cve_id, score, severity = hit
            link = NVD_DETAIL + cve_id
            sev = f"{score} {severity}".strip()
            cve_count += 1
        out.append(row + [link, sev])

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8", newline="") as fout:
        csv.writer(fout).writerows(out)
    return cve_count


def build_combined_rows(paths: List[Path], lookup: Dict) -> List[Tuple[str, str, str, str, str]]:
    """Return the deduped (host, product, version, level, link) rows
    that go into combined_cves.csv, sorted by severity desc."""
    rows: List[Tuple[str, str, str, str, str]] = []
    seen = set()
    for p in paths:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                continue
            for row in reader:
                while len(row) < len(header):
                    row.append("")
                name, ver = _row_name_version(row, header)
                if not (name and ver):
                    continue
                hit = lookup.get((name, ver))
                if not (hit and hit[0]):
                    continue
                host = _row_host(row, header)
                cve_id, score, sev = hit
                link = NVD_DETAIL + cve_id
                level = f"{score} {sev}".strip()
                key = (host, name, ver, cve_id)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((host or "(unknown)", name, ver, level, link))

    def _sort_key(r):
        try:
            score = -float(r[3].split()[0])
        except Exception:
            score = 0
        return (score, r[0], r[1], r[2])
    rows.sort(key=_sort_key)
    return rows


def validate_combined(rows: List, log: Optional[Callable] = None) -> List:
    """Independent CVE-detail validation pass — same as the side
    project's validate_combined.py logic, run inline here so the
    workflow finishes with one shot. Drops any row whose CVE detail
    doesn't actually have a CPE in range for the installed version."""
    detail_path = _cache_dir() / "nvd_cve_detail_cache.json"
    cache = _load_cve_detail_cache(detail_path)
    validated = []
    drop_count = 0

    def _validate(row):
        host, product, version, level, link = row
        cve_id = link.rsplit("/", 1)[-1] if "/" in link else ""
        if not cve_id:
            return row, False
        cve = _fetch_cve_detail(cve_id, cache, detail_path, log=log)
        if not cve:
            return row, False
        product_cpes = []
        for cfg in cve.get("configurations", []):
            for n in cfg.get("nodes", []):
                for m in n.get("cpeMatch", []):
                    if _cpe_product_matches(m, product):
                        product_cpes.append(m)
        if not product_cpes:
            return row, False
        for m in product_cpes:
            if cpe_matches_version(m, version):
                return row, True
        return row, False

    with ThreadPoolExecutor(max_workers=12) as ex:
        for row, ok in ex.map(_validate, rows):
            if ok:
                validated.append(list(row))
            else:
                drop_count += 1
    if log and drop_count:
        log(f"[CVE] Dropped {drop_count} row(s) that didn't survive independent CVE-detail validation", "info")
    return validated


def fetch_all_pairs(pairs: list, cache: Dict, cache_path: Path, log: Optional[Callable] = None) -> Dict:
    """For every (product, version) pair, look up the best CVE in
    parallel using 12 workers. Returns dict[(name, ver) -> (cve_id,
    score, severity) | (None, None, None)]."""
    lookup: Dict = {}
    counter = {"done": 0}
    lock = threading.Lock()
    total = len(pairs)

    def process(pair):
        name, ver = pair
        result = find_best_cve(name, ver, cache, cache_path, log=log)
        with lock:
            counter["done"] += 1
            done = counter["done"]
        # Per-pair progress is too noisy for the workflow log;
        # emit every 20.
        if log and done % 20 == 0:
            log(f"[CVE] Lookup progress: {done}/{total} pairs", "info")
        return pair, result

    with ThreadPoolExecutor(max_workers=12) as ex:
        for pair, result in ex.map(process, pairs):
            lookup[pair] = result
    return lookup
