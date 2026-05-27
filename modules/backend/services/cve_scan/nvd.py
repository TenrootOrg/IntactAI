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


# Stop-word tokens that should never end a keyword. Names like
# "Microsoft 365 Apps for business" otherwise produce keywords like
# "365 Apps for" — strip the trailing "for" and adjacent dangling tokens
# before sending to NVD.
_KW_TRAILING_NOISE = {"for", "with", "and", "by", "of", "the", "a", "an", "to", "in"}


# Canonicalization patterns — every regex that matches gets replaced
# with the second element, dramatically collapsing near-duplicate SKUs
# to one lookup. Ordered most-specific first.
_CANON_PATTERNS = [
    # Microsoft Visual C++ runtime — 8+ SKUs per version (X64/X86 ×
    # Additional/Minimum × Runtime/Redistributable). Collapse to year.
    (re.compile(r"\bmicrosoft visual c\+\+ (\d{4}).*$", re.I), r"microsoft visual c++ \1"),
    (re.compile(r"\bmicrosoft visual c\+\+ \d{4}-(\d{4}).*$", re.I), r"microsoft visual c++ \1"),
    (re.compile(r"\bmicrosoft visual c\+\+ v?14\b.*$", re.I), "microsoft visual c++ 14"),
    # Python 3.x — has up to 12 sub-component installer entries.
    (re.compile(r"\bpython (\d+\.\d+(?:\.\d+)?) .*$", re.I), r"python \1"),
    (re.compile(r"\bpython launcher\b.*$", re.I), "python launcher"),
    # Microsoft Office Click-to-Run components.
    (re.compile(r"\boffice 16 click-to-run .*$", re.I), "office 16 click-to-run"),
    (re.compile(r"\bmicrosoft (?:office|365 apps?)\b.*$", re.I), "microsoft 365 apps"),
    (re.compile(r"\bיישומי microsoft 365\b.*$", re.I), "microsoft 365 apps"),
    # Microsoft .NET runtime variants.
    (re.compile(r"\bmicrosoft \.net core runtime - (\d+\.\d+(?:\.\d+)?)\b.*$", re.I), r"microsoft .net core runtime \1"),
    (re.compile(r"\bmicrosoft \.net runtime - (\d+\.\d+(?:\.\d+)?)\b.*$", re.I), r"microsoft .net runtime \1"),
    (re.compile(r"\bmicrosoft \.net host(?:fxr)? - (\d+\.\d+(?:\.\d+)?)\b.*$", re.I), r"microsoft .net runtime \1"),
    (re.compile(r"\bmicrosoft windows desktop runtime - (\d+\.\d+(?:\.\d+)?)\b.*$", re.I), r"microsoft windows desktop runtime \1"),
    # Microsoft Edge / WebView2.
    (re.compile(r"\bmicrosoft edge webview2 runtime\b.*$", re.I), "microsoft edge"),
    # CrowdStrike product family — many sub-products (Sensor / Device
    # Control / Firmware Analysis) all map to the same falcon CPE.
    (re.compile(r"\bcrowdstrike .*$", re.I), "crowdstrike falcon"),
    # Generic "(User)" / "(Machine)" / "(Per User)" install-scope tags.
    (re.compile(r"\s*\((?:user|machine|per[- ]user|all users?)\)\s*$", re.I), ""),
]


def canonical_name(name: str) -> str:
    """Collapse a noisy product name into the form most likely to share
    a CPE lookup with siblings. Returns the canonical lookup key
    (lower-cased). Used to dedupe (product, version) pairs before
    hitting NVD — a Windows enterprise inventory typically has ~30%
    near-duplicate SKUs (8 Visual C++ variants → 1 lookup, 12 Python
    sub-components → 1, etc.)."""
    if not name:
        return ""
    s = name.strip()
    for pat, repl in _CANON_PATTERNS:
        s = pat.sub(repl, s)
    # Strip trailing whitespace / dashes left by the substitutions.
    s = re.sub(r"\s+", " ", s).strip(" -")
    return s.lower()


def _keyword_candidates(name: str) -> list:
    """Generate an ordered list of keyword candidates to try against
    NVD when no CPE-map hit. First candidate is the existing
    `clean_for_query` result (back-compat); subsequent candidates are
    progressively broader heuristics so a noisy product like
    'Microsoft 365 Apps for business - en-us' eventually retries with
    'Microsoft 365' instead of giving up after 'Apps for'.

    Each candidate is also de-duplicated and bounded to keep API call
    counts predictable: at most 3 attempts per product."""
    cands: list = []

    def _add(s: str) -> None:
        s = (s or "").strip()
        if not s:
            return
        # Drop trailing stop-words/noise tokens.
        toks = s.split()
        while toks and toks[-1].lower() in _KW_TRAILING_NOISE:
            toks.pop()
        s = " ".join(toks)[:120].strip()
        if s and s not in cands:
            cands.append(s)

    # 1. Original cleaner — keeps existing matches working.
    _add(clean_for_query(name))

    # 2. Vendor-preserving variant: don't strip the vendor prefix
    # (Microsoft 365, Adobe Acrobat — the vendor IS the brand).
    s = LOCALE_RE.sub(" ", name)
    s = PARENS_RE.sub(" ", s)
    s = TRAILING_DASH_NUM_RE.sub(" ", s)
    s = VERSION_RE.sub(" ", s)
    s = re.sub(r"[^\w\s\.\+\-]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    words = s.split()
    if len(words) >= 2:
        _add(" ".join(words[:2]))

    # Note: an earlier revision also tried a single-word fallback
    # (e.g. "Java", "Microsoft"). It was dropped because such broad
    # queries return ENORMOUS result sets (NVD's keyword search on
    # "Microsoft" or "Adobe" can return thousands of unrelated CVEs);
    # each one made the workers stall on JSON parse + cve_applies_to
    # scan, doubling overall scan time for negligible match gain.
    return cands[:2]


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
    # 30s per attempt × 3 attempts = ≤90s worst case per page. The
    # previous 120s default let a hung TLS handshake silently stall an
    # entire 12-worker pool for >6 minutes — easy to misread as "stuck".
    for attempt in range(3):
        _acquire_rate_slot()
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # Only log slow successes (>5s) to keep the log readable.
                elapsed = time.time() - t0
                if log and elapsed > 5:
                    log(f"[CVE] NVD slow ({elapsed:.1f}s) for {('CPE ' if use_cpe else 'kw ')+keyword!r}", "info")
                return data
        except Exception as e:
            wait = 2 ** attempt
            elapsed = time.time() - t0
            if log:
                log(f"[CVE] NVD error after {elapsed:.1f}s on {('CPE ' if use_cpe else 'kw ')+keyword!r}: {e} (retry {attempt+1}/3 in {wait}s)", "warning")
            time.sleep(wait)
    if log:
        log(f"[CVE] NVD gave up after 3 attempts on {('CPE ' if use_cpe else 'kw ')+keyword!r}", "error")
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

    # Expanded coverage for common Windows-enterprise software the
    # original side-project map didn't catch. Each new entry was added
    # because a real run produced an "unknown" status that the operator
    # would have to triage by hand otherwise.
    ("python",                      "cpe:2.3:a:python:python"),
    ("microsoft 365",               "cpe:2.3:a:microsoft:365_apps"),
    ("יישומי microsoft 365",        "cpe:2.3:a:microsoft:365_apps"),
    ("microsoft 365 apps",          "cpe:2.3:a:microsoft:365_apps"),
    ("crowdstrike",                 "cpe:2.3:a:crowdstrike:falcon"),
    ("notepad++",                   "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"),
    ("slack",                       "cpe:2.3:a:slack:slack"),
    ("discord",                     "cpe:2.3:a:discord:discord"),
    ("telegram desktop",            "cpe:2.3:a:telegram:telegram_desktop"),
    ("docker desktop",              "cpe:2.3:a:docker:desktop"),
    ("docker",                      "cpe:2.3:a:docker:docker"),
    ("vlc media player",            "cpe:2.3:a:videolan:vlc_media_player"),
    ("obs studio",                  "cpe:2.3:a:obsproject:obs_studio"),
    ("wireshark",                   "cpe:2.3:a:wireshark:wireshark"),
    ("nodejs",                      "cpe:2.3:a:nodejs:node.js"),
    ("node.js",                     "cpe:2.3:a:nodejs:node.js"),
    ("anydesk",                     "cpe:2.3:a:anydesk:anydesk"),
    ("filezilla",                   "cpe:2.3:a:filezilla-project:filezilla_client"),
    ("winscp",                      "cpe:2.3:a:winscp:winscp"),
    ("openssh",                     "cpe:2.3:a:openbsd:openssh"),
    ("git",                         "cpe:2.3:a:git-scm:git"),
    ("apache tomcat",               "cpe:2.3:a:apache:tomcat"),
    ("apache",                      "cpe:2.3:a:apache:http_server"),
    ("nginx",                       "cpe:2.3:a:nginx:nginx"),
    ("oracle java",                 "cpe:2.3:a:oracle:jdk"),
    ("amazon corretto",             "cpe:2.3:a:amazon:corretto"),
    ("jetbrains",                   "cpe:2.3:a:jetbrains:intellij_idea"),
    ("sublime text",                "cpe:2.3:a:sublimehq:sublime_text"),
    ("opera",                       "cpe:2.3:a:opera:opera"),
    ("brave",                       "cpe:2.3:a:brave:browser"),
    ("vivaldi",                     "cpe:2.3:a:vivaldi:vivaldi"),
    ("thunderbird",                 "cpe:2.3:a:mozilla:thunderbird"),
    ("libreoffice",                 "cpe:2.3:a:libreoffice:libreoffice"),
    ("openoffice",                  "cpe:2.3:a:apache:openoffice"),
    ("foxit reader",                "cpe:2.3:a:foxit:reader"),
    ("evernote",                    "cpe:2.3:a:evernote:evernote"),
    ("dropbox",                     "cpe:2.3:a:dropbox:dropbox"),
    ("box drive",                   "cpe:2.3:a:box:drive"),
    ("splunk",                      "cpe:2.3:a:splunk:splunk"),
    ("postman",                     "cpe:2.3:a:postman:postman"),
    ("yara",                        "cpe:2.3:a:virustotal:yara"),
    ("kape",                        "cpe:2.3:a:eric-zimmerman:kape"),
    ("wsl",                         "cpe:2.3:a:microsoft:windows_subsystem_for_linux"),
    # Windows 11 / 10 — extra editions the strict "pro NNh2" / "NN h2"
    # prefixes didn't cover (Enterprise, Enterprise Evaluation, etc.).
    ("windows 11 enterprise evaluation 25h2", "cpe:2.3:o:microsoft:windows_11_25h2"),
    ("windows 11 enterprise evaluation 24h2", "cpe:2.3:o:microsoft:windows_11_24h2"),
    ("windows 11 enterprise evaluation 23h2", "cpe:2.3:o:microsoft:windows_11_23h2"),
    ("windows 11 enterprise 25h2",  "cpe:2.3:o:microsoft:windows_11_25h2"),
    ("windows 11 enterprise 24h2",  "cpe:2.3:o:microsoft:windows_11_24h2"),
    ("windows 11 enterprise 23h2",  "cpe:2.3:o:microsoft:windows_11_23h2"),
    ("windows 10 enterprise 22h2",  "cpe:2.3:o:microsoft:windows_10_22h2"),
    ("windows 10 enterprise 21h2",  "cpe:2.3:o:microsoft:windows_10_21h2"),
    ("windows server 2022",         "cpe:2.3:o:microsoft:windows_server_2022"),
    ("windows server 2019",         "cpe:2.3:o:microsoft:windows_server_2019"),
    ("windows server 2016",         "cpe:2.3:o:microsoft:windows_server_2016"),
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


def _scan_local_rows(local_rows, name, version):
    """Run the same matching logic as `_scan` against rows produced by
    `local_db.search_by_cpe()`. Each local row has the shape
    {cve_id, cvss_score, severity, cpe_match} where `cpe_match` mirrors
    the NVD-API cpeMatch shape that `cpe_matches_version` already
    understands. Returns (cve_id, score, severity) for the
    highest-CVSS applicable CVE, or None."""
    best = (None, -1.0, "")
    for r in local_rows:
        m = r["cpe_match"]
        if not cpe_matches_version(m, version):
            continue
        # Reuse the existing name-token check from `cve_applies_to` —
        # the local-DB row only carries one cpe match, but the
        # phrase/token rule still applies to guard against generic-name
        # collisions ("Microsoft Office" CPE matching "Office Lens").
        # Inline the check rather than call cve_applies_to (which
        # iterates a full cve_obj we don't have here).
        lname = name.lower()
        for marker in (" for ", " plugin for ", " add-in for ", " addin for "):
            idx = lname.find(marker)
            if idx > 0:
                lname = lname[:idx]
                break
        name_tokens = set(re.findall(r"\w+", lname))
        if not name_tokens:
            continue
        criteria = m.get("criteria", "")
        parts = criteria.split(":")
        if len(parts) < 6:
            continue
        product = parts[4].replace("_", " ").lower()
        prod_tokens = [t for t in re.findall(r"\w+", product) if len(t) >= 4]
        phrase_in_name = product in lname
        tokens_in_name = bool(prod_tokens) and all(t in name_tokens for t in prod_tokens)
        if not (phrase_in_name or tokens_in_name):
            continue
        score = r.get("cvss_score") or 0.0
        sev = r.get("severity") or ""
        if score > best[1]:
            best = (r["cve_id"], score, sev)
    return best if best[0] is not None else None


def _try_local_db(name, version, cpe_or_pair, log: Optional[Callable] = None):
    """Look up a CPE in the local SQLite mirror. Returns
    (saw_data, hit) — `saw_data=True` when the DB had ANY rows for
    this vendor:product (used to disambiguate 'patched' vs 'unknown'),
    `hit` is the (cve_id, score, sev) triple if a CVE applies.

    `cpe_or_pair` is either a CPE-2.3 string ('cpe:2.3:a:vendor:product:...')
    or a pre-parsed (vendor, product) tuple. Returns (False, None) if
    the local DB hasn't been populated yet — caller falls back to REST.
    """
    try:
        from . import local_db as _local_db
        if not _local_db.is_populated():
            return False, None
        if isinstance(cpe_or_pair, tuple):
            vendor, product = cpe_or_pair
        else:
            parts = (cpe_or_pair or "").split(":")
            if len(parts) < 5:
                return False, None
            vendor, product = parts[3], parts[4]
        rows = _local_db.search_by_cpe(vendor, product)
        if not rows:
            return False, None
        hit = _scan_local_rows(rows, name, version)
        return True, hit
    except Exception as e:
        if log:
            log(f"[CVE] Local-DB lookup error for {cpe_or_pair}: {e} (falling back to REST)", "warning")
        return False, None


def find_best_cve(name, version, cache, cache_path: Path, log: Optional[Callable] = None):
    """Return (status, cve_id, score, severity). `status` ∈
    {'vulnerable', 'patched', 'unknown'} and lets callers separate
    "we found a CVE that applies" from "NVD has CVEs for this product
    but none affect this version" from "no NVD data for this product
    at all". When status != 'vulnerable', the remaining fields are
    None and callers should treat them as empty.

    Lookup order:
      Layer 0 — local SQLite mirror of the NVD feed (fast, no network)
      Layer 1 — hand-curated PRODUCT_TO_CPE → REST (operator overrides)
      Layer 2 — vendored CPE dictionary → REST
      Layer 3 — NVD keyword search (broad, slow)

    The REST layers (1-3) only fire when the local DB hasn't been
    populated yet (fresh install) or returned nothing for the resolved
    CPE — they're the back-compat path."""
    if not (name and name.strip()) or not (version and version.strip()):
        return ("unknown", None, None, None)

    saw_any_cve_data = False

    # Resolve CPE candidates from the two existing layers (curated +
    # dictionary). These no longer need to issue HTTPS — we use them
    # to derive a vendor:product to query the local DB with.
    cpe_curated = cpe_for(name)
    try:
        from . import cpe_dict as _cpe_dict
        cpe_dict_hit = _cpe_dict.lookup_cpe(name)
    except Exception:
        cpe_dict_hit = None

    # Track which CPEs were answered by the local DB so we can skip
    # the REST fallback for the same CPE. Local DB is authoritative
    # when populated — a "patched" verdict there means we should NOT
    # turn around and re-ask NVD over the network for the same data.
    cpes_answered_locally: set = set()

    # Layer 0: local SQLite — instant, deterministic, no network.
    for cpe in (cpe_curated, cpe_dict_hit):
        if not cpe:
            continue
        saw_local, hit = _try_local_db(name, version, cpe, log=log)
        if saw_local:
            saw_any_cve_data = True
            cpes_answered_locally.add(cpe)
            if hit and hit[0]:
                return ("vulnerable",) + hit

    # Layer 1: REST against PRODUCT_TO_CPE (only when local DB didn't
    # have data for this CPE — i.e. CPE is brand-new and not in our
    # mirror yet).
    if cpe_curated and cpe_curated not in cpes_answered_locally:
        blob = _fetch(cpe_curated, True, cache, cache_path, log=log)
        if blob.get("totalResults", 0) > 0:
            saw_any_cve_data = True
            hit = _scan(blob, name, version)
            if hit and hit[0]:
                return ("vulnerable",) + hit

    # Layer 2: REST against vendored CPE dictionary.
    if (cpe_dict_hit and cpe_dict_hit != cpe_curated
            and cpe_dict_hit not in cpes_answered_locally):
        blob = _fetch(cpe_dict_hit, True, cache, cache_path, log=log)
        if blob.get("totalResults", 0) > 0:
            saw_any_cve_data = True
            hit = _scan(blob, name, version)
            if hit and hit[0]:
                return ("vulnerable",) + hit

    # Layer 3: multi-keyword REST fallback — DROPPED when the local
    # DB is populated. The mirror is comprehensive (every CVE NVD
    # has), so if our PRODUCT_TO_CPE map AND the cpe_dict both failed
    # to produce a CPE, the noisy keyword search isn't going to do
    # better. Skipping it saves 15-30 s per unmatched product (some
    # keyword calls hit NVD's slow long-tail). Only fires when local
    # DB hasn't been populated yet (e.g. fresh install before the
    # first bulk_load completes).
    try:
        from . import local_db as _local_db
        _local_populated = _local_db.is_populated()
    except Exception:
        _local_populated = False
    if not _local_populated:
        for keyword in _keyword_candidates(name):
            blob = _fetch(keyword, False, cache, cache_path, log=log)
            if blob.get("totalResults", 0) > 0:
                saw_any_cve_data = True
                hit = _scan(blob, name, version)
                if hit and hit[0]:
                    return ("vulnerable",) + hit

    return (("patched" if saw_any_cve_data else "unknown"), None, None, None)


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
        # New 4-tuple shape: (status, cve_id, score, severity). Only
        # populate the CVE columns when status == 'vulnerable'.
        if hit and hit[0] == "vulnerable":
            _status, cve_id, score, severity = hit
            link = NVD_DETAIL + cve_id
            sev = f"{score} {severity}".strip()
            cve_count += 1
        out.append(row + [link, sev])

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8", newline="") as fout:
        csv.writer(fout).writerows(out)
    return cve_count


def build_combined_rows(paths: List[Path], lookup: Dict, mode: str = "vulnerable_only") -> List[Tuple[str, str, str, str, str, str]]:
    """Return the deduped (host, product, version, status, level, link)
    rows that go into combined_cves.csv.

    `mode` controls inclusion + sort:
      - 'vulnerable_only' (default): only rows where NVD found an
        applicable CVE. Sorted by CVSS desc. Matches the original
        side-project behavior.
      - 'full': include every (host × product × version) the inventory
        saw. Rows without a CVE get status 'patched' (NVD has CVEs
        for the product but not this version) or 'unknown' (no NVD
        data at all). Ordered Vulnerable → Unknown → Patched, then
        by CVSS desc within each bucket.
    """
    rows: List[Tuple[str, str, str, str, str, str]] = []
    # Vulnerable rows are deduped by (host, name, ver, cve). Patched /
    # unknown rows by (host, name, ver) — no CVE to disambiguate by.
    seen_vuln = set()
    seen_other = set()
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
                host = _row_host(row, header) or "(unknown)"
                if not hit:
                    if mode != "full":
                        continue
                    key = (host, name, ver)
                    if key in seen_other:
                        continue
                    seen_other.add(key)
                    rows.append((host, name, ver, "unknown", "", ""))
                    continue
                status = hit[0]
                if status == "vulnerable":
                    cve_id, score, sev = hit[1], hit[2], hit[3]
                    link = NVD_DETAIL + cve_id
                    level = f"{score} {sev}".strip()
                    key = (host, name, ver, cve_id)
                    if key in seen_vuln:
                        continue
                    seen_vuln.add(key)
                    rows.append((host, name, ver, "vulnerable", level, link))
                else:
                    if mode != "full":
                        continue
                    key = (host, name, ver)
                    if key in seen_other:
                        continue
                    seen_other.add(key)
                    rows.append((host, name, ver, status, "", ""))

    # Ordering: Vulnerable first (sorted by descending CVSS), then
    # Unknown, then Patched. Within Unknown/Patched buckets, sort by
    # (host, product, version) for stable diffing across runs.
    bucket_order = {"vulnerable": 0, "unknown": 1, "patched": 2}

    def _sort_key(r):
        host, name, ver, status, level, link = r
        bucket = bucket_order.get(status, 99)
        if status == "vulnerable":
            try:
                score = -float(level.split()[0])
            except Exception:
                score = 0
            return (bucket, score, host, name, ver)
        return (bucket, 0, host, name, ver)

    rows.sort(key=_sort_key)
    return rows


def validate_combined(rows: List, log: Optional[Callable] = None) -> List:
    """Independent CVE-detail validation pass — same as the side
    project's validate_combined.py logic, run inline here so the
    workflow finishes with one shot. Drops any *vulnerable* row whose
    CVE detail doesn't actually have a CPE in range for the installed
    version. Rows with status 'patched' or 'unknown' are passed
    through untouched (there's no CVE to validate)."""
    detail_path = _cache_dir() / "nvd_cve_detail_cache.json"
    cache = _load_cve_detail_cache(detail_path)
    validated = []
    drop_count = 0

    # Local-DB lookup is the fast path: a single SELECT returns every
    # cpe_match for a CVE-ID, no HTTPS round-trip. Falls back to the
    # REST cve-detail call only when local DB isn't populated.
    try:
        from . import local_db as _local_db
        _local_db_populated = _local_db.is_populated()
    except Exception:
        _local_db = None
        _local_db_populated = False

    def _local_cpe_matches_for_cve(cve_id):
        """Return every cpe_match row tied to this CVE, in the same
        shape `cpe_matches_version` / `_cpe_product_matches` consume.
        Uses the local_db module's thread-local connection cache so
        we don't blow through the FD limit under heavy concurrency."""
        if not (_local_db and _local_db_populated):
            return []
        db = _local_db._DEFAULT_DB
        if not db.exists():
            return []
        out = []
        con = _local_db._get_thread_conn(db)
        for r in con.execute("""
            SELECT vendor, product, cpe_version,
                   version_start, version_start_incl,
                   version_end, version_end_incl, vulnerable
            FROM cpe_match WHERE cve_id = ?
        """, (cve_id,)):
            m = {
                "criteria": f"cpe:2.3:a:{r['vendor']}:{r['product']}:{r['cpe_version'] or '*'}:*:*:*:*:*:*:*",
                "vulnerable": bool(r["vulnerable"]),
            }
            if r["version_start"]:
                k = "versionStartIncluding" if r["version_start_incl"] else "versionStartExcluding"
                m[k] = r["version_start"]
            if r["version_end"]:
                k = "versionEndIncluding" if r["version_end_incl"] else "versionEndExcluding"
                m[k] = r["version_end"]
            out.append(m)
        return out

    def _validate(row):
        # row shape: (host, product, version, status, level, link)
        host, product, version, status, level, link = row
        if status != "vulnerable":
            return row, True
        cve_id = link.rsplit("/", 1)[-1] if "/" in link else ""
        if not cve_id:
            return row, False

        # Layer 0: validate against local DB. Avoids a per-row NVD
        # cve-detail HTTPS round-trip.
        if _local_db_populated:
            matches = _local_cpe_matches_for_cve(cve_id)
            if matches:
                product_cpes = [m for m in matches if _cpe_product_matches(m, product)]
                if not product_cpes:
                    return row, False
                for m in product_cpes:
                    if cpe_matches_version(m, version):
                        return row, True
                return row, False
            # Empty matches list = CVE not in local DB (newer than
            # last bulk_load). Fall through to REST.

        # Fallback: NVD REST cve-detail call.
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

    # 64 workers when validating against local DB (no rate limit, just
    # SQLite SELECTs), 12 when falling back to NVD REST.
    _vworkers = 64 if _local_db_populated else 12
    with ThreadPoolExecutor(max_workers=_vworkers) as ex:
        for row, ok in ex.map(_validate, rows):
            if ok:
                validated.append(list(row))
            else:
                drop_count += 1
    if log and drop_count:
        log(f"[CVE] Dropped {drop_count} vulnerable row(s) that didn't survive independent CVE-detail validation", "info")
    return validated


def fetch_all_pairs(pairs: list, cache: Dict, cache_path: Path, log: Optional[Callable] = None,
                    progress_cb: Optional[Callable] = None) -> Dict:
    """For every (product, version) pair, look up the best CVE in
    parallel using 12 workers. Returns dict[(name, ver) -> (status,
    cve_id, score, severity)].

    `progress_cb(done, total)` is invoked every ~5% so the caller can
    update the workflow row's progress bar live (otherwise it sits at
    the same value through a long NVD lookup phase — confusing on
    enterprise-scale inventories with 900+ pairs)."""
    # Canonicalize first — collapse near-duplicate SKUs that would
    # otherwise each issue their own NVD lookup. The 'pairs' the caller
    # gave us still get full results (we expand back at the end); the
    # threadpool only sees the deduped canonical set.
    canon_to_originals: Dict[Tuple[str, str], list] = {}
    for p in pairs:
        canon = (canonical_name(p[0]) or p[0].lower().strip(), p[1])
        canon_to_originals.setdefault(canon, []).append(p)
    canonical_pairs = list(canon_to_originals.keys())
    if log and len(canonical_pairs) < len(pairs):
        log(
            f"[CVE] Canonicalized {len(pairs)} pairs → {len(canonical_pairs)} unique lookups "
            f"({len(pairs) - len(canonical_pairs)} duplicates collapsed)",
            "info",
        )

    lookup: Dict = {}
    state = {
        "done": 0,
        "in_flight": 0,
        "last_pair": None,
        "stop_heartbeat": False,
    }
    lock = threading.Lock()
    total = len(canonical_pairs)
    log_step = max(5, total // 40)
    pct_step = max(1, total // 20)

    def _heartbeat():
        """Background thread — emits a status line every 30s so a
        wedged worker pool never goes silent. Without this, a hung
        urlopen looks identical to slow rate-limited progress."""
        while True:
            time.sleep(30)
            with lock:
                if state["stop_heartbeat"]:
                    return
                done = state["done"]
                inflight = state["in_flight"]
                last = state["last_pair"]
            if log and done < total:
                pair_desc = f"{last[0]!r}@{last[1]}" if last else "(none)"
                log(
                    f"[CVE] Heartbeat: {done}/{total} done, {inflight} in flight, last pair: {pair_desc}",
                    "info",
                )

    def process(pair):
        name, ver = pair
        with lock:
            state["in_flight"] += 1
            state["last_pair"] = pair
        try:
            result = find_best_cve(name, ver, cache, cache_path, log=log)
        except Exception as e:
            # Don't let one bad pair poison the pool. Tag the result as
            # 'unknown' so the row still appears in full-mode output
            # with an obvious explanation in the workflow log.
            if log:
                log(f"[CVE] Lookup error on ({name!r}, {ver!r}): {e}", "warning")
            result = ("unknown", None, None, None)
        with lock:
            state["in_flight"] -= 1
            state["done"] += 1
            done = state["done"]
        if log and (done % log_step == 0 or done == total):
            pct = int(100 * done / max(total, 1))
            log(f"[CVE] Lookup progress: {done}/{total} pairs ({pct}%)", "info")
        if progress_cb and (done % pct_step == 0 or done == total):
            try:
                progress_cb(done, total)
            except Exception:
                pass
        return pair, result

    # Worker count: when the local DB is populated (no NVD rate cap),
    # we're CPU/SQLite-bound and benefit from more threads. When we
    # have to fall back to the REST path, the 50 req/30s NVD cap
    # means more workers just queue on the rate slot — keep it modest.
    try:
        from . import local_db as _local_db
        _local_populated = _local_db.is_populated()
    except Exception:
        _local_populated = False
    workers = 64 if _local_populated else 12

    hb_thread = threading.Thread(target=_heartbeat, daemon=True, name="cve-scan-heartbeat")
    hb_thread.start()
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            # Look up canonical pairs only — each result is then fanned
            # out to every original pair that canonicalized to it, so
            # the caller's dict is keyed by the original (name, version)
            # exactly as before.
            for canon_pair, result in ex.map(process, canonical_pairs):
                for orig in canon_to_originals[canon_pair]:
                    lookup[orig] = result
    finally:
        with lock:
            state["stop_heartbeat"] = True
    return lookup
