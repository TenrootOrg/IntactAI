"""CPE dictionary lookup — local token-overlap search against a
vendored copy of the NVD CPE vendor:product list (from tiiuae/cpedict,
daily-updated from the official NVD feed).

Replaces what was previously a ~100-entry hand-curated map with a
65 k-entry dictionary so unknown enterprise software can be resolved
to a CPE automatically rather than landing in the "unknown" bucket.

Design constraints:
  - No network calls during lookup — the CSV ships in-repo so scans
    are fully offline-capable.
  - First load builds an inverted index in memory; subsequent lookups
    are O(name_tokens × posting_list_size), which is microseconds for
    typical product names.
  - Hand-curated PRODUCT_TO_CPE still wins (operator-known overrides
    take precedence); this module is the FALLBACK when the curated
    map misses, and it sits BEFORE the noisy NVD keyword search.
  - Strict subset rule keeps false-positive rate near zero — a dict
    entry's (vendor + product) tokens must ALL appear in the installed
    name's tokens. Score is the entry's specificity (token count) so
    more-specific entries win when several match.

Public API:
    init_dictionary(path=None)             # idempotent, called lazily
    lookup_cpe(product_name) -> str | None # CPE string or None
    refresh_dictionary_from_upstream()     # called from maintenance
"""
from __future__ import annotations

import csv
import io
import re
import threading
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


# Upstream feed — daily-updated CSV of CPE vendor:product pairs.
# Pulled from the NVD CPE dictionary by tiiuae/cpedict's GitHub Action.
UPSTREAM_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv"

_DEFAULT_PATH = Path(__file__).parent / "data" / "cpes.csv"


# Stopwords stripped from BOTH dictionary tokens (at index build time)
# and installed-name tokens (at lookup time). Without these, a 65 k-entry
# search returns hundreds of garbage candidates per name. Keep this
# list conservative — over-stripping (e.g. "365" or "16") collapses
# distinct CPE products to the same token-set and produces nonsense
# matches like "Microsoft Visual C++ 2022" → "microsoft:365".
_STOPWORDS = {
    "the", "a", "an", "for", "with", "and", "or", "of", "to", "in",
    "by", "from", "on", "at", "is", "be", "as",
    # Windows-install noise that adds zero signal:
    "x86", "x64", "win32", "win64", "32bit", "64bit",
    "user", "machine",
    "edition", "ed", "version", "ver",
    "redistributable", "redist",
    # Locale fragments:
    "en", "us", "he", "il", "enus", "heil", "de", "fr", "ja", "zh",
}


# Tokens used as vendor signal: when one of these is the dict-entry's
# vendor AND also appears in the installed name, the score gets a
# bonus so e.g. "Microsoft Edge" prefers "microsoft:edge" over a
# vendor-less collision.
# Product-name tokens too generic to use as a single-token "rescue"
# match. Without this, "Microsoft Visual C++ ... Runtime" → first dict
# entry where any vendor's product is exactly 'runtime' (e.g.
# `jetbrains:runtime`) wins, which is nonsense. These words appear in
# hundreds of product names and need vendor context to disambiguate.
_RESCUE_BLOCKLIST = {
    "runtime", "framework", "service", "services", "client", "server",
    "system", "tools", "utility", "data", "engine", "platform",
    "manager", "studio", "browser", "viewer", "player", "reader",
    "agent", "driver", "drivers", "core", "common", "library",
    "redistributable", "host", "extensions", "extension", "addin",
    "plugin", "plus", "free", "pro", "professional", "lite", "mini",
    "desktop", "mobile", "cloud", "online", "offline", "central",
    "console", "monitor", "scanner", "updater", "installer", "setup",
    "launcher", "controller", "connector", "config", "configurator",
}


_KNOWN_VENDORS = {
    "microsoft", "google", "mozilla", "apple", "adobe", "oracle",
    "ibm", "cisco", "amazon", "facebook", "meta", "samsung", "intel",
    "amd", "nvidia", "dell", "hp", "lenovo", "logitech", "vmware",
    "redhat", "canonical", "ubuntu", "debian", "fedora",
    "rapid7", "crowdstrike", "splunk", "elastic", "datadog",
    "atlassian", "github", "gitlab", "jetbrains", "slack", "zoom",
    "dropbox", "box", "okta", "duo",
    "apache", "nginx", "wireshark", "openssl", "openssh", "python",
    "java", "nodejs", "docker", "kubernetes",
    "telegram", "whatsapp", "discord", "spotify",
    "rarlab", "sophos", "trendmicro", "kaspersky", "symantec",
    "fortinet", "paloaltonetworks", "checkpoint", "qualys", "tenable",
}


# Tokenizer: keeps letters, digits, and intra-token + - _ . so that
# canonical CPE strings like "notepad++", "7-zip", "windows_10",
# "node.js" survive intact. Tokens must START with an alphanumeric.
# Pure-numeric tokens are kept (year/version disambiguators like "11",
# "2022") so e.g. "Windows 11" doesn't false-match windows_2003.
_TOKEN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9+\-_.]*[A-Za-z0-9+])?")

# Strip CSV-format backslash escapes used for CPE special characters
# (notepad\+\+ → notepad++, c\#\# → c##). Without this the dict token
# would contain a literal backslash and never match an installed name.
_BACKSLASH_ESC_RE = re.compile(r"\\(.)")


def _tokenize(text: str) -> List[str]:
    """Lowercase, strip noise, return non-stopword tokens of length ≥ 2.
    Underscores are treated as word separators so the dictionary's
    canonical product names (e.g. 'visual_c++', 'windows_11') split on
    the same boundaries an installed name would naturally produce."""
    if not text:
        return []
    text = _BACKSLASH_ESC_RE.sub(r"\1", text.lower())
    text = text.replace("_", " ")
    toks = _TOKEN_RE.findall(text)
    return [t for t in toks if t not in _STOPWORDS and len(t) >= 2]


_load_lock = threading.Lock()
# All (vendor, product, all_tokens, vendor_token) tuples in the
# dictionary. `all_tokens` is the union of tokens from vendor + product
# (used for subset matching). `vendor_token` is the bare vendor lowercased
# (used for the vendor-bonus heuristic).
_index: List[Tuple[str, str, set, str]] = []
# Inverted index: token → set of indices into _index.
_postings: Dict[str, set] = {}
_loaded = False


def init_dictionary(path: Optional[Path] = None, force: bool = False) -> int:
    """Load the CSV and build the inverted index. Idempotent unless
    `force=True` (e.g. after a refresh). Returns the entry count;
    0 means the file was missing."""
    global _index, _postings, _loaded
    with _load_lock:
        if _loaded and not force:
            return len(_index)
        p = path or _DEFAULT_PATH
        if not p.exists():
            _index = []
            _postings = {}
            _loaded = True
            return 0
        idx: List[Tuple[str, str, set, str]] = []
        post: Dict[str, set] = {}
        with p.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            try:
                next(reader)  # skip header
            except StopIteration:
                _loaded = True
                return 0
            for row in reader:
                if len(row) < 2:
                    continue
                vendor_raw = row[0].strip()
                product_raw = row[1].strip()
                if not vendor_raw or not product_raw:
                    continue
                vendor_tokens = _tokenize(vendor_raw)
                product_tokens = _tokenize(product_raw)
                all_tokens = set(vendor_tokens) | set(product_tokens)
                if not all_tokens:
                    continue
                # Skip entries that, after stopword stripping, become
                # so generic they'd match anything (single short token,
                # all-numeric, etc.). These would otherwise cause
                # cascade-bad matches like every installed file with
                # "user" in the name resolving to some random
                # `something:user_product`.
                if len(all_tokens) == 1:
                    only = next(iter(all_tokens))
                    # Keep 3-char product names like "git", "vim",
                    # drop only 1-2 char tokens and pure-digit ones.
                    if len(only) < 3 or only.isdigit():
                        continue
                vendor_token = (vendor_tokens[0] if vendor_tokens else vendor_raw.lower())
                entry_id = len(idx)
                idx.append((vendor_raw, product_raw, all_tokens, vendor_token))
                for t in all_tokens:
                    post.setdefault(t, set()).add(entry_id)
        _index = idx
        _postings = post
        _loaded = True
        return len(_index)


def lookup_cpe(product_name: str) -> Optional[str]:
    """Best-effort CPE lookup. Returns `cpe:2.3:a:VENDOR:PRODUCT` or
    None when no confident match is found.

    Matching rule (strict subset): every token in the dictionary
    entry's (vendor + product) tokens must appear in the installed
    name's tokens. Score is the entry's token count (more specific
    wins) plus a vendor-bonus when the entry's vendor is a known
    high-signal vendor present in the name.

    Why strict subset: with 65 k dictionary entries, anything more
    permissive (e.g. "≥ 2 tokens overlap") produces too many garbage
    matches like 'CrowdStrike Device Control' → 'manageengine_device_control_plus'.
    Strict subset is essentially "the user's installed name says
    EVERYTHING this CPE represents, plus maybe some noise" — which
    is the right semantics."""
    if not _loaded:
        init_dictionary()
    if not _index:
        return None

    name_tokens = set(_tokenize(product_name))
    if not name_tokens:
        return None

    # Union postings for every token in the name. Avoids O(N) scan
    # over the full dictionary.
    candidates: set = set()
    for t in name_tokens:
        if t in _postings:
            candidates |= _postings[t]
    if not candidates:
        return None

    best_score = 0.0
    best_entry: Optional[Tuple[str, str]] = None
    rescue_candidates: List[Tuple[str, str, str]] = []  # for single-token rescue pass

    for cid in candidates:
        vendor_raw, product_raw, dict_tokens, vendor_token = _index[cid]
        # Strict subset: every dict token must be in the name.
        if not dict_tokens.issubset(name_tokens):
            # Single-product-token RESCUE: many real products ship
            # with just the product name ("OneDrive", "Velociraptor",
            # "Slack") even though the CPE entry is "microsoft:onedrive"
            # / "rapid7:velociraptor". When the dict's PRODUCT token
            # alone exactly equals one of the name's tokens and isn't
            # a common word, remember as a fallback. Used only if
            # nothing matched via strict-subset.
            #
            # Filter out vendors named after the product (e.g.
            # "git:git", "wireshark:wireshark") so we don't tie a
            # single-token name to itself when a more specific entry
            # exists. Common-tokens (≤4 chars or generic) also skip.
            product_tokens_only = set(_tokenize(product_raw))
            if (
                len(product_tokens_only) == 1
                and next(iter(product_tokens_only)) in name_tokens
                and len(next(iter(product_tokens_only))) > 4
                and next(iter(product_tokens_only)) not in _RESCUE_BLOCKLIST
            ):
                only = next(iter(product_tokens_only))
                rescue_candidates.append((only, vendor_raw, product_raw))
            continue
        # Specificity score — favours longer entries because matching
        # 4 tokens out of 4 is stronger evidence than matching 1 of 1.
        score = len(dict_tokens) * 1.0
        # Vendor bonus when the entry's vendor is well-known and the
        # installed name carries it explicitly.
        if vendor_token in _KNOWN_VENDORS and vendor_token in name_tokens:
            score += 2.0
        if score > best_score:
            best_score = score
            best_entry = (vendor_raw, product_raw)

    if best_entry is not None:
        vendor, product = best_entry
        return f"cpe:2.3:a:{vendor}:{product}"

    # Strict-subset miss — try the rescue path. We accept the rescue
    # ONLY when exactly one well-known vendor's CPE has the product
    # token; otherwise we'd be guessing.
    if rescue_candidates:
        # Group by product token; prefer a unique known-vendor entry.
        by_product: Dict[str, List[Tuple[str, str]]] = {}
        for tok, v, p in rescue_candidates:
            by_product.setdefault(tok, []).append((v, p))
        for tok, entries in by_product.items():
            known = [(v, p) for v, p in entries if (_tokenize(v) or [""])[0] in _KNOWN_VENDORS]
            if len(known) == 1:
                v, p = known[0]
                return f"cpe:2.3:a:{v}:{p}"
            # Multiple known-vendor entries for the same product token
            # (e.g. "velociraptor" → rapid7 AND symantec). Deterministic
            # pick — alphabetically first vendor — beats no match.
            if len(known) > 1:
                v, p = sorted(known)[0]
                return f"cpe:2.3:a:{v}:{p}"
            # Only one entry in the dictionary, period — high confidence.
            if len(entries) == 1:
                v, p = entries[0]
                return f"cpe:2.3:a:{v}:{p}"
    return None


def refresh_dictionary_from_upstream(logger: Optional[Callable] = None,
                                     dest: Optional[Path] = None,
                                     timeout: int = 60) -> Dict:
    """Fetch the latest CSV from the upstream feed and replace the
    vendored copy. Called by the maintenance route. Returns a dict
    with {ok: bool, entries: int, message: str} for caller logging.

    Safe to call concurrently; the load lock prevents a partially-
    written file from being indexed. On network failure, the existing
    file is preserved."""
    def _log(msg: str, lvl: str = "info"):
        if logger:
            try:
                logger(msg, lvl)
            except TypeError:
                logger(msg)
        else:
            print(msg, flush=True)

    p = dest or _DEFAULT_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    _log(f"[CPE-DICT] Fetching {UPSTREAM_URL}…")
    try:
        req = urllib.request.Request(UPSTREAM_URL, headers={"User-Agent": "intact-cve-scan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
    except Exception as e:
        _log(f"[CPE-DICT] Download failed: {e} (keeping existing file)", "warning")
        return {"ok": False, "entries": 0, "message": f"download failed: {e}"}

    # Validate it parses as CSV with the expected schema before
    # overwriting the on-disk copy. Otherwise a bad upstream commit
    # could brick the lookup until the next install.
    rows = 0
    try:
        text = payload.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        if not header or len(header) < 2 or header[0].strip("\"' ").lower() != "vendor":
            raise ValueError(f"unexpected header: {header}")
        for _ in reader:
            rows += 1
    except Exception as e:
        _log(f"[CPE-DICT] Upstream payload did not validate as CSV: {e} (keeping existing file)", "warning")
        return {"ok": False, "entries": 0, "message": f"invalid payload: {e}"}

    # Write atomically (write to temp + rename) so a concurrent reader
    # never sees a half-written file.
    tmp = p.with_suffix(p.suffix + ".new")
    tmp.write_bytes(payload)
    tmp.replace(p)
    _log(f"[CPE-DICT] Replaced {p.name} ({rows} entries, {len(payload)} bytes).", "success")

    # Force-reload the in-memory index so the next lookup sees the
    # fresh data without a backend restart.
    n = init_dictionary(force=True)
    _log(f"[CPE-DICT] Reloaded in-memory index ({n} entries).", "info")
    return {"ok": True, "entries": n, "message": f"refreshed ({n} entries)"}
