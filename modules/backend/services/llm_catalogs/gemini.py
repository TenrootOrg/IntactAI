"""Gemini (Google Generative AI) model catalog.

Google's /v1beta/models endpoint returns rich metadata (`displayName`,
`inputTokenLimit`, `outputTokenLimit`, `supportedGenerationMethods`)
but no pricing or `created` timestamp. Each entry is filtered to
`generateContent`-capable models (drops embedding/tuning), then enriched
from OpenRouter for pricing — the native max_output_tokens and context
length come straight from Gemini's response.
"""

import re
from typing import Callable, Dict, Optional

import requests

from .base import CatalogStore, enrich_from_openrouter, get_provider_api_key

CATALOG_PATH = "/app/data/gemini_models.json"
MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
FETCH_TIMEOUT_SEC = 30

# Strip trailing revision suffixes like `-001`, `-002`. Drop only when
# the suffix follows a non-numeric segment to avoid mangling versions
# like `gemini-1.5-pro` (the `1.5` is not a revision).
_REVISION_SUFFIX_RE = re.compile(r"-(\d{3})$")
# `models/` prefix is part of every Gemini id when fetched via REST.
_MODELS_PREFIX = "models/"

# Known divergences between Gemini's native id and OpenRouter's catalog.
# Gemini sometimes uses `-latest` aliases internally; OpenRouter mirrors
# specific generations. Add as observed.
KNOWN_RENAMES = {
    # native -> openrouter
    "gemini-2.5-flash-preview": "gemini-2.5-flash-preview",
    "gemini-2.5-pro-preview": "gemini-2.5-pro-preview",
}

store = CatalogStore("gemini", CATALOG_PATH, MODELS_URL)


def _strip_models_prefix(mid: str) -> str:
    return mid[len(_MODELS_PREFIX):] if mid.startswith(_MODELS_PREFIX) else mid


def to_canonical(native_id: str) -> str:
    base = _strip_models_prefix(native_id or "")
    base = _REVISION_SUFFIX_RE.sub("", base)
    base = KNOWN_RENAMES.get(base, base)
    return f"google/{base}"


def _supports_generate_content(raw: Dict) -> bool:
    methods = raw.get("supportedGenerationMethods") or []
    return "generateContent" in methods


def _normalize(raw: Dict) -> Optional[Dict]:
    mid = raw.get("name")  # Gemini uses `name`, not `id`
    if not mid or not _supports_generate_content(raw):
        return None
    # Strip the `models/` prefix so the id matches what callers send
    # to the SDK (`gemini-2.5-pro`, not `models/gemini-2.5-pro`).
    bare = _strip_models_prefix(mid)
    return {
        "id": bare,
        "canonical_id": to_canonical(mid),
        "name": raw.get("displayName") or bare,
        # Gemini publishes outputTokenLimit directly — use it; enrichment
        # won't overwrite a non-null value (or will overwrite with the
        # OpenRouter-mirrored value if present, which usually matches).
        "max_output_tokens": raw.get("outputTokenLimit"),
        "context_length": raw.get("inputTokenLimit"),
        "pricing": None,  # not in Gemini's response — pulled from OpenRouter
        "created": None,  # not in Gemini's response
        "deprecated": False,
        "enriched_from": "pending",
    }


def refresh_catalog(logger: Optional[Callable] = None, api_key: Optional[str] = None) -> Dict:
    log = logger or (lambda msg, level="info": print(f"[GEMINI-CATALOG] [{level}] {msg}", flush=True))
    key = api_key or get_provider_api_key("gemini")
    if not key:
        log("No Gemini API key configured — skipping catalog refresh", "warning")
        return {"success": False, "model_count": 0, "error": "no API key"}

    log(f"Fetching Gemini model catalog from {MODELS_URL}...")
    try:
        resp = requests.get(
            MODELS_URL,
            params={"key": key, "pageSize": 200},
            timeout=FETCH_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        upstream = resp.json()
    except Exception as e:
        log(f"Fetch failed: {e}", "warning")
        return {"success": False, "model_count": 0, "error": str(e)}

    raw_models = upstream.get("models") or []
    models = []
    for r in raw_models:
        n = _normalize(r)
        if n:
            models.append(n)
    # Enrichment fills pricing / overrides max_output_tokens with the
    # OpenRouter value when available. We preserve Gemini's native
    # max_output_tokens for entries with no OpenRouter match.
    pre_enrich_max = {m["id"]: m["max_output_tokens"] for m in models}
    unenriched = enrich_from_openrouter(models)
    # Restore native max_output_tokens for entries that ended up with
    # null after enrichment (OpenRouter match existed but didn't
    # include the field).
    for m in models:
        if m.get("max_output_tokens") is None and pre_enrich_max.get(m["id"]):
            m["max_output_tokens"] = pre_enrich_max[m["id"]]
    if unenriched:
        log(f"{unenriched}/{len(models)} entries had no OpenRouter match — pricing null, native max kept", "info")
    summary = store.write(models, unenriched_count=unenriched)
    log(f"Catalog refreshed: {summary['model_count']} models written to {CATALOG_PATH}")
    return summary


def search(q: str = "", limit: int = 10, offset: int = 0) -> Dict:
    return store.search(q=q, limit=limit, offset=offset)


def catalog_status() -> Dict:
    return store.status()


def load_catalog():
    return store.load()
