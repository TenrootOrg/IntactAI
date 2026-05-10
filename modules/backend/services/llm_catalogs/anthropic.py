"""Anthropic model catalog.

Anthropic's /v1/models returns id + display_name + created_at + type
only — no max-tokens, no context length, no pricing. Each entry's
`canonical_id` is computed by stripping the trailing date suffix and
prepending `anthropic/`, then the entry is enriched against the
OpenRouter catalog to backfill the rich metadata fields.
"""

import re
from typing import Callable, Dict, Optional

import requests

from .base import CatalogStore, enrich_from_openrouter, get_provider_api_key

CATALOG_PATH = "/app/data/anthropic_models.json"
MODELS_URL = "https://api.anthropic.com/v1/models"
ANTHROPIC_VERSION = "2023-06-01"
FETCH_TIMEOUT_SEC = 30

# Known divergences between Anthropic's native id format and OpenRouter's
# catalog id. Currently driven by the dot-vs-dash convention difference
# in the Claude 3.5 / 3.7 generations. Add entries here when a new
# Anthropic family ships and we observe the join failing.
KNOWN_RENAMES = {
    # native -> openrouter
    "claude-3-5-sonnet": "claude-3.5-sonnet",
    "claude-3-5-haiku": "claude-3.5-haiku",
    "claude-3-7-sonnet": "claude-3.7-sonnet",
}

_DATE_SUFFIX_RE = re.compile(r"-\d{8}$")  # -YYYYMMDD

store = CatalogStore("anthropic", CATALOG_PATH, MODELS_URL)


def to_canonical(native_id: str) -> str:
    """Convert an Anthropic native model id (often with a -YYYYMMDD
    suffix) into the OpenRouter join key `anthropic/<family>`."""
    base = _DATE_SUFFIX_RE.sub("", native_id or "")
    base = KNOWN_RENAMES.get(base, base)
    return f"anthropic/{base}"


def _normalize(raw: Dict) -> Optional[Dict]:
    mid = raw.get("id")
    if not mid:
        return None
    # Anthropic hints deprecation by tagging the display name; surface it.
    display = raw.get("display_name") or mid
    deprecated = "(deprecated)" in display.lower() or "deprecated" in display.lower()
    # `created_at` is ISO; convert best-effort to unix ts; leave None on
    # parse failure rather than crashing the whole refresh.
    created = None
    if raw.get("created_at"):
        try:
            from datetime import datetime
            created = int(datetime.fromisoformat(raw["created_at"].replace("Z", "+00:00")).timestamp())
        except Exception:
            created = None
    return {
        "id": mid,
        "canonical_id": to_canonical(mid),
        "name": display,
        "max_output_tokens": None,  # filled by enrich_from_openrouter
        "context_length": None,
        "pricing": None,
        "created": created,
        "deprecated": deprecated,
        "enriched_from": "pending",
    }


def refresh_catalog(logger: Optional[Callable] = None, api_key: Optional[str] = None) -> Dict:
    """Fetch Anthropic's model list, normalize, enrich from OpenRouter,
    persist. Returns summary dict.

    `api_key` may be supplied by the caller; otherwise we look it up
    from the saved frontend config (which only has it when the operator
    is currently using `claude` as their provider).
    """
    log = logger or (lambda msg, level="info": print(f"[ANTHROPIC-CATALOG] [{level}] {msg}", flush=True))
    key = api_key or get_provider_api_key("claude")
    if not key:
        log("No Anthropic API key configured — skipping catalog refresh", "warning")
        return {"success": False, "model_count": 0, "error": "no API key"}

    log(f"Fetching Anthropic model catalog from {MODELS_URL}...")
    try:
        resp = requests.get(
            MODELS_URL,
            headers={"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION},
            timeout=FETCH_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        upstream = resp.json()
    except Exception as e:
        log(f"Fetch failed: {e}", "warning")
        return {"success": False, "model_count": 0, "error": str(e)}

    raw_models = upstream.get("data") or []
    models = [m for m in (_normalize(r) for r in raw_models) if m]
    unenriched = enrich_from_openrouter(models)
    if unenriched:
        log(f"{unenriched}/{len(models)} entries had no OpenRouter match — metadata fields null", "info")
    summary = store.write(models, unenriched_count=unenriched)
    log(f"Catalog refreshed: {summary['model_count']} models written to {CATALOG_PATH}")
    return summary


def search(q: str = "", limit: int = 10, offset: int = 0) -> Dict:
    return store.search(q=q, limit=limit, offset=offset)


def catalog_status() -> Dict:
    return store.status()


def load_catalog():
    return store.load()
