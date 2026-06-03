"""OpenRouter model catalog.

Source of truth for the dropdown's full ~300-model list AND the
metadata-enrichment source for the three direct-provider catalogs.
Each entry's `id == canonical_id` (OpenRouter's id format IS the
canonical join key), and `enriched_from = "native"` since OpenRouter's
own response carries every metadata field we need.
"""

import os
from typing import Callable, Dict, Optional

import requests

from .base import CatalogStore

CATALOG_PATH = "/app/data/openrouter_models.json"
MODELS_URL = "https://openrouter.ai/api/v1/models"
FETCH_TIMEOUT_SEC = 30

store = CatalogStore("openrouter", CATALOG_PATH, MODELS_URL)


def _normalize(raw: Dict) -> Optional[Dict]:
    """Project the upstream OpenRouter entry onto the shared schema."""
    mid = raw.get("id")
    if not mid:
        return None
    top_provider = raw.get("top_provider") or {}
    return {
        "id": mid,
        "canonical_id": mid,  # OpenRouter id IS the canonical key
        "name": raw.get("name") or mid,
        "max_output_tokens": top_provider.get("max_completion_tokens"),
        "context_length": raw.get("context_length"),
        "pricing": raw.get("pricing"),
        "created": raw.get("created", 0),
        "deprecated": False,  # OpenRouter doesn't surface a deprecated flag
        "enriched_from": "native",
    }


def refresh_catalog(logger: Optional[Callable] = None, **_kwargs) -> Dict:
    """Fetch the full OpenRouter model list and write it to disk.

    Returns a summary dict: {success, model_count, fetched_at, error}.
    Best-effort — if the network call fails, returns success=False
    without raising. Operators see the warning in install/maintenance
    logs but the existing on-disk catalog keeps serving the UI.

    `**_kwargs` accepts but ignores `api_key=…` so the maintenance
    runner can call every provider's refresh_catalog uniformly.
    """
    log = logger or (lambda msg, level="info": print(f"[OPENROUTER-CATALOG] [{level}] {msg}", flush=True))
    log(f"Fetching OpenRouter model catalog from {MODELS_URL}...")
    try:
        resp = requests.get(MODELS_URL, timeout=FETCH_TIMEOUT_SEC)
        resp.raise_for_status()
        upstream = resp.json()
    except Exception as e:
        log(f"Fetch failed: {e}", "warning")
        return {"success": False, "model_count": 0, "error": str(e)}

    raw_models = upstream.get("data") or []
    models = [m for m in (_normalize(r) for r in raw_models) if m]
    summary = store.write(models, unenriched_count=0)
    log(f"Catalog refreshed: {summary['model_count']} models written to {CATALOG_PATH}")
    return summary


def load_catalog():
    """Back-compat: return the model list as a flat list (the way the old
    services/openrouter_catalog.py exposed it)."""
    return store.load()


def search(q: str = "", limit: int = 10, offset: int = 0) -> Dict:
    return store.search(q=q, limit=limit, offset=offset)


def catalog_status() -> Dict:
    return store.status()
