#!/usr/bin/env python3
"""
OpenRouter model catalog — persistent dictionary of every model OpenRouter
exposes via its public `/api/v1/models` endpoint, fetched at install time
and refreshed via the maintenance workflow.

The dashboard's model selector reads this catalog (via the
`/api/config/openrouter/models` endpoint) so an operator gets the full
300+ model list when typing in the model field — not the heavily
filtered "anthropic / openai / google / qwen, 2 newest per family" cut
that the prior in-memory cache returned.

File layout:
    /app/data/openrouter_models.json — persistent catalog snapshot
        {
          "fetched_at": "2026-05-10T12:34:56Z",
          "source": "https://openrouter.ai/api/v1/models",
          "model_count": 327,
          "models": [
            {"id": "...", "name": "...", "created": 1234567890,
             "context_length": 200000, "pricing": {...}},
            ...
          ]
        }

Operations:
    refresh_catalog(logger=None) — fetch, write file, return summary dict
    load_catalog()              — read file, return models list (cached
                                  in-memory after first load)
    search(q, limit, offset)    — substring filter on id+name, paginated
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

import requests

CATALOG_PATH = "/app/data/openrouter_models.json"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
FETCH_TIMEOUT_SEC = 30

# In-memory cache so repeat reads on a single backend process don't hit
# the disk. Reset on backend restart, which is fine — disk file persists.
_cache: Dict = {"models": [], "fetched_at": 0.0, "mtime": 0.0}


def refresh_catalog(logger: Optional[Callable] = None) -> Dict:
    """Fetch the full OpenRouter model list and write it to CATALOG_PATH.

    Returns a summary dict: {success, model_count, fetched_at, error}.
    Best-effort — if the network call fails, the function logs and
    returns success=False without raising. The caller decides whether
    to surface the failure (install logs warn, maintenance run fails).
    """
    log = logger or (lambda msg, level="info": print(f"[OPENROUTER-CATALOG] [{level}] {msg}", flush=True))

    log(f"Fetching OpenRouter model catalog from {OPENROUTER_MODELS_URL}...")
    try:
        resp = requests.get(OPENROUTER_MODELS_URL, timeout=FETCH_TIMEOUT_SEC)
        resp.raise_for_status()
        upstream = resp.json()
    except Exception as e:
        log(f"Fetch failed: {e}", "warning")
        return {"success": False, "model_count": 0, "error": str(e)}

    raw_models = upstream.get("data") or []
    # Keep the fields the UI + downstream resolver actually use. Drop
    # the rest (per-provider routing detail, instruct templates, etc.)
    # so the file stays small and reads are fast.
    models = []
    for m in raw_models:
        mid = m.get("id")
        if not mid:
            continue
        models.append({
            "id": mid,
            "name": m.get("name") or mid,
            "created": m.get("created", 0),
            "context_length": m.get("context_length"),
            "pricing": m.get("pricing"),  # operators want to see $$ at glance
        })

    payload = {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": OPENROUTER_MODELS_URL,
        "model_count": len(models),
        "models": models,
    }

    os.makedirs(os.path.dirname(CATALOG_PATH), exist_ok=True)
    tmp = CATALOG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(payload, f, separators=(",", ":"))
    os.replace(tmp, CATALOG_PATH)

    # Bust the in-memory cache so the next load() picks up the new file.
    _cache["models"] = []
    _cache["mtime"] = 0.0

    log(f"Catalog refreshed: {len(models)} models written to {CATALOG_PATH}")
    return {
        "success": True,
        "model_count": len(models),
        "fetched_at": payload["fetched_at"],
    }


def load_catalog() -> List[Dict]:
    """Return the cached model list. Reads the file on first call (or
    when the file's mtime has changed since the last read). Returns []
    if the file doesn't exist — the caller should treat that as
    "operator hasn't run install yet" and either bootstrap-fetch or
    show an empty dropdown."""
    if not os.path.exists(CATALOG_PATH):
        return []

    mtime = os.path.getmtime(CATALOG_PATH)
    if _cache["models"] and _cache["mtime"] == mtime:
        return _cache["models"]

    try:
        with open(CATALOG_PATH) as f:
            payload = json.load(f)
        models = payload.get("models") or []
        _cache["models"] = models
        _cache["mtime"] = mtime
        _cache["fetched_at"] = time.time()
        return models
    except Exception as e:
        print(f"[OPENROUTER-CATALOG] Failed to read {CATALOG_PATH}: {e}", flush=True)
        return []


def search(q: str = "", limit: int = 10, offset: int = 0) -> Dict:
    """Substring-filter the catalog by id+name, paginated.

    Args:
        q: case-insensitive substring; empty string returns the full
           catalog (paginated).
        limit: max results to return (the UI's "show 10 each time").
        offset: skip this many matches (for "show more").

    Returns:
        {"models": [...], "total": <int>, "model_count": <int>,
         "limit": <int>, "offset": <int>, "fetched_at": "..."}
    """
    models = load_catalog()
    catalog_meta = {}
    if os.path.exists(CATALOG_PATH):
        try:
            with open(CATALOG_PATH) as f:
                p = json.load(f)
            catalog_meta = {
                "fetched_at": p.get("fetched_at"),
                "model_count": p.get("model_count", len(models)),
            }
        except Exception:
            pass

    q_lower = (q or "").strip().lower()
    if q_lower:
        matches = [m for m in models
                   if q_lower in m["id"].lower()
                   or q_lower in (m.get("name") or "").lower()]
    else:
        matches = list(models)

    total = len(matches)
    page = matches[offset:offset + max(1, int(limit))]

    return {
        "models": page,
        "total": total,
        "limit": limit,
        "offset": offset,
        **catalog_meta,
    }


def catalog_status() -> Dict:
    """Return a summary of the on-disk catalog (operator sees this in
    the maintenance UI). Doesn't trigger a fetch."""
    if not os.path.exists(CATALOG_PATH):
        return {"present": False, "model_count": 0}
    try:
        with open(CATALOG_PATH) as f:
            payload = json.load(f)
        return {
            "present": True,
            "model_count": payload.get("model_count", 0),
            "fetched_at": payload.get("fetched_at"),
            "source": payload.get("source"),
        }
    except Exception as e:
        return {"present": True, "error": str(e), "model_count": 0}
