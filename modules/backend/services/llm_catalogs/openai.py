"""OpenAI model catalog.

OpenAI's /v1/models returns ~80 entries spanning chat, embeddings,
audio, image, and tuning models. We filter to chat/completion-capable
ids only so the dropdown stays useful (operators don't want
`text-embedding-3-large` showing up).

Native ids carry an optional date suffix (`gpt-5.5-2026-04-01`); strip
it for the canonical join key. OpenAI doesn't publish max-tokens,
context length, or pricing in the listing endpoint — entries are
enriched from the OpenRouter catalog.
"""

import re
from typing import Callable, Dict, Optional

import requests

from .base import CatalogStore, enrich_from_openrouter, get_provider_api_key

CATALOG_PATH = "/app/data/openai_models.json"
MODELS_URL = "https://api.openai.com/v1/models"
FETCH_TIMEOUT_SEC = 30

# Filter to id prefixes operators would actually pick for chat/completion.
# Keeps the dropdown focused — drops embeddings, audio, image, tuning.
_CHAT_PREFIXES = ("gpt-", "o1", "o3", "o4", "chatgpt-")

# Strip OpenAI's two date-suffix shapes:
#   gpt-4o-2024-11-20         (-YYYY-MM-DD)
#   gpt-5.5-preview-0514      (-MMDD)  — rarer, used for previews
_DATE_SUFFIX_RE = re.compile(r"-(\d{4}-\d{2}-\d{2}|\d{4})$")

# Known divergences — rare for OpenAI; keep slot ready for when one shows up.
KNOWN_RENAMES: Dict[str, str] = {}

store = CatalogStore("openai", CATALOG_PATH, MODELS_URL)


def _is_chat_model(mid: str) -> bool:
    if not mid:
        return False
    if any(mid.startswith(p) for p in _CHAT_PREFIXES):
        # Drop obvious non-chat siblings even within the chat prefixes
        if mid.endswith("-tts") or mid.endswith("-transcribe") or "-audio-" in mid:
            return False
        if "-realtime" in mid or "-image" in mid:
            return False
        return True
    return False


def to_canonical(native_id: str) -> str:
    base = _DATE_SUFFIX_RE.sub("", native_id or "")
    base = KNOWN_RENAMES.get(base, base)
    return f"openai/{base}"


def _normalize(raw: Dict) -> Optional[Dict]:
    mid = raw.get("id")
    if not mid or not _is_chat_model(mid):
        return None
    return {
        "id": mid,
        "canonical_id": to_canonical(mid),
        # OpenAI doesn't return a friendly name; the id IS the display
        # most operators recognise (`gpt-4o`, `o1-2024-12-17`). Catalog
        # enrichment can swap in OpenRouter's prettier name if matched.
        "name": mid,
        "max_output_tokens": None,
        "context_length": None,
        "pricing": None,
        "created": raw.get("created"),
        "deprecated": False,
        "enriched_from": "pending",
    }


def refresh_catalog(logger: Optional[Callable] = None, api_key: Optional[str] = None) -> Dict:
    log = logger or (lambda msg, level="info": print(f"[OPENAI-CATALOG] [{level}] {msg}", flush=True))
    key = api_key or get_provider_api_key("openai")
    if not key:
        log("No OpenAI API key configured — skipping catalog refresh", "warning")
        return {"success": False, "model_count": 0, "error": "no API key"}

    log(f"Fetching OpenAI model catalog from {MODELS_URL}...")
    try:
        resp = requests.get(
            MODELS_URL,
            headers={"Authorization": f"Bearer {key}"},
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
