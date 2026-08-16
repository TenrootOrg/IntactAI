"""Shared catalog IO + enrichment helpers.

Each provider module imports `CatalogStore` for atomic-write +
mtime-cached read + paginated search, and `enrich_from_openrouter` to
backfill rich metadata onto direct-provider entries.
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional


class CatalogStore:
    """Thin file-backed store for one provider's model catalog.

    Same on-disk shape across all four providers — see
    services/llm_catalogs/__init__.py for the per-entry schema.
    """

    def __init__(self, provider: str, file_path: str, source_url: str):
        self.provider = provider
        self.file_path = file_path
        self.source_url = source_url
        # In-memory cache so repeat reads on a single backend process don't
        # hit the disk. Reset on backend restart, which is fine — disk
        # file persists.
        self._cache: Dict = {"models": [], "mtime": 0.0, "fetched_at": 0.0}

    def write(self, models: List[Dict], unenriched_count: int = 0) -> Dict:
        """Atomically write the catalog file. Returns summary dict.

        Refuses to replace an existing catalog with an EMPTY one. A fetch can
        succeed at the HTTP level and still yield nothing usable — an auth
        error rendered as `{}`, or an upstream schema change that makes every
        entry fail _normalize. Writing that would swap a working 400-model
        catalog for zero models and report success, and the damage is silent:
        pricing reads 0.00 and context windows fall back to a constant. The
        previous catalog is strictly better than nothing, so it stays.
        """
        if not models:
            existing = self.load()
            if existing:
                return {"success": False, "model_count": len(existing),
                        "error": "refused to overwrite the existing catalog "
                                 f"({len(existing)} models) with an empty one"}
        payload = {
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": self.source_url,
            "model_count": len(models),
            "unenriched_count": unenriched_count,
            "models": models,
        }
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        tmp = self.file_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(payload, f, separators=(",", ":"))
        os.replace(tmp, self.file_path)
        # Bust the in-memory cache so the next load() picks up the new file.
        self._cache["models"] = []
        self._cache["mtime"] = 0.0
        return {
            "success": True,
            "model_count": len(models),
            "unenriched_count": unenriched_count,
            "fetched_at": payload["fetched_at"],
        }

    def load(self) -> List[Dict]:
        """Return the cached model list. Reads the file on first call (or
        when mtime has changed). Returns [] if the file doesn't exist —
        the caller should treat that as 'not yet refreshed' and either
        bootstrap-fetch or fall back to the alias options."""
        if not os.path.exists(self.file_path):
            return []
        mtime = os.path.getmtime(self.file_path)
        if self._cache["models"] and self._cache["mtime"] == mtime:
            return self._cache["models"]
        try:
            with open(self.file_path) as f:
                payload = json.load(f)
            models = payload.get("models") or []
            self._cache["models"] = models
            self._cache["mtime"] = mtime
            self._cache["fetched_at"] = time.time()
            return models
        except Exception as e:
            print(f"[{self.provider.upper()}-CATALOG] Failed to read {self.file_path}: {e}", flush=True)
            return []

    @staticmethod
    def _selectable(m: Dict) -> bool:
        """Should this model be offerable in the model picker?

        Drops rows we cannot put a number against, and ONLY those:

          - `openrouter/auto`, `/fusion`, `/pareto-code`, … are routers. The
            price depends on whichever model the router picks at request time,
            so no cost estimate shown before the run can be honest.
          - `google/lyria-*` are music-generation models that carry no token
            pricing and are not text LLMs at all.

        A `:free` model is KEPT: $0 is its real price, not missing data. The
        caller renders it as "free" rather than as a blank price.
        """
        pricing = m.get("pricing") or {}
        try:
            has_price = (float(pricing.get("prompt") or 0) > 0
                         or float(pricing.get("completion") or 0) > 0)
        except (TypeError, ValueError):
            has_price = False
        return has_price or str(m.get("id", "")).endswith(":free")

    def search(self, q: str = "", limit: int = 10, offset: int = 0) -> Dict:
        """Substring-filter the catalog by id+name, paginated.

        Unpriceable models are filtered out here rather than at refresh time,
        so the on-disk catalog stays a faithful mirror of upstream and
        _estimate_llm_cost can still resolve anything already configured.
        """
        models = [m for m in self.load() if self._selectable(m)]
        catalog_meta = {}
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path) as f:
                    p = json.load(f)
                catalog_meta = {
                    "fetched_at": p.get("fetched_at"),
                    "model_count": p.get("model_count", len(models)),
                    "unenriched_count": p.get("unenriched_count", 0),
                }
            except Exception:
                pass

        q_lower = (q or "").strip().lower()
        if q_lower:
            matches = [m for m in models
                       if q_lower in m["id"].lower()
                       or q_lower in (m.get("name") or "").lower()
                       or q_lower in (m.get("canonical_id") or "").lower()]
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

    def status(self) -> Dict:
        """Return a summary of the on-disk catalog (operator sees this in
        the maintenance UI). Doesn't trigger a fetch."""
        if not os.path.exists(self.file_path):
            return {"present": False, "model_count": 0, "provider": self.provider}
        try:
            with open(self.file_path) as f:
                payload = json.load(f)
            return {
                "present": True,
                "provider": self.provider,
                "model_count": payload.get("model_count", 0),
                "unenriched_count": payload.get("unenriched_count", 0),
                "fetched_at": payload.get("fetched_at"),
                "source": payload.get("source"),
            }
        except Exception as e:
            return {"present": True, "provider": self.provider, "error": str(e), "model_count": 0}


def enrich_from_openrouter(entries: List[Dict]) -> int:
    """Look up each entry by canonical_id in the OpenRouter catalog and
    backfill name/max_output_tokens/context_length/pricing in place.
    No-op for entries already enriched ('native' = OpenRouter's own).

    Returns count of entries that *failed* to find a match (so the
    refresh summary can warn the operator).
    """
    # Local import — openrouter module imports base, so we'd recurse
    # if this lived at module top.
    from services.llm_catalogs import openrouter as openrouter_module

    or_models = openrouter_module.store.load()
    or_by_id = {m["id"]: m for m in or_models}

    unenriched = 0
    for e in entries:
        if e.get("enriched_from") == "native":
            continue  # OpenRouter's own catalog; nothing to enrich
        match = or_by_id.get(e.get("canonical_id"))
        if not match:
            e["enriched_from"] = "native_only"
            unenriched += 1
            continue
        # Native name wins if the provider gave us one; otherwise borrow
        # OpenRouter's prettier display name.
        if not e.get("name"):
            e["name"] = match.get("name")
        e["max_output_tokens"] = match.get("max_output_tokens")
        e["context_length"] = match.get("context_length")
        e["pricing"] = match.get("pricing")
        e["enriched_from"] = "openrouter"
    return unenriched


def get_provider_api_key(provider: str) -> Optional[str]:
    """Pull the API key for the given provider from the saved frontend
    config. The config only stores one `online_llm.api_key` tied to
    whichever provider is currently selected — so this returns the key
    only when the operator is currently using that provider, and None
    otherwise. Direct-provider catalog refresh degrades gracefully when
    None is returned.
    """
    try:
        from services.file_storage_service import load_frontend_config
        cfg = load_frontend_config() or {}
        online = (cfg.get("agentic") or {}).get("online_llm") or {}
        if online.get("provider") == provider:
            key = online.get("api_key") or ""
            return key.strip() or None
    except Exception:
        pass
    return None
