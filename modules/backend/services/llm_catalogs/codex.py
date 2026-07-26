"""Codex (subscription) model catalog.

Sourced from the CLI itself — `codex debug models` renders the catalog it will
actually accept — rather than from an HTTP endpoint. That distinction is the
whole point of this module: the vendor's web /models endpoint answers happily
with slugs like `gpt-5-5`, but `codex exec -m gpt-5-5` is refused with "not
supported when using Codex with a ChatGPT account". The CLI's own catalog is
the list whose entries work, and it is scoped to the connected account.

Consequences of the source being a subprocess rather than a URL:
  * refresh needs the CLI installed AND a connected subscription; both are
    ordinary "not yet" states, reported as success=False rather than raised.
  * there is no API key anywhere in this path.
  * pricing stays empty: a subscription is not metered per token, so quoting
    $/M here would be a lie. Context window comes from the catalog itself.

An empty model setting remains valid and is the default: the CLI then picks a
model for the plan. This catalog is for operators who want to pin one.
"""

from typing import Callable, Dict, List, Optional

from .base import CatalogStore

CATALOG_PATH = "/app/data/codex_models.json"
PROVIDER_ID = "codex-subscription"

# `codex debug models` is a local subprocess, so there is no URL. CatalogStore
# records the source for the status line; name the command instead.
store = CatalogStore("codex", CATALOG_PATH, "codex debug models")


def to_canonical(native_id: str) -> str:
    return f"openai/{(native_id or '').strip()}"


def _normalize(raw: Dict) -> Optional[Dict]:
    slug = raw.get("slug")
    if not slug:
        return None
    # `visibility` hides entries the picker should not show (internal variants).
    if str(raw.get("visibility") or "list").lower() not in ("list", "visible", ""):
        return None
    efforts = [e.get("effort") for e in (raw.get("supported_reasoning_levels") or [])
               if isinstance(e, dict) and e.get("effort")]
    return {
        "id": slug,
        "canonical_id": to_canonical(slug),
        "name": raw.get("display_name") or slug,
        "context_length": raw.get("context_window") or raw.get("max_context_window"),
        # the catalog publishes no per-response cap; the context window is the
        # meaningful number for an operator sizing a case payload
        "max_output_tokens": None,
        "pricing": {},          # subscription: not metered per token
        "created": None,
        "deprecated": False,
        "enriched_from": "codex-cli",
        "description": (raw.get("description") or "")[:200] or None,
        "reasoning_levels": efforts or None,
        "default_reasoning_level": raw.get("default_reasoning_level"),
    }


def refresh_catalog(logger: Optional[Callable] = None, api_key: Optional[str] = None) -> Dict:
    """Re-read the catalog from the CLI and persist it.

    `api_key` is accepted only so the maintenance route can call every catalog
    module uniformly; this provider has none.
    """
    log = logger or (lambda m, l="info": print(f"[CATALOG] codex: {m}", flush=True))
    try:
        from services.agentic import subscription_cli as sub
        raw_models: List[Dict] = sub.list_models(PROVIDER_ID)
    except Exception as e:  # noqa: BLE001 — includes SubscriptionCLIError
        reason = getattr(e, "reason", "")
        if reason == "cli_not_installed":
            msg = "the Codex CLI is not installed — install it in Settings → Agentic"
        elif reason == "cli_not_authenticated":
            msg = "the Codex subscription is not connected — sign in from Settings → Agentic"
        else:
            msg = str(e)
        log(f"refresh skipped: {msg}", "warning")
        return {"success": False, "model_count": 0, "error": msg}

    models = [m for m in (_normalize(r) for r in raw_models) if m]
    if not models:
        return {"success": False, "model_count": 0,
                "error": "the CLI returned an empty catalog"}

    summary = store.write(models, unenriched_count=0)
    log(f"stored {len(models)} model(s) the subscription can use")
    return summary


def search(q: str = "", limit: int = 10, offset: int = 0) -> Dict:
    return store.search(q=q, limit=limit, offset=offset)


def catalog_status() -> Dict:
    return store.status()


def load_catalog():
    return store.load()
