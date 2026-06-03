"""Back-compat shim — the OpenRouter catalog moved to
`services.llm_catalogs.openrouter` so it lives next to the three new
direct-provider catalogs (anthropic, openai, gemini). Re-exports the
public surface so existing imports keep working.
"""

from services.llm_catalogs.openrouter import (  # noqa: F401
    CATALOG_PATH,
    MODELS_URL as OPENROUTER_MODELS_URL,
    refresh_catalog,
    load_catalog,
    search,
    catalog_status,
)
