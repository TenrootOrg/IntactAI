"""LLM model catalogs — one persistent dictionary per provider.

Each catalog is a JSON snapshot of the provider's live model listing,
fetched at install time and refreshed by the maintenance workflow. The
dashboard's model selector (Settings → Agentic) reads them through
`/api/config/<provider>/models?q=…&limit=10` so operators can search the
full live list while typing — not a hardcoded select.

Per-entry schema (same shape across all four providers):

    {"id":            "<native id sent to the provider's API>",
     "canonical_id":  "<vendor>/<family-no-date>",
     "name":          "<human readable>",
     "max_output_tokens": <int|null>,
     "context_length":    <int|null>,
     "pricing":           {"prompt": "<usd-per-token>", ...} | null,
     "created":           <unix-ts|null>,
     "deprecated":        <bool>,
     "enriched_from":     "native" | "openrouter" | "native_only"}

OpenRouter is the metadata source for every direct-provider catalog —
direct providers' /v1/models endpoints return barebones data (id +
created_at + a display name), so each direct-provider refresh joins
against the OpenRouter catalog on `canonical_id` to backfill name /
max_output_tokens / context_length / pricing. If a direct-provider
model has no OpenRouter match (e.g. brand-new release not yet
mirrored), the entry survives with `enriched_from = "native_only"` and
metadata fields null — operator can still pick it; the resolver falls
back to MAX_LLM_TOKENS.

Refresh order matters: OpenRouter must be refreshed before the three
direct-provider catalogs so the enrichment source exists.
"""

from . import base, openrouter, anthropic, openai, gemini

__all__ = ["base", "openrouter", "anthropic", "openai", "gemini"]
