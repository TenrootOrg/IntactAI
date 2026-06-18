"""Token budgeting for the LLM boundary — deliberately tokenizer-free.

An airgapped appliance has no accurate offline tokenizer (tiktoken mis-counts
Claude by 15-20%; Anthropic ``count_tokens`` needs network). So we use a coarse
``chars/4`` UPPER-BOUND only as a pre-send budget *guard* (decides whether to drop
to a smaller distillation tier). The single source of truth for real cost is the
provider's ``response.usage`` recorded post-call via ``record_llm_metrics``.
"""

from __future__ import annotations

import json
import math

# Per-altitude entity caps (the report narrates the whole case; chat narrates a
# question-scoped subgraph, so it needs far fewer).
REPORT_MAX_ENTITIES = 60
CHAT_MAX_ENTITIES = 20

# Char budgets for the distilled payload SENT TO THE LLM (~4 chars/token, so
# report ≈ 8k-token ceiling, chat ≈ 3k). Tripwires, not hard truncation.
REPORT_BUDGET_CHARS = 32_000
CHAT_BUDGET_CHARS = 12_000

# Max distillation step-downs before we send what we have.
MAX_STEPDOWNS = 2


def approx_tokens(text) -> int:
    """Coarse upper-bound token estimate. NOT a billed number — label any stored
    value `_approx`. Real counts come from `response.usage`."""
    s = text if isinstance(text, str) else json.dumps(text, default=str)
    return math.ceil(len(s) / 4)


def over_budget(payload, budget_chars: int) -> bool:
    s = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return len(s) > budget_chars
