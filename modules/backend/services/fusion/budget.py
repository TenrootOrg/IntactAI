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


# --------------------------------------------------------------------------
# Adaptive budget — always on (was the per-case "Use the model's full context").
# --------------------------------------------------------------------------
# The constants above are hand-picked for a hypothetical ~128k-context model and
# never consult the model actually selected. That is wrong in BOTH directions:
# against a 272k model the report is trimmed to ~37% of what would fit, while
# against a small local model (8k Ollama) the same constants would happily build
# a payload that overflows it outright.
#
# When enabled, the budget is derived from the real context window instead:
#
#     usable = context - output_cap - SYSTEM_PROMPT_RESERVE
#     budget = usable * CONTEXT_UTILISATION
#
# Two deliberate safety margins, because over-filling a context does not fail
# gracefully — the provider rejects the call, or silently truncates the middle:
#   * the output cap is subtracted, since context is shared input+output;
#   * approx_tokens() is a chars/4 ESTIMATE, so CONTEXT_UTILISATION leaves room
#     for it being wrong (real tokenizers run ~10-20% over this for dense JSON).
#
# Long-context retrieval also degrades ("lost in the middle"), so filling the
# window is not automatically better than a curated payload — hence opt-in
# rather than the default.
SYSTEM_PROMPT_RESERVE = 4_000      # system prompt + chat history headroom
CONTEXT_UTILISATION = 0.75         # of what remains after output+system
CHARS_PER_TOKEN = 4                # matches approx_tokens()


def adaptive_budget(context_length, output_cap):
    """(budget_chars, budget_tokens) for a model, or None when unknown.

    Returns None (caller keeps the static constants) if the context window can't
    be resolved — never guess, since guessing high is what overflows a context.
    """
    try:
        ctx = int(context_length or 0)
        out = int(output_cap or 0)
    except (TypeError, ValueError):
        return None
    if ctx <= 0:
        return None
    usable = ctx - max(0, out) - SYSTEM_PROMPT_RESERVE
    if usable <= 0:
        return None
    tokens = int(usable * CONTEXT_UTILISATION)
    return tokens * CHARS_PER_TOKEN, tokens



# TRANSPORT INPUT CAP — measured, not assumed.
# The budget above is derived from the MODEL's context window, but a transport can
# impose its own limit on the request itself. The Codex subscription CLI reads the
# prompt from stdin and hard-rejects anything larger than 1 MiB:
#     Error: turn/start failed: Input exceeds the maximum length of 1048576
#     characters. (code -32602) data: {"input_error_code":"input_too_large",
#                                      "max_chars":1048576,"actual_chars":1100056}
# Measured on this box: 1,000,125 chars succeeded (376,564 input tokens reported);
# 1,100,000 chars failed instantly. That ceiling is INDEPENDENT of the model's
# context — a 1M-TOKEN model still cannot receive more than 1 MiB of CHARACTERS
# through this CLI. Without this clamp, selecting a large-context model makes
# adaptive_budget compute a multi-megabyte payload and EVERY report fails.
TRANSPORT_MAX_INPUT_CHARS = {
    "codex-subscription": 1_048_576,
}
# Leave room for the system prompt + framing the CLI adds around the payload.
TRANSPORT_RESERVE_CHARS = 48_000


def transport_cap_chars(provider):
    """Hard input-size ceiling for a provider's transport, or None if unbounded."""
    cap = TRANSPORT_MAX_INPUT_CHARS.get((provider or "").strip().lower())
    return max(0, cap - TRANSPORT_RESERVE_CHARS) if cap else None


def approx_tokens(text) -> int:
    """Coarse upper-bound token estimate. NOT a billed number — label any stored
    value `_approx`. Real counts come from `response.usage`."""
    s = text if isinstance(text, str) else json.dumps(text, default=str)
    return math.ceil(len(s) / 4)


def over_budget(payload, budget_chars: int) -> bool:
    s = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return len(s) > budget_chars
