"""Agentic analyzers package.
Public import path unchanged: `from services.agentic.analyzers import X` works
(incl. call_llm / is_llm_configured used by the memory + fusion layers).
  _llm.py — LLM transport + config: cost/model tables, alias/limit helpers,
            call_llm + online/offline backends, usage metrics. Used by the
            memory + fusion layers (call_llm / is_llm_configured / MODEL_ALIASES).

  (_analysis.py was removed — the per-artifact LLM analysis + its sampling/scope
   helpers were old agentic-pipeline code; analysis now happens at the fusion /
   Case Analysis layer.)
"""
from services.agentic.analyzers._llm import *       # noqa: F401,F403
