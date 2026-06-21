"""Agentic pipeline package — split from the former pipeline.py.
Public import path unchanged: `from services.agentic.pipeline import X` works
(incl. _collect_only_report imported by the fusion no-llm test).
  _helpers.py — watchdog, phase updates, collect-only report stub.
  _runners.py — run_agentic_pipeline (the collection orchestrator).
"""
from services.agentic.pipeline._helpers import *  # noqa: F401,F403
from services.agentic.pipeline._runners import *  # noqa: F401,F403
from services.agentic.pipeline._helpers import _collect_only_report  # noqa: F401 (used by test_no_llm)
