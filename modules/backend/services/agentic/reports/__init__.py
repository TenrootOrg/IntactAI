"""Agentic reports package — collect-only after the LLM report engine was retired.
Public import path unchanged: `from services.agentic.reports import X` still works.
  _base.py — the live collect-only surface: client-row filtering, the empty-data
             placeholder report, run-result storage, and raw-artifact persistence
             (consumed by the fusion / Case Analysis layer). The LLM report
             generators (_generate.py) were removed; reporting now lives in fusion.
"""
from services.agentic.reports._base import *      # noqa: F401,F403
