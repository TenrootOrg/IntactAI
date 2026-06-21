"""Agentic reports package — split from the former reports.py for maintainability.
Public import path unchanged: `from services.agentic.reports import X` still works.
  _base.py     — markdown/format/client helpers, timeline section, report storage,
                 and pipeline-artifact / per-client persistence + packaging.
  _generate.py — the large LLM report generators (final / per-client / macro / multi).
"""
from services.agentic.reports._base import *      # noqa: F401,F403
from services.agentic.reports._generate import *  # noqa: F401,F403
