#!/usr/bin/env python3
"""
Agentic Service Module - Forensics collection pipeline: hunts -> collect -> persist for fusion

Collect-only: this module gathers artifacts via Velociraptor and persists the
rows for Case Analysis (services/fusion) to read. No per-run LLM analysis or
reporting happens here.
"""

# Load the STATIC macro-skill index once at module import. The fusion analyst
# shares this read-only index; the loader is idempotent so re-import is cheap.
# The macros ship as static files in services/agentic/skills/macros/ (no
# download). Failure is non-fatal — the analyst falls back to the base prompt.
try:
    from services.agentic.skills import load_macro_index_at_boot
    load_macro_index_at_boot()
except Exception as _skill_load_err:  # noqa: BLE001
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "[Skills] macro index load failed at boot: %s — analyst will use base prompt only",
        _skill_load_err,
    )

# Main pipeline functions
from services.agentic.pipeline import run_agentic_pipeline

# Export all public symbols
__all__ = [
    'run_agentic_pipeline',
]
