#!/usr/bin/env python3
"""
Agentic Service Module - Full forensics pipeline: hunts -> collect -> LLM analysis -> report

This module provides the main agentic forensics pipeline functionality.
Re-exports all public functions for backward compatibility.
"""

# Load DFIR skill index once at module import. Threads in analyze_artifacts
# share this read-only index; the loader is idempotent so re-import is cheap.
# Failure is non-fatal — the analyzer falls back to the base prompt.
try:
    from services.agentic.skills import load_skill_index_at_boot
    load_skill_index_at_boot()
except Exception as _skill_load_err:  # noqa: BLE001
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "[Skills] index load failed at boot: %s — analyzer will use base prompt only",
        _skill_load_err,
    )

# Main pipeline functions
from services.agentic.pipeline import run_agentic_pipeline, run_agentic_on_existing

# For backward compatibility - legacy function name aliases
_extract_timeline_events = None  # Lazy import to avoid circular imports


def get_extract_timeline_events():
    """Get the extract_timeline_events function (lazy import)"""
    global _extract_timeline_events
    if _extract_timeline_events is None:
        from services.agentic.utils import extract_timeline_events
        _extract_timeline_events = extract_timeline_events
    return _extract_timeline_events


# Export all public symbols
__all__ = [
    'run_agentic_pipeline',
    'run_agentic_on_existing',
]
