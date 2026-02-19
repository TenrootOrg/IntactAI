#!/usr/bin/env python3
"""
Agentic Service Module - Full forensics pipeline: hunts -> collect -> LLM analysis -> report

This module provides the main agentic forensics pipeline functionality.
Re-exports all public functions for backward compatibility.
"""

# Main pipeline functions
from services.agentic.pipeline import run_agentic_pipeline, run_agentic_on_existing

# Report functions
from services.agentic.reports import (
    get_report_content,
    get_available_report_types
)

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
    'get_report_content',
    'get_available_report_types',
]
