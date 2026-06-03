"""Engagement Report builder.

Combines multiple completed workflow reports (agentic / aws_scan /
azure_scan) into a single IR-firm-style markdown deliverable with
LLM-written executive synthesis on top.

Public entry point: `run_engagement_build(run_id, sources, notes, llm_config)`
"""

from .builder import run_engagement_build

__all__ = ['run_engagement_build']
