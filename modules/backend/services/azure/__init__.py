"""
Azure Security Automation Service

Provides Azure/M365 security log collection and SIGMA-based detection.
Supports both online (API) and offline (manual upload) modes.
"""

from .pipeline import run_azure_pipeline, run_azure_on_existing
from .sigma_runner import run_sigma_rules, load_azure_rules
from .collectors import collect_azure_logs, parse_uploaded_logs

__all__ = [
    'run_azure_pipeline',
    'run_azure_on_existing',
    'run_sigma_rules',
    'load_azure_rules',
    'collect_azure_logs',
    'parse_uploaded_logs'
]
