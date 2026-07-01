"""
AWS Security Automation Service

Mirror of `services.azure` for the AWS provider. Collects CloudTrail
events, GuardDuty findings, AccessAnalyzer findings, and IAM principal
posture, runs them through the same SIGMA → LLM analyzer →
report pipeline.

This module is currently a *scaffold*: every per-source collector
returns hand-curated fixture data from `fake_data/*.json` rather than
calling a real AWS API. The shape and call graph match Azure exactly so
that swapping in a real boto3 integration later is a
one-function edit per source (see `collectors._FAKE_SOURCES`).
"""

from .pipeline import run_aws_pipeline, run_aws_on_existing, get_aws_blueprints, get_available_sources
from .collectors import collect_aws_logs, parse_uploaded_logs, LOG_SOURCES, detect_source_type
from .sigma_runner import run_sigma_rules, load_aws_rules

__all__ = [
    'run_aws_pipeline',
    'run_aws_on_existing',
    'get_aws_blueprints',
    'get_available_sources',
    'run_sigma_rules',
    'load_aws_rules',
    'collect_aws_logs',
    'parse_uploaded_logs',
    'detect_source_type',
    'LOG_SOURCES',
]
