"""
AWS SIGMA runner — thin wrapper around the shared `azure.sigma_runner`.

The matching engine itself is provider-agnostic (it just needs a list of
loaded SIGMA rule dicts + a list of event records). Only the rule-load
path differs: AWS rules live under `/opt/sigma-rules/rules/cloud/aws/`.
"""

from services.azure.sigma_runner import (
    load_cloud_rules,
    load_aws_rules,
    run_sigma_rules,
    validate_rules_directory,
)

__all__ = [
    'load_cloud_rules',
    'load_aws_rules',
    'run_sigma_rules',
    'validate_rules_directory',
]
