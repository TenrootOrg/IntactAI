#!/usr/bin/env python3
"""
Kept only as an import path: the aws/azure pipelines and routes import
add_log_to_run from here. The WorkflowLogger class that lived here was never
instantiated (and its fail() set "failed" with no error text), so it was removed.
"""

from services.workflow_service import add_log_to_run  # noqa: F401
