#!/usr/bin/env python3
"""
Backwards compatibility wrapper for upgrade service.
All functionality has been moved to services/upgrade/ package.
This file re-exports everything for backwards compatibility.
"""

# Re-export everything from the new upgrade package
from services.upgrade import *

# Explicitly re-export private names that might be used externally
from services.upgrade import (
    _run_command,
    _read_env_file,
    _update_env_file,
    _compare_versions,
)
