#!/usr/bin/env python3
"""
Offline Collector Service Module - Generate and manage Velociraptor offline collectors

This module provides functionality for creating offline collectors that can be
deployed to endpoints without network connectivity, and importing their results.

Re-exports all public functions for backward compatibility.
"""

# Config management
from services.offline_collector.config import (
    init_offline_collector_index,
    seed_default_templates,
    get_all_configs,
    get_config,
    save_config,
    delete_config
)

# Collector generation
from services.offline_collector.generator import (
    generate_collector,
    create_collection_script
)

# Import functionality
from services.offline_collector.importer import import_results

# Utilities and constants
from services.offline_collector.constants import (
    COLLECTOR_OUTPUT_DIR,
    VELOCIRAPTOR_CONTAINER,
    VELO_CLIENT_PATHS,
    DEFAULT_ARTIFACTS,
    LINUX_DEFAULT_ARTIFACTS,
    DARWIN_DEFAULT_ARTIFACTS,
    ARTIFACTS_BY_OS,
    artifacts_for_os,
    QUICK_TRIAGE_ARTIFACTS,
    get_collector_file,
    cleanup_old_collectors
)

# Export all public symbols
__all__ = [
    # Config
    'init_offline_collector_index',
    'seed_default_templates',
    'get_all_configs',
    'get_config',
    'save_config',
    'delete_config',
    # Generator
    'generate_collector',
    'create_collection_script',
    # Importer
    'import_results',
    # Constants/Utils
    'COLLECTOR_OUTPUT_DIR',
    'VELOCIRAPTOR_CONTAINER',
    'VELO_CLIENT_PATHS',
    'DEFAULT_ARTIFACTS',
    'LINUX_DEFAULT_ARTIFACTS',
    'DARWIN_DEFAULT_ARTIFACTS',
    'ARTIFACTS_BY_OS',
    'artifacts_for_os',
    'QUICK_TRIAGE_ARTIFACTS',
    'get_collector_file',
    'cleanup_old_collectors',
]
