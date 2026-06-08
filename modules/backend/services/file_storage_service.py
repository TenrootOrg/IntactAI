#!/usr/bin/env python3
"""
File Storage Service - Backwards compatibility wrapper

This module re-exports all functions from the services.storage package
to maintain backwards compatibility with existing imports.

The actual implementation has been refactored into:
- services/storage/base.py - Connection, schema, migrations
- services/storage/workflow_store.py - Workflow CRUD
- services/storage/blueprint_store.py - Blueprint CRUD
- services/storage/collector_store.py - Offline collector CRUD
- services/storage/config_store.py - Frontend/cloud config
- services/storage/report_store.py - Report CRUD
- services/storage/export_import.py - Database export/import
"""

# Re-export everything from the storage package
from services.storage import (
    # Constants
    STORAGE_BASE,
    DB_PATH,

    # Base utilities
    get_connection,
    row_to_dict,
    init_storage,

    # Workflow operations
    save_workflow,
    load_workflows,
    get_workflow,
    delete_workflow,

    # Blueprint operations - Velociraptor
    save_velociraptor_blueprint,
    load_velociraptor_blueprints,
    get_velociraptor_blueprint,
    delete_velociraptor_blueprint,

    # Blueprint operations - Agentic
    save_agentic_blueprint,
    load_agentic_blueprints,
    get_agentic_blueprint,
    delete_agentic_blueprint,

    # Blueprint operations - Timesketch
    save_timesketch_blueprint,
    load_timesketch_blueprints,
    get_timesketch_blueprint,
    delete_timesketch_blueprint,

    # Blueprint operations - Memory (VolWeb plugin sets)
    save_memory_blueprint,
    load_memory_blueprints,
    get_memory_blueprint,
    delete_memory_blueprint,

    # Collector operations
    save_offline_collector_config,
    load_offline_collector_configs,
    get_offline_collector_config,
    delete_offline_collector_config,

    # Config operations
    save_frontend_config,
    load_frontend_config,
    save_cloud_config,
    load_cloud_config,

    # Report operations
    save_report,
    get_report,
    delete_report,

    # Export/Import
    export_db,
    import_db,

    # Backwards compatibility aliases
    _get_connection,
    _row_to_dict,
)

# Note: storage_initialized is set during package import in storage/__init__.py
