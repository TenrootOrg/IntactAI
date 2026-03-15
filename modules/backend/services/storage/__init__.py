#!/usr/bin/env python3
"""
Storage Package - SQLite-based persistence for workflows, blueprints, configs, and reports

This package provides a modular storage layer with the following components:
- base: Connection management, schema, and migrations
- workflow_store: Workflow run CRUD operations
- blueprint_store: Blueprint CRUD for all types (velociraptor, agentic, timesketch)
- collector_store: Offline collector configuration CRUD
- config_store: Frontend and cloud configuration storage
- report_store: Report CRUD operations
- export_import: Database export and import functionality
"""

# Base utilities
from .base import (
    STORAGE_BASE,
    DB_PATH,
    get_connection,
    row_to_dict,
    init_storage,
)

# Workflow operations
from .workflow_store import (
    save_workflow,
    load_workflows,
    get_workflow,
    delete_workflow,
)

# Blueprint operations
from .blueprint_store import (
    save_velociraptor_blueprint,
    load_velociraptor_blueprints,
    get_velociraptor_blueprint,
    delete_velociraptor_blueprint,
    save_agentic_blueprint,
    load_agentic_blueprints,
    get_agentic_blueprint,
    delete_agentic_blueprint,
    save_timesketch_blueprint,
    load_timesketch_blueprints,
    get_timesketch_blueprint,
    delete_timesketch_blueprint,
)

# Collector operations
from .collector_store import (
    save_offline_collector_config,
    load_offline_collector_configs,
    get_offline_collector_config,
    delete_offline_collector_config,
)

# Config operations
from .config_store import (
    save_frontend_config,
    load_frontend_config,
    save_cloud_config,
    load_cloud_config,
)

# Report operations
from .report_store import (
    save_report,
    get_report,
    delete_report,
)

# Export/Import operations
from .export_import import (
    export_db,
    import_db,
)

# Initialize storage on package import
print("[STORAGE] Initializing SQLite storage...", flush=True)
storage_initialized = init_storage()
if storage_initialized:
    print(f"[STORAGE] SQLite storage initialized: {DB_PATH}", flush=True)
else:
    print("[STORAGE] SQLite storage initialization failed", flush=True)


# Backwards compatibility aliases (private function names used internally)
_get_connection = get_connection
_row_to_dict = row_to_dict
