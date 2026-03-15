#!/usr/bin/env python3
"""
Scheduler Service - Backwards compatibility wrapper

This module re-exports all functions from the services.scheduler package
to maintain backwards compatibility with existing imports.

The actual implementation has been refactored into:
- services/scheduler/base.py - Scheduler initialization, table creation
- services/scheduler/executor.py - Blueprint execution functions
- services/scheduler/jobs.py - Job CRUD and management
"""

# Re-export everything from the scheduler package
from services.scheduler import (
    # Constants
    SCHEDULER_DB_PATH,

    # Scheduler access
    get_scheduler,
    init_scheduled_jobs_table,

    # Job CRUD
    create_scheduled_job,
    get_scheduled_job,
    list_scheduled_jobs,
    update_scheduled_job,
    delete_scheduled_job,
    toggle_scheduled_job,
    run_job_now,
    restore_jobs_on_startup,
    ensure_scheduler_ready,

    # Executor functions
    run_scheduled_blueprint,
    run_velociraptor_hunt,
    run_timesketch_pipeline,
    update_job_run_stats,

    # Backwards compatibility aliases
    _run_scheduled_blueprint,
    _run_velociraptor_hunt,
    _run_timesketch_pipeline,
    _update_job_run_stats,
)
