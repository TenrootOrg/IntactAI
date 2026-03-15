#!/usr/bin/env python3
"""
Scheduler Package - Manages recurring blueprint execution schedules

Uses APScheduler with SQLite job store for persistence across restarts.
Always uses days as interval and runs at a specified time of day.

IMPORTANT: Scheduler initialization is lazy to prevent startup hangs.
Jobs are restored in a background thread after first access.

Components:
- base: Scheduler initialization, table creation
- executor: Blueprint execution functions (APScheduler callbacks)
- jobs: CRUD operations for scheduled jobs
"""

# Base utilities
from .base import (
    SCHEDULER_DB_PATH,
    get_scheduler,
    init_scheduled_jobs_table,
)

# Job CRUD and management
from .jobs import (
    create_scheduled_job,
    get_scheduled_job,
    list_scheduled_jobs,
    update_scheduled_job,
    delete_scheduled_job,
    toggle_scheduled_job,
    run_job_now,
    restore_jobs_on_startup,
    ensure_scheduler_ready,
)

# Executor functions (mainly for internal use)
from .executor import (
    run_scheduled_blueprint,
    run_velociraptor_hunt,
    run_timesketch_pipeline,
    update_job_run_stats,
)

# Initialize table on package import
init_scheduled_jobs_table()

# Backwards compatibility: expose private function names used elsewhere
_run_scheduled_blueprint = run_scheduled_blueprint
_run_velociraptor_hunt = run_velociraptor_hunt
_run_timesketch_pipeline = run_timesketch_pipeline
_update_job_run_stats = update_job_run_stats

# NOTE: Jobs are restored lazily on first scheduler access, not during module import.
# This prevents startup hangs if the scheduler database is corrupted.
