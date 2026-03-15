#!/usr/bin/env python3
"""
Scheduler Base - APScheduler initialization and configuration

Provides lazy initialization of the BackgroundScheduler with SQLite persistence.
Jobs are restored on first scheduler access to prevent startup hangs.
"""

import os
import threading
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from services.file_storage_service import _get_connection as get_db_connection

# Scheduler instance (singleton)
_scheduler: Optional[BackgroundScheduler] = None
_scheduler_lock = threading.Lock()
_jobs_restored = False
_restore_lock = threading.Lock()

# Path to scheduler jobs database
SCHEDULER_DB_PATH = '/app/data/scheduler_jobs.db'


def _safe_init_scheduler() -> Optional[BackgroundScheduler]:
    """Safely initialize the scheduler with error handling."""
    try:
        # Check if database file exists and is accessible
        db_dir = os.path.dirname(SCHEDULER_DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        # Use SQLite for job persistence
        jobstores = {
            'default': SQLAlchemyJobStore(url=f'sqlite:///{SCHEDULER_DB_PATH}')
        }
        scheduler = BackgroundScheduler(
            jobstores=jobstores,
            timezone='UTC'
        )
        scheduler.start()
        print("[SCHEDULER] Scheduler started", flush=True)
        return scheduler
    except Exception as e:
        print(f"[SCHEDULER] Error initializing scheduler: {e}", flush=True)
        # Try to recover by removing corrupted database
        try:
            if os.path.exists(SCHEDULER_DB_PATH):
                os.remove(SCHEDULER_DB_PATH)
                print("[SCHEDULER] Removed corrupted scheduler database, retrying...", flush=True)
                jobstores = {
                    'default': SQLAlchemyJobStore(url=f'sqlite:///{SCHEDULER_DB_PATH}')
                }
                scheduler = BackgroundScheduler(
                    jobstores=jobstores,
                    timezone='UTC'
                )
                scheduler.start()
                print("[SCHEDULER] Scheduler started after recovery", flush=True)
                return scheduler
        except Exception as e2:
            print(f"[SCHEDULER] Recovery failed: {e2}", flush=True)
        return None


def get_scheduler() -> Optional[BackgroundScheduler]:
    """Get or create the scheduler instance. Returns None if initialization fails."""
    global _scheduler
    with _scheduler_lock:
        if _scheduler is None:
            _scheduler = _safe_init_scheduler()
        return _scheduler


def init_scheduled_jobs_table():
    """Initialize the scheduled_jobs metadata table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            blueprint_id TEXT NOT NULL,
            blueprint_type TEXT NOT NULL DEFAULT 'velociraptor',
            client_ids TEXT,
            interval_type TEXT NOT NULL DEFAULT 'days',
            interval_value INTEGER NOT NULL DEFAULT 1,
            run_time TEXT DEFAULT '02:00',
            last_run_at TEXT,
            next_run_at TEXT,
            run_count INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            report_types TEXT,
            anonymize_data INTEGER DEFAULT 0,
            custom_patterns TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    # Add run_time column if it doesn't exist (migration)
    try:
        cursor.execute("ALTER TABLE scheduled_jobs ADD COLUMN run_time TEXT DEFAULT '02:00'")
    except Exception:
        pass  # Column already exists

    # Add time filter columns (migration)
    time_filter_columns = [
        ("time_filter_enabled", "INTEGER DEFAULT 0"),
        ("time_filter_mode", "TEXT DEFAULT 'relative'"),
        ("time_filter_relative_range", "TEXT DEFAULT '7d'"),
        ("time_filter_start", "TEXT"),
        ("time_filter_end", "TEXT")
    ]
    for col_name, col_def in time_filter_columns:
        try:
            cursor.execute(f"ALTER TABLE scheduled_jobs ADD COLUMN {col_name} {col_def}")
        except Exception:
            pass  # Column already exists

    conn.commit()
    conn.close()


def is_jobs_restored() -> bool:
    """Check if jobs have been restored."""
    return _jobs_restored


def set_jobs_restored(value: bool):
    """Set the jobs restored flag."""
    global _jobs_restored
    _jobs_restored = value


def get_restore_lock() -> threading.Lock:
    """Get the restore lock for thread-safe job restoration."""
    return _restore_lock
