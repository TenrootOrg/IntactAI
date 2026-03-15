#!/usr/bin/env python3
"""
Scheduler Jobs - CRUD operations for scheduled jobs

Provides functions to create, read, update, and delete scheduled jobs,
as well as job management (enable/disable, run now, restore on startup).
"""

import json
import threading
import uuid
from datetime import datetime
from typing import Optional

from apscheduler.triggers.cron import CronTrigger

from services.file_storage_service import _get_connection as get_db_connection
from .base import get_scheduler, is_jobs_restored, set_jobs_restored, get_restore_lock


def create_scheduled_job(
    name: str,
    blueprint_id: str,
    blueprint_type: str,
    interval_value: int = 1,
    run_time: str = "02:00",
    client_ids: list = None,
    report_types: list = None,
    anonymize_data: bool = False,
    custom_patterns: list = None,
    description: str = "",
    time_filter_enabled: bool = False,
    time_filter_mode: str = "relative",
    time_filter_relative_range: str = "7d",
    time_filter_start: str = None,
    time_filter_end: str = None
) -> dict:
    """
    Create a new scheduled job.

    Args:
        name: Human-readable job name
        blueprint_id: ID of blueprint to execute (for timesketch: KAPE target name)
        blueprint_type: 'velociraptor', 'agentic', or 'timesketch'
        interval_value: Number of days between runs
        run_time: Time of day to run (HH:MM format, e.g., "02:00")
        client_ids: List of client IDs to target
        report_types: For agentic: ['technical']
        anonymize_data: For agentic: enable data anonymization
        custom_patterns: For agentic: custom masking patterns
        description: Optional description (for timesketch: sketch name)
        time_filter_enabled: For agentic: enable time filtering
        time_filter_mode: 'relative' or 'between'
        time_filter_relative_range: '24h', '7d', '30d', '90d'
        time_filter_start: ISO datetime for 'between' mode
        time_filter_end: ISO datetime for 'between' mode

    Returns:
        Job metadata dict
    """
    from .executor import run_scheduled_blueprint

    job_id = str(uuid.uuid4())
    now = datetime.utcnow()

    # Parse run_time
    try:
        hour, minute = map(int, run_time.split(':'))
    except Exception:
        hour, minute = 2, 0  # Default to 2 AM

    # Create CronTrigger - runs at specified time every N days
    trigger = CronTrigger(hour=hour, minute=minute)

    # Add job to APScheduler
    scheduler = ensure_scheduler_ready()
    if not scheduler:
        raise RuntimeError("Scheduler not available")

    scheduler.add_job(
        func=run_scheduled_blueprint,
        trigger=trigger,
        args=[job_id],
        id=job_id,
        name=name,
        replace_existing=True
    )

    # Calculate next run
    aps_job = scheduler.get_job(job_id)
    next_run = aps_job.next_run_time if aps_job else None

    # Store metadata in our table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scheduled_jobs
        (id, name, description, blueprint_id, blueprint_type, client_ids,
         interval_type, interval_value, run_time, next_run_at, enabled,
         report_types, anonymize_data, custom_patterns,
         time_filter_enabled, time_filter_mode, time_filter_relative_range,
         time_filter_start, time_filter_end, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        job_id,
        name,
        description,
        blueprint_id,
        blueprint_type,
        json.dumps(client_ids or []),
        'days',  # Always days
        interval_value,
        run_time,
        next_run.isoformat() if next_run else None,
        1,  # enabled
        json.dumps(report_types or ['technical']),
        1 if anonymize_data else 0,
        json.dumps(custom_patterns or []),
        1 if time_filter_enabled else 0,
        time_filter_mode,
        time_filter_relative_range,
        time_filter_start,
        time_filter_end,
        now.isoformat(),
        now.isoformat()
    ))
    conn.commit()
    conn.close()

    print(f"[SCHEDULER] Created job: {job_id} - {name} (every {interval_value} day(s) at {run_time})", flush=True)

    return get_scheduled_job(job_id)


def get_scheduled_job(job_id: str) -> Optional[dict]:
    """Get a scheduled job by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    conn.close()

    if row:
        return dict(zip(columns, row))
    return None


def list_scheduled_jobs(enabled_only: bool = False) -> list:
    """List all scheduled jobs."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if enabled_only:
        cursor.execute("SELECT * FROM scheduled_jobs WHERE enabled = 1 ORDER BY created_at DESC")
    else:
        cursor.execute("SELECT * FROM scheduled_jobs ORDER BY created_at DESC")

    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    conn.close()

    jobs = []
    for row in rows:
        job = dict(zip(columns, row))
        # Get next run from APScheduler (if available)
        try:
            scheduler = get_scheduler()
            if scheduler:
                aps_job = scheduler.get_job(job['id'])
                if aps_job and aps_job.next_run_time:
                    job['next_run_at'] = aps_job.next_run_time.isoformat()
        except Exception:
            pass
        jobs.append(job)

    return jobs


def update_scheduled_job(job_id: str, updates: dict) -> Optional[dict]:
    """Update a scheduled job."""
    from .executor import run_scheduled_blueprint

    job = get_scheduled_job(job_id)
    if not job:
        return None

    # Fields that can be updated
    allowed_fields = [
        'name', 'description', 'blueprint_id', 'blueprint_type',
        'client_ids', 'interval_value', 'run_time', 'enabled',
        'report_types', 'anonymize_data', 'custom_patterns'
    ]

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()

    for field in allowed_fields:
        if field in updates:
            value = updates[field]
            # JSON encode lists
            if field in ['client_ids', 'report_types', 'custom_patterns']:
                value = json.dumps(value) if isinstance(value, list) else value
            elif field == 'anonymize_data':
                value = 1 if value else 0

            cursor.execute(f"UPDATE scheduled_jobs SET {field} = ?, updated_at = ? WHERE id = ?",
                          (value, now, job_id))

    conn.commit()
    conn.close()

    # If interval or run_time changed, reschedule the APScheduler job
    if 'interval_value' in updates or 'run_time' in updates:
        scheduler = get_scheduler()
        if scheduler:
            try:
                scheduler.remove_job(job_id)
            except Exception:
                pass

            interval_value = updates.get('interval_value', job.get('interval_value', 1))
            run_time = updates.get('run_time', job.get('run_time', '02:00'))

            try:
                hour, minute = map(int, run_time.split(':'))
            except Exception:
                hour, minute = 2, 0

            trigger = CronTrigger(hour=hour, minute=minute)

            scheduler.add_job(
                func=run_scheduled_blueprint,
                trigger=trigger,
                args=[job_id],
                id=job_id,
                name=updates.get('name', job['name']),
                replace_existing=True
            )

    # Handle enable/disable
    if 'enabled' in updates:
        scheduler = get_scheduler()
        if scheduler:
            try:
                if updates['enabled']:
                    scheduler.resume_job(job_id)
                else:
                    scheduler.pause_job(job_id)
            except Exception:
                pass

    return get_scheduled_job(job_id)


def delete_scheduled_job(job_id: str) -> bool:
    """Delete a scheduled job."""
    job = get_scheduled_job(job_id)
    if not job:
        return False

    # Remove from APScheduler
    scheduler = get_scheduler()
    if scheduler:
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass  # Job might not exist in scheduler

    # Remove from metadata table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scheduled_jobs WHERE id = ?", (job_id,))
    conn.commit()
    conn.close()

    print(f"[SCHEDULER] Deleted job: {job_id}", flush=True)
    return True


def toggle_scheduled_job(job_id: str, enabled: bool) -> Optional[dict]:
    """Enable or disable a scheduled job."""
    return update_scheduled_job(job_id, {'enabled': enabled})


def run_job_now(job_id: str) -> bool:
    """Manually trigger a job to run immediately."""
    from .executor import run_scheduled_blueprint

    job = get_scheduled_job(job_id)
    if not job:
        return False

    # Run in background thread
    thread = threading.Thread(
        target=run_scheduled_blueprint,
        args=[job_id],
        daemon=True
    )
    thread.start()
    print(f"[SCHEDULER] Manual trigger: {job_id}", flush=True)
    return True


def restore_jobs_on_startup():
    """Restore all enabled jobs to APScheduler. Called lazily on first scheduler access."""
    from .executor import run_scheduled_blueprint

    restore_lock = get_restore_lock()

    with restore_lock:
        if is_jobs_restored():
            return  # Already restored

        try:
            scheduler = get_scheduler()
            if scheduler is None:
                print("[SCHEDULER] Cannot restore jobs - scheduler not available", flush=True)
                return

            # Get enabled jobs from our metadata table (not APScheduler's store)
            jobs = list_scheduled_jobs(enabled_only=True)
            restored_count = 0

            for job in jobs:
                try:
                    # Check if job already exists in scheduler
                    if scheduler.get_job(job['id']):
                        continue

                    run_time = job.get('run_time', '02:00')
                    try:
                        hour, minute = map(int, run_time.split(':'))
                    except Exception:
                        hour, minute = 2, 0

                    trigger = CronTrigger(hour=hour, minute=minute)

                    scheduler.add_job(
                        func=run_scheduled_blueprint,
                        trigger=trigger,
                        args=[job['id']],
                        id=job['id'],
                        name=job['name'],
                        replace_existing=True
                    )
                    restored_count += 1
                except Exception as e:
                    print(f"[SCHEDULER] Error restoring job {job.get('id')}: {e}", flush=True)

            if restored_count > 0:
                print(f"[SCHEDULER] Restored {restored_count} scheduled job(s)", flush=True)

            set_jobs_restored(True)

        except Exception as e:
            print(f"[SCHEDULER] Error during job restoration: {e}", flush=True)


def ensure_scheduler_ready():
    """Ensure scheduler is initialized and jobs are restored. Call this before scheduler operations."""
    # Get scheduler (initializes if needed)
    scheduler = get_scheduler()

    # Restore jobs if not already done
    if not is_jobs_restored():
        # Restore in background to avoid blocking
        thread = threading.Thread(target=restore_jobs_on_startup, daemon=True)
        thread.start()
        # Wait briefly for restoration (non-blocking for most cases)
        thread.join(timeout=2.0)

    return scheduler
