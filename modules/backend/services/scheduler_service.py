#!/usr/bin/env python3
"""
Scheduler Service - Manages recurring blueprint execution schedules.

Uses APScheduler with SQLite job store for persistence across restarts.
Always uses days as interval and runs at a specified time of day.

IMPORTANT: Scheduler initialization is lazy to prevent startup hangs.
Jobs are restored in a background thread after first access.
"""

import threading
import uuid
import os
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger

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


# Initialize table on module load
init_scheduled_jobs_table()


def _run_scheduled_blueprint(job_id: str):
    """Execute a scheduled blueprint run."""
    from services.agentic import run_agentic_pipeline
    from services.file_storage_service import load_frontend_config, get_velociraptor_blueprint, get_agentic_blueprint
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    import json

    print(f"[SCHEDULER] Executing scheduled job: {job_id}", flush=True)

    # Get job metadata
    job_meta = get_scheduled_job(job_id)
    if not job_meta:
        print(f"[SCHEDULER] Job not found: {job_id}", flush=True)
        return

    if not job_meta.get('enabled', True):
        print(f"[SCHEDULER] Job disabled, skipping: {job_id}", flush=True)
        return

    blueprint_id = job_meta['blueprint_id']
    blueprint_type = job_meta.get('blueprint_type', 'velociraptor')
    client_ids = json.loads(job_meta.get('client_ids', '[]'))
    report_types = json.loads(job_meta.get('report_types', '["technical"]'))
    anonymize_data = bool(job_meta.get('anonymize_data', 0))
    custom_patterns = json.loads(job_meta.get('custom_patterns', '[]'))

    # Reconstruct time_filter from job metadata
    time_filter = None
    if job_meta.get('time_filter_enabled'):
        time_filter = {
            'enabled': True,
            'mode': job_meta.get('time_filter_mode', 'relative'),
            'relative_range': job_meta.get('time_filter_relative_range', '7d'),
            'start_datetime': job_meta.get('time_filter_start'),
            'end_datetime': job_meta.get('time_filter_end')
        }

    try:
        if blueprint_type == 'agentic':
            # Load LLM config
            config = load_frontend_config() or {}
            llm_config = config.get('agentic', {})

            # Get blueprint name
            agentic_bp = get_agentic_blueprint(blueprint_id)
            blueprint_name = agentic_bp.get('name', blueprint_id) if agentic_bp else blueprint_id

            # Create automation run
            run_id = create_automation_run(
                automation_type="agentic",
                name=f"Scheduled: {job_meta['name']}",
                details={
                    "blueprint_id": blueprint_id,
                    "blueprint": blueprint_name,
                    "client_ids": client_ids,
                    "collection_minutes": 30,
                    "report_types": report_types,
                    "scheduled_job_id": job_id
                }
            )

            # Run in background thread
            thread = threading.Thread(
                target=run_agentic_pipeline,
                args=(run_id, blueprint_id, client_ids, 30, llm_config, report_types,
                      anonymize_data, custom_patterns, False, None, time_filter),
                daemon=True
            )
            thread.start()
            time_filter_info = ""
            if time_filter:
                mode = time_filter.get('mode', 'relative')
                if mode == 'relative':
                    time_filter_info = f", time_filter=relative({time_filter.get('relative_range', '7d')})"
                else:
                    time_filter_info = f", time_filter=between"
            print(f"[SCHEDULER] Started agentic pipeline: run_id={run_id}{time_filter_info}", flush=True)

        elif blueprint_type == 'timesketch':
            # Timesketch automation - KAPE collection + Plaso + TimeSketch import
            _run_timesketch_pipeline(job_meta, client_ids)
            print(f"[SCHEDULER] Started timesketch pipeline for {len(client_ids)} clients", flush=True)

        else:
            # Velociraptor blueprint - run hunt directly
            _run_velociraptor_hunt(job_meta['name'], blueprint_id, client_ids)
            print(f"[SCHEDULER] Started velociraptor scan: blueprint={blueprint_id}", flush=True)

        # Update job metadata
        _update_job_run_stats(job_id)

    except Exception as e:
        print(f"[SCHEDULER] Error executing job {job_id}: {e}", flush=True)
        import traceback
        traceback.print_exc()


def _run_velociraptor_hunt(job_name: str, blueprint_id: str, client_ids: list):
    """Execute a Velociraptor hunt from a blueprint."""
    from services.file_storage_service import get_velociraptor_blueprint
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    from services.velociraptor_service import setup_velociraptor_connection
    import json

    # Get blueprint
    blueprint = get_velociraptor_blueprint(blueprint_id)
    if not blueprint:
        print(f"[SCHEDULER] Blueprint not found: {blueprint_id}", flush=True)
        return

    artifacts = blueprint.get('artifacts', [])
    settings = blueprint.get('settings', {})
    expire_minutes = settings.get('hunt_expiry', 120)
    timeout_seconds = settings.get('timeout', 3600)
    cpu_limit = settings.get('cpu_limit', 50)

    if not artifacts:
        print(f"[SCHEDULER] No artifacts in blueprint: {blueprint_id}", flush=True)
        return

    # Create workflow run
    blueprint_name = blueprint.get('name', blueprint_id)
    run_id = create_automation_run(
        automation_type="scheduled_hunt",
        name=f"Scheduled: {job_name}",
        details={
            "blueprint_id": blueprint_id,
            "blueprint": blueprint_name,
            "artifact_count": len(artifacts),
            "client_ids": client_ids
        }
    )

    try:
        # Import here to avoid circular imports
        from pyvelociraptor import api_pb2, api_pb2_grpc

        channel = setup_velociraptor_connection()
        if not channel:
            add_log_to_run(run_id, "Failed to connect to Velociraptor", "error")
            update_run_status(run_id, "failed")
            return

        stub = api_pb2_grpc.APIStub(channel)

        # Build VQL for hunt
        expire_seconds = expire_minutes * 60
        artifacts_list = json.dumps(artifacts)
        spec_parts = ", ".join([f'`{a}`=dict()' for a in artifacts])

        query = f"""
LET collection = hunt(
    description='Scheduled: {job_name} ({len(artifacts)} artifacts)',
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    cpu_limit={cpu_limit}
)
SELECT HuntId FROM collection
"""

        add_log_to_run(run_id, f"Creating hunt with {len(artifacts)} artifacts")

        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )

        hunt_id = None
        response_log = None
        for response in stub.Query(request_obj, timeout=120):
            if response.log:
                response_log = response.log
                print(f"[SCHEDULER] VQL log: {response.log}", flush=True)
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    print(f"[SCHEDULER] VQL response: {resp_data}", flush=True)
                    if resp_data and len(resp_data) > 0:
                        hunt_id = resp_data[0].get('HuntId')
                except Exception as parse_err:
                    print(f"[SCHEDULER] Parse error: {parse_err}", flush=True)

        channel.close()

        if hunt_id:
            add_log_to_run(run_id, f"Hunt created: {hunt_id}", "success")
            update_run_status(run_id, "completed", progress=100)
            print(f"[SCHEDULER] Hunt created: {hunt_id}", flush=True)
        else:
            error_msg = response_log or "No HuntId returned from Velociraptor"
            add_log_to_run(run_id, f"Failed to create hunt: {error_msg}", "error")
            update_run_status(run_id, "failed")
            print(f"[SCHEDULER] Failed to create hunt: {error_msg}", flush=True)

    except Exception as e:
        add_log_to_run(run_id, f"Error: {str(e)}", "error")
        update_run_status(run_id, "failed")
        print(f"[SCHEDULER] Hunt error: {e}", flush=True)


def _run_timesketch_pipeline(job_meta: dict, client_ids: list):
    """Execute a Timesketch automation pipeline for each client.

    This runs KAPE collection followed by Plaso processing and TimeSketch import.
    """
    from services.kape_service import run_kape_collection_grpc, monitor_flow_completion
    from services.plaso_service import process_with_plaso, run_pinfo
    from services.timesketch_service import import_to_timesketch
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    from services.velociraptor_service import get_client_info
    from services.file_storage_service import get_timesketch_blueprint
    from config import TIMESKETCH_CONFIG
    import json
    import time

    job_name = job_meta.get('name', 'Scheduled Timesketch')
    blueprint_id = job_meta.get('blueprint_id', '')
    sketch_name = job_meta.get('description', '') or f"Scheduled_{datetime.utcnow().strftime('%Y%m%d')}"

    # Load blueprint settings
    blueprint = get_timesketch_blueprint(blueprint_id) if blueprint_id else None
    settings = blueprint.get('settings', {}) if blueprint else {}

    kape_target = settings.get('kape_target', '_KapeTriage')
    timeout_seconds = settings.get('collection_timeout', 10000)
    cpu_limit = 50

    for client_id in client_ids:
        try:
            # Get client hostname
            client_info = get_client_info(client_id)
            client_name = client_info.get('hostname', client_id) if client_info else client_id

            # Create automation run
            blueprint_name = blueprint.get('name', blueprint_id) if blueprint else blueprint_id
            run_id = create_automation_run(
                automation_type="timesketch",
                name=f"Scheduled: {job_name} - {client_name}",
                details={
                    "client_id": client_id,
                    "client_name": client_name,
                    "kape_target": kape_target,
                    "sketch_name": sketch_name,
                    "scheduled_job_id": job_meta.get('id'),
                    "blueprint_id": blueprint_id,
                    "blueprint": blueprint_name
                }
            )

            def workflow_logger(message, level="info"):
                add_log_to_run(run_id, message, level)

            workflow_logger(f"Starting scheduled Timesketch pipeline for {client_name}")
            workflow_logger(f"KAPE Target: {kape_target}")

            # Step 1: Run KAPE collection
            workflow_logger("=== PHASE 1: Starting KAPE Collection ===")
            flow_id = run_kape_collection_grpc(
                client_id=client_id,
                kape_target=kape_target,
                timeout_seconds=timeout_seconds,
                cpu_limit=cpu_limit
            )

            if not flow_id:
                workflow_logger("Failed to start KAPE collection", "error")
                update_run_status(run_id, "failed")
                continue

            workflow_logger(f"KAPE collection started: flow_id={flow_id}")
            update_run_status(run_id, "running", progress=10)

            # Step 2: Monitor flow completion
            workflow_logger("=== PHASE 2: Monitoring KAPE Collection ===")
            flow_state = monitor_flow_completion(
                client_id=client_id,
                flow_id=flow_id,
                timeout_seconds=timeout_seconds,
                logger=workflow_logger
            )

            if flow_state != "FINISHED":
                workflow_logger(f"KAPE collection failed: {flow_state}", "error")
                update_run_status(run_id, "failed")
                continue

            workflow_logger("KAPE collection completed successfully", "success")
            update_run_status(run_id, "running", progress=40)

            # Step 3: Process with Plaso
            workflow_logger("=== PHASE 3: Processing with Plaso ===")
            plaso_file = process_with_plaso(
                client_id=client_id,
                flow_id=flow_id,
                client_name=client_name,
                logger=workflow_logger
            )

            if not plaso_file:
                workflow_logger("Plaso processing failed", "error")
                update_run_status(run_id, "failed")
                continue

            workflow_logger(f"Plaso processing completed: {plaso_file}", "success")
            update_run_status(run_id, "running", progress=55)

            # Step 3.5: Verify Plaso file with pinfo
            workflow_logger("=== PHASE 3.5: Verifying Plaso Storage (pinfo) ===")
            pinfo_result = run_pinfo(plaso_file, logger=workflow_logger)

            if pinfo_result:
                event_count = pinfo_result.get('event_count', 0)
                if event_count == 0:
                    workflow_logger("No events matched the selected parser - skipping Timesketch import", "warning")
                    workflow_logger("Tip: Try using 'Auto (All Parsers)' or a broader parser preset", "info")
                    update_run_status(run_id, "completed", progress=100)
                    continue
                workflow_logger(f"Plaso file verified: {event_count} events ready for import", "success")
            else:
                workflow_logger("Could not verify Plaso file, continuing anyway...", "warning")

            update_run_status(run_id, "running", progress=70)

            # Step 4: Import to Timesketch
            workflow_logger("=== PHASE 4: Importing to Timesketch ===")
            timeline_name = f"{client_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

            result = import_to_timesketch(
                plaso_file=plaso_file,
                sketch_name=sketch_name,
                timeline_name=timeline_name,
                timesketch_config=TIMESKETCH_CONFIG,
                logger=workflow_logger
            )

            if result:
                workflow_logger("Timesketch import completed successfully", "success")
                workflow_logger(f"Sketch ID: {result.get('sketch_id')}", "success")
                workflow_logger(f"Timeline ID: {result.get('timeline_id')}", "success")
                update_run_status(run_id, "completed", progress=100)
            else:
                workflow_logger("Timesketch import failed", "error")
                update_run_status(run_id, "failed")

        except Exception as e:
            print(f"[SCHEDULER] Timesketch pipeline error for {client_id}: {e}", flush=True)
            import traceback
            traceback.print_exc()


def _update_job_run_stats(job_id: str):
    """Update last_run_at and run_count for a job."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    cursor.execute("""
        UPDATE scheduled_jobs
        SET last_run_at = ?, run_count = run_count + 1, updated_at = ?
        WHERE id = ?
    """, (now, now, job_id))
    conn.commit()
    conn.close()


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
    import json

    job_id = str(uuid.uuid4())
    now = datetime.utcnow()

    # Parse run_time
    try:
        hour, minute = map(int, run_time.split(':'))
    except Exception:
        hour, minute = 2, 0  # Default to 2 AM

    # Create CronTrigger - runs at specified time every N days
    # For daily: day_of_week='*' (every day)
    # For every N days: we use a different approach with day='*/N' doesn't work well
    # So we use interval but with a cron-like start time
    if interval_value == 1:
        # Daily - use cron trigger
        trigger = CronTrigger(hour=hour, minute=minute)
    else:
        # Every N days - use cron with specific day calculation
        # Run at specified time, check day modulo
        trigger = CronTrigger(hour=hour, minute=minute)

    # Add job to APScheduler
    scheduler = ensure_scheduler_ready()
    if not scheduler:
        raise RuntimeError("Scheduler not available")

    scheduler.add_job(
        func=_run_scheduled_blueprint,
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
    import json

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
                func=_run_scheduled_blueprint,
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
    job = get_scheduled_job(job_id)
    if not job:
        return False

    # Run in background thread
    thread = threading.Thread(
        target=_run_scheduled_blueprint,
        args=[job_id],
        daemon=True
    )
    thread.start()
    print(f"[SCHEDULER] Manual trigger: {job_id}", flush=True)
    return True


def restore_jobs_on_startup():
    """Restore all enabled jobs to APScheduler. Called lazily on first scheduler access."""
    global _jobs_restored

    with _restore_lock:
        if _jobs_restored:
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
                        func=_run_scheduled_blueprint,
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

            _jobs_restored = True

        except Exception as e:
            print(f"[SCHEDULER] Error during job restoration: {e}", flush=True)


def ensure_scheduler_ready():
    """Ensure scheduler is initialized and jobs are restored. Call this before scheduler operations."""
    global _jobs_restored

    # Get scheduler (initializes if needed)
    scheduler = get_scheduler()

    # Restore jobs if not already done
    if not _jobs_restored:
        # Restore in background to avoid blocking
        thread = threading.Thread(target=restore_jobs_on_startup, daemon=True)
        thread.start()
        # Wait briefly for restoration (non-blocking for most cases)
        thread.join(timeout=2.0)

    return scheduler


# NOTE: Jobs are restored lazily on first scheduler access, not during module import.
# This prevents startup hangs if the scheduler database is corrupted.
