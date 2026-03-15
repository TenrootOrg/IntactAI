#!/usr/bin/env python3
"""
Scheduler Executor - Blueprint execution functions for scheduled jobs

Contains the callback functions that APScheduler invokes when jobs run.
"""

import threading
from datetime import datetime

from services.file_storage_service import _get_connection as get_db_connection


def run_scheduled_blueprint(job_id: str):
    """Execute a scheduled blueprint run. This is the main APScheduler callback."""
    from services.agentic import run_agentic_pipeline
    from services.file_storage_service import load_frontend_config, get_velociraptor_blueprint, get_agentic_blueprint
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    from .jobs import get_scheduled_job
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
            run_timesketch_pipeline(job_meta, client_ids)
            print(f"[SCHEDULER] Started timesketch pipeline for {len(client_ids)} clients", flush=True)

        else:
            # Velociraptor blueprint - run hunt directly
            run_velociraptor_hunt(job_meta['name'], blueprint_id, client_ids)
            print(f"[SCHEDULER] Started velociraptor scan: blueprint={blueprint_id}", flush=True)

        # Update job metadata
        update_job_run_stats(job_id)

    except Exception as e:
        print(f"[SCHEDULER] Error executing job {job_id}: {e}", flush=True)
        import traceback
        traceback.print_exc()


def run_velociraptor_hunt(job_name: str, blueprint_id: str, client_ids: list):
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
    cpu_limit = settings.get('cpu_limit', 80)

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


def run_timesketch_pipeline(job_meta: dict, client_ids: list):
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

    job_name = job_meta.get('name', 'Scheduled Timesketch')
    blueprint_id = job_meta.get('blueprint_id', '')
    sketch_name = job_meta.get('description', '') or f"Scheduled_{datetime.utcnow().strftime('%Y%m%d')}"

    # Load blueprint settings
    blueprint = get_timesketch_blueprint(blueprint_id) if blueprint_id else None
    settings = blueprint.get('settings', {}) if blueprint else {}

    kape_target = settings.get('kape_target', '_KapeTriage')
    timeout_seconds = settings.get('collection_timeout', 10000)
    cpu_limit = settings.get('cpu_limit', 80)

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


def update_job_run_stats(job_id: str):
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
