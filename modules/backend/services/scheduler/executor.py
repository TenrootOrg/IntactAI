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
                automation_type="velociraptor_collection",
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

        elif blueprint_type == 'memory':
            # Memory-forensics pipeline — single host per run (memory
            # acquisition is per-target). The scheduler hands the first
            # client_id; multi-client scheduling for memory is a defer
            # because of disk-pressure mechanics documented in the plan.
            run_memory_scheduled(job_meta, client_ids)
            print(f"[SCHEDULER] Started memory pipeline for {len(client_ids)} clients", flush=True)

        elif blueprint_type == 'cve':
            # CVE Management — env-wide: dispatch the cve_management hunt to every
            # client, then auto-run the NVD scan on the results. No client_ids
            # (hunt model). Runs in its own thread (see run_cve_scan_scheduled).
            run_cve_scan_scheduled(job_meta['name'])
            print(f"[SCHEDULER] Started CVE management scan (env-wide)", flush=True)

        else:
            # Velociraptor Hunt (env-wide) — legacy 'velociraptor' + explicit 'hunt'.
            run_velociraptor_hunt(job_meta['name'], blueprint_id, client_ids)
            print(f"[SCHEDULER] Started velociraptor hunt: blueprint={blueprint_id}", flush=True)

        # Update job metadata
        update_job_run_stats(job_id)

        # Re-arm month/year interval jobs (one-shot DateTrigger); no-op for days/weeks.
        try:
            from .jobs import reschedule_after_run
            reschedule_after_run(job_id)
        except Exception as _re:
            print(f"[SCHEDULER] Reschedule after run failed for {job_id}: {_re}", flush=True)

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
    # Flow-level resource limits — bumped from the historical hardcoded values
    # (1M rows / 100K logs / 1 GiB) to defaults that fit real KAPE-class
    # collections. Existing blueprints that don't carry these keys inherit
    # the new ceilings via the .get() fallback.
    flow_max_rows      = settings.get('flow_max_rows', 10000000)
    flow_max_logs      = settings.get('flow_max_logs', 1000000)
    flow_max_upload_mb = settings.get('flow_max_upload_mb', 51200)
    flow_max_bytes     = int(flow_max_upload_mb) * 1024 * 1024

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

        # hunt() rejects max_logs (collect_client-only arg), so we omit it.
        # flow_max_logs is still honored on the TimeSketch / collect_client path.
        _ = flow_max_logs  # intentionally unused here
        query = f"""
LET collection = hunt(
    description='Scheduled: {job_name} ({len(artifacts)} artifacts)',
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    max_rows={flow_max_rows},
    max_bytes={flow_max_bytes},
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


def run_cve_scan_scheduled(job_name: str):
    """Scheduled CVE Management — env-wide: dispatch the cve_management hunt to
    every enrolled client, wait for it, then auto-run the NVD scan on the pulled
    results. Mirrors routes/cve_routes.py `_worker()`; runs in a daemon thread so
    the APScheduler worker isn't held for the hunt's wait window. No client_ids
    (hunt model)."""
    import threading
    from pathlib import Path
    from services.workflow_service import (create_automation_run, update_run_status,
                                           register_cancel_event)
    from services.cve_scan.hunt import _dispatch_cve_hunt, _wait_for_hunt, _stop_hunt
    from services.cve_scan import run_cve_scan, pull_from_velociraptor

    # Wait window = the cve_management blueprint's hunt_expiry (minutes), else 120.
    try:
        from services.file_storage_service import get_velociraptor_blueprint
        bp = get_velociraptor_blueprint('cve_management') or {}
        expiry_min = int((bp.get('settings') or {}).get('hunt_expiry', 120))
    except Exception:
        expiry_min = 120
    max_wait_seconds = max(60, expiry_min * 60)

    run_id = create_automation_run(
        automation_type='cve_scan',
        name=f"Scheduled: {job_name}",
        details={"source": "scheduler", "scan_mode": "vulnerable_only"},
    )
    register_cancel_event(run_id)

    def _worker():
        try:
            update_run_status(run_id, 'running', progress=5)
            hunt_id = _dispatch_cve_hunt(run_id, description=f"Intact.AI CVE Scan: {job_name}",
                                         max_wait_seconds=max_wait_seconds)
            if not hunt_id:
                update_run_status(run_id, 'failed', error='Failed to dispatch CVE hunt')
                return
            try:
                from services.file_storage_service import get_workflow, save_workflow
                w = get_workflow(run_id)
                if w:
                    w.setdefault('details', {})['hunt_id'] = hunt_id
                    save_workflow(w)
            except Exception:
                pass
            finished = _wait_for_hunt(run_id, hunt_id, timeout_seconds=max_wait_seconds)
            if not finished:
                _stop_hunt(run_id, hunt_id)
            run_dir = Path('/tmp/cve_uploads') / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            csvs = pull_from_velociraptor(run_id, None, hunt_id, run_dir)
            if not csvs:
                update_run_status(run_id, 'failed', error='CVE hunt produced no data to scan')
                return
            run_cve_scan(run_id, csvs, name=job_name, mode='vulnerable_only')
        except Exception as e:
            print(f"[SCHEDULER] CVE scheduled run error: {e}", flush=True)
            try:
                update_run_status(run_id, 'failed', error=str(e))
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()
    return run_id


def run_timesketch_pipeline(job_meta: dict, client_ids: list):
    """Execute a Timesketch automation pipeline for each client.

    This runs KAPE collection followed by Plaso processing and TimeSketch import.
    """
    from services.kape_service import run_kape_collection_grpc, monitor_flow_completion
    from services.velociraptor_service import export_flow_to_zip, cleanup_flow_export
    from services.agentic.collectors._base import resolve_hostnames
    from services.kape_upload_service import process_kape_upload
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    from services.file_storage_service import get_timesketch_blueprint
    from config import PLASO_OUTPUT_DIR
    import os

    job_name = job_meta.get('name', 'Scheduled Timesketch')
    blueprint_id = job_meta.get('blueprint_id', '')
    sketch_name = job_meta.get('description', '') or f"Scheduled_{datetime.utcnow().strftime('%Y%m%d')}"

    # Load blueprint settings
    blueprint = get_timesketch_blueprint(blueprint_id) if blueprint_id else None
    settings = blueprint.get('settings', {}) if blueprint else {}

    kape_target = settings.get('kape_target', '_KapeTriage')
    timeout_seconds = settings.get('collection_timeout', 10000)
    cpu_limit = settings.get('cpu_limit', 80)
    # KAPE artifact env params (passed into collect_client(env=dict(...))).
    # Defaults match default_blueprints.yaml so even legacy DB rows that
    # predate these keys still get the bumped ceilings.
    kape_max_file_size       = settings.get('kape_max_file_size', 10737418240)
    kape_max_hash_size       = settings.get('kape_max_hash_size', 0)
    kape_collection_policy   = settings.get('kape_collection_policy', 'ExcludeSigned')
    # Flow-level resource limits (passed as collect_client args).
    flow_max_rows            = settings.get('flow_max_rows', 10000000)
    flow_max_logs            = settings.get('flow_max_logs', 1000000)
    flow_max_upload_mb       = settings.get('flow_max_upload_mb', 51200)

    for client_id in client_ids:
        try:
            # Get client hostname
            client_name = resolve_hostnames([client_id]).get(client_id, client_id)

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

            # Register a cancel event so the user can Stop a scheduled run
            # from the dashboard. Without this, the Velociraptor CancelFlow
            # cleanup we wired into monitor_flow_completion has no event
            # to attach to, and the run is uninterruptible until KAPE
            # finishes naturally.
            from services.workflow_service import register_cancel_event
            register_cancel_event(run_id)

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
                cpu_limit=cpu_limit,
                max_rows=flow_max_rows,
                max_logs=flow_max_logs,
                max_upload_mb=flow_max_upload_mb,
                max_file_size=kape_max_file_size,
                max_hash_size=kape_max_hash_size,
                collection_policy=kape_collection_policy,
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
                logger=workflow_logger,
                run_id=run_id,  # wire workflow Stop into the Velociraptor CancelFlow
            )

            if flow_state == "CANCELLED":
                workflow_logger("KAPE collection cancelled by user", "warning")
                continue

            if flow_state != "FINISHED":
                workflow_logger(f"KAPE collection failed: {flow_state}", "error")
                update_run_status(run_id, "failed")
                continue

            workflow_logger("KAPE collection completed successfully", "success")
            update_run_status(run_id, "running", progress=40)

            # Step 3: Export flow as ZIP, then process via shared upload path.
            # This avoids the live-filesystem 1 MiB chunk-truncation bug.
            workflow_logger("=== PHASE 3: Exporting Velociraptor flow as ZIP ===")
            zip_path = os.path.join(PLASO_OUTPUT_DIR, f"flow_{flow_id}_{run_id}.zip")
            export_ok = export_flow_to_zip(client_id, flow_id, zip_path, logger=workflow_logger)
            if not export_ok:
                workflow_logger("Velociraptor ZIP export failed", "error")
                update_run_status(run_id, "failed")
                cleanup_flow_export(client_id, flow_id, logger=workflow_logger)
                continue

            update_run_status(run_id, "running", progress=55)

            # Step 4: Process ZIP via the same pipeline as Upload Existing
            workflow_logger("=== PHASE 4: Processing ZIP with Plaso + Timesketch ===")
            timeline_name = f"{client_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

            result = process_kape_upload(
                zip_path=zip_path,
                original_filename=os.path.basename(zip_path),
                settings={
                    'sketch_name': sketch_name,
                    'timeline_name': timeline_name,
                    'client_name': client_name,  # we already know the real hostname
                    'plaso_parser': settings.get('plaso_parser'),
                    'plaso_workers': settings.get('plaso_workers', 2),
                    'plaso_hasher': settings.get('plaso_hasher'),
                    'plaso_hasher_size': settings.get('plaso_hasher_size', 100),
                    # Propagate the per-blueprint TS-processing wait timeout so
                    # big collections aren't capped by the old hardcoded ~3 h.
                    'timesketch_processing_timeout': settings.get(
                        'timesketch_processing_timeout', 259200
                    ),
                },
                run_id=run_id,
                cleanup_zip=True,
            )

            # Clean up the Velociraptor-side export dir regardless of outcome
            cleanup_flow_export(client_id, flow_id, logger=workflow_logger)

            if result and result.get('status') == 'completed':
                workflow_logger("Timesketch import completed successfully", "success")
                workflow_logger(f"Sketch ID: {result.get('sketch_id')}", "success")
                workflow_logger(f"Timeline ID: {result.get('timeline_id')}", "success")
            elif result and result.get('status') == 'no_events':
                workflow_logger("No events to import (parser mismatch)", "warning")
                # process_kape_upload already set status to completed
            else:
                err = (result or {}).get('error', 'Unknown error')
                workflow_logger(f"Pipeline failed: {err}", "error")
                # process_kape_upload already set status to failed

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


def run_memory_scheduled(job_meta: dict, client_ids: list) -> None:
    """Dispatch a memory-forensics run from a scheduled blueprint.

    Memory acquisition is per-host (4-16 GB transient .raw, three
    concurrent copies during pipeline), so the scheduler runs ONE
    client per job firing. If the operator scheduled multi-client,
    we iterate them serially — each becomes its own workflow row.
    """
    import threading

    from services.memory.pipeline import run_memory_pipeline
    from services.storage.blueprint_store import get_memory_blueprint
    from services.workflow_service import create_automation_run, update_run_status, add_log_to_run

    if not client_ids:
        print("[SCHEDULER] memory: no client_ids — skipping", flush=True)
        return

    blueprint_id = job_meta.get("blueprint_id") or ""
    blueprint = get_memory_blueprint(blueprint_id) if blueprint_id else None
    settings = (blueprint.get("settings") if blueprint else {}) or {}
    mode = settings.get("mode") or "layered"
    case_name = job_meta.get("case_name") or job_meta.get("name") or "Memory (scheduled)"

    for cid in client_ids:
        run_id = create_automation_run(
            automation_type="memory",
            name=f"Memory ({mode}) — scheduled: {cid}",
            details={
                "trigger": "scheduled",
                "scheduled_job_id": job_meta.get("id"),
                "mode": mode,
                "client_id": cid,
                "blueprint_id": blueprint_id or None,
                "case_name": case_name,
            },
        )
        add_log_to_run(run_id, f"scheduler: memory dispatch client={cid} mode={mode}", "info")
        update_run_status(run_id, "running", progress=1)
        threading.Thread(
            target=run_memory_pipeline,
            kwargs={
                "run_id": run_id,
                "client_id": cid,
                "mode": mode,
                "case_name": case_name,
                "blueprint": blueprint,
            },
            daemon=True,
        ).start()
