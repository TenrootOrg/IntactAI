#!/usr/bin/env python3
"""
Timesketch Routes - Timesketch endpoints
"""

from flask import Blueprint, jsonify, request
import os
import time
import threading
import traceback
import sys
import subprocess
import shutil
from datetime import datetime

import queue

from config import TIMESKETCH_CONFIG, VELOCIRAPTOR_CONTAINER, PLASO_IMAGE, PLASO_OUTPUT_DIR
from services import (
    get_job,
    add_job,
    update_job,
    create_automation_run,
    add_log_to_run,
    update_run_status,
    monitor_flow_completion,
    run_pinfo,
    import_to_timesketch,
    get_jobs,
    run_kape_collection_grpc,
)
from services.velociraptor_service import export_flow_to_zip, cleanup_flow_export
from services.kape_upload_service import process_kape_upload

timesketch_bp = Blueprint('timesketch', __name__)

# Serializes Phase 3 (Plaso + Timesketch upload) across concurrent Timesketch
# pipelines. Multiple KAPE collections + ZIP exports run in parallel, but
# only one Plaso/upload runs at a time — Plaso is CPU+disk heavy and two
# concurrent runs degrade both.
_PLASO_PIPELINE_SEMAPHORE = threading.Semaphore(1)


def validate_automation_prerequisites():
    """
    Validate all prerequisites before starting automation.
    Returns: (success: bool, message: str)
    """
    try:
        # Check 1: Docker daemon
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        if result.returncode != 0:
            return False, "Docker daemon is not responding"

        # Check 2: Velociraptor container running
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'name={VELOCIRAPTOR_CONTAINER}', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if VELOCIRAPTOR_CONTAINER not in result.stdout:
            return False, f"Velociraptor container ({VELOCIRAPTOR_CONTAINER}) is not running"

        # Check 3: Disk space in /tmp (need at least 500MB free)
        stat = shutil.disk_usage('/tmp')
        free_mb = stat.free / (1024 * 1024)
        if free_mb < 500:
            return False, f"Insufficient disk space in /tmp ({free_mb:.0f}MB free, need 500MB)"

        # Check 4: TimeSketch container running
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=timesketch', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if 'timesketch' not in result.stdout:
            return False, "TimeSketch container is not running"

        return True, "All prerequisites validated successfully"

    except subprocess.TimeoutExpired:
        return False, "System validation timed out"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


@timesketch_bp.route('/api/timesketch/import', methods=['POST'])
def run_timesketch_import():
    """Process KAPE collection and import into TimeSketch - Complete workflow"""
    sys.stdout.flush()

    # Pre-flight: the import workflow polls a Velociraptor flow's
    # results, so the server must be reachable. Without this check the
    # request would crash deep inside services/agentic/collectors.py
    # with a generic gRPC error — useless for the operator. The 503
    # response names the artifact (`Windows.KapeFiles.Targets`) so
    # they know what's missing.
    from services.container_status import require_velociraptor
    err, status = require_velociraptor('timesketch')
    if err:
        return jsonify(err), status

    try:
        data = request.get_json(silent=True) or {}
        flow_id = data.get('flow_id')
        client_id = data.get('client_id')

        # SHAPE VALIDATION (Mythos #2 extended): both fields flow into
        # `services/agentic/collectors.py` VQL strings (`get_flow(
        # client_id='{cid}', flow_id='{fid}')`, `enumerate_flow(...)`,
        # `cancel_flow(...)`, etc.). Velociraptor's IDs follow strict
        # prefixed-alphanumeric shapes; legit inputs always pass,
        # attack shapes never do.
        from services.vql_safety import is_valid_client_id, is_valid_flow_id
        if not is_valid_client_id(client_id):
            return jsonify({"error": "client_id is required and must match C.<hex>"}), 400
        if flow_id and not is_valid_flow_id(flow_id):
            return jsonify({"error": "flow_id must match F.<alphanumeric>"}), 400
        client_name = data.get('client_name', 'Unknown')
        sketch_name = data.get('sketch_name', f'Investigation_{datetime.now().strftime("%Y%m%d")}')
        timeline_name = data.get('timeline_name', f'{client_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        sketch_id = data.get('sketch_id')  # Optional: if provided, add to existing sketch
        monitor_timeout = data.get('monitor_timeout', 10000)  # Timeout for monitoring flow completion

        # Plaso processing settings
        plaso_parser = data.get('plaso_parser', '')  # Parser preset (win7, winevtx, etc.)
        plaso_workers = data.get('plaso_workers', 2)  # Number of parallel workers
        plaso_hasher = data.get('plaso_hasher', '')  # Hasher (md5, sha1, sha256, all)
        plaso_hasher_size_mb = data.get('plaso_hasher_size_mb', 0)  # Max file size to hash in MB (0 = no limit)
        # Wall-clock cap on the Timesketch indexing wait (default 3 days). Big
        # collections can take many hours to index; the old 10000s cap killed
        # otherwise-fine uploads. Mirrors the per-blueprint key.
        timesketch_processing_timeout = data.get('timesketch_processing_timeout', 259200)

        # Use Timesketch configuration from config
        timesketch_config = TIMESKETCH_CONFIG

        if not flow_id or not client_id:
            return jsonify({"error": "flow_id and client_id are required"}), 400

        # Check if the flow exists
        jobs = get_jobs()
        if flow_id not in jobs:
            return jsonify({"error": f"Flow {flow_id} not found"}), 404

        print(f"\n{'='*80}", flush=True)
        print(f"[API] Timesketch import request received", flush=True)
        print(f"[API] Flow ID: {flow_id}", flush=True)
        print(f"[API] Client ID: {client_id}", flush=True)
        print(f"[API] Client Name: {client_name}", flush=True)
        if sketch_id:
            print(f"[API] Adding to existing Sketch ID: {sketch_id}", flush=True)
        else:
            print(f"[API] Creating new Sketch: {sketch_name}", flush=True)
        print(f"[API] Timeline Name: {timeline_name}", flush=True)
        print(f"[API] Monitor Timeout: {monitor_timeout}s", flush=True)
        print(f"{'='*80}\n", flush=True)

        # Update job status
        update_job(flow_id, {
            'status': 'processing',
            'phase': 'Starting pipeline'
        })

        # Run the complete workflow in a background thread
        def timesketch_workflow():
            """Complete Timesketch workflow: Monitor flow -> Export ZIP -> process_kape_upload (Plaso + Timesketch)"""
            run_id = None
            try:
                # Get job info and check if run_id already exists
                job_info = get_job(flow_id)
                run_id = job_info.get('run_id')  # Reuse existing run_id if it exists

                if run_id:
                    # Update existing run with additional details
                    add_log_to_run(run_id, "Continuing with full TimeSketch pipeline", "info")
                    add_log_to_run(run_id, f"Sketch: {sketch_name if not sketch_id else f'Existing Sketch #{sketch_id}'}", "info")
                    add_log_to_run(run_id, f"Timeline: {timeline_name}", "info")
                    add_log_to_run(run_id, f"Monitor timeout: {monitor_timeout}s", "info")
                else:
                    # Fallback: create new run if run_id doesn't exist (shouldn't happen)
                    run_id = create_automation_run(
                        automation_type="timesketch",
                        name=f"TimeSketch Automation - {client_name}",
                        details={
                            "flow_id": flow_id,
                            "client_id": client_id,
                            "client_name": client_name,
                            "sketch_name": sketch_name if not sketch_id else f"Existing Sketch #{sketch_id}",
                            "sketch_id": sketch_id,
                            "timeline_name": timeline_name,
                            "kape_target": job_info.get('kape_target', 'Unknown'),
                            "timeout_seconds": job_info.get('timeout_seconds', 10000),
                            "cpu_limit": job_info.get('cpu_limit', 50),
                            "monitor_timeout": monitor_timeout,
                            "blueprint_id": job_info.get('blueprint_id'),
                            "blueprint": job_info.get('blueprint', 'Unknown')
                        }
                    )

                # Register cancel event for stop support (now that run_id is known)
                from services.workflow_service import register_cancel_event
                cancel_event = register_cancel_event(run_id)

                # Create a logger callback that writes to Elasticsearch
                def workflow_logger(message, level="info"):
                    """Callback to log messages to Elasticsearch workflow run"""
                    add_log_to_run(run_id, message, level)

                # Validate prerequisites before starting
                workflow_logger("Validating system prerequisites...", "info")
                valid, validation_msg = validate_automation_prerequisites()
                if not valid:
                    workflow_logger(f"✗ Prerequisites check failed: {validation_msg}", "error")
                    update_run_status(run_id, "failed", progress=0)
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'Validation failed',
                        'error': validation_msg
                    })
                    return

                workflow_logger(f"✓ {validation_msg}", "success")
                workflow_logger("Starting Timesketch automation pipeline", "info")
                workflow_logger("This is a long-running process with 3 main phases:", "info")
                workflow_logger("  1. Monitor KAPE collection until complete", "info")
                workflow_logger("  2. Process collected files with Plaso", "info")
                workflow_logger("  3. Import timeline to Timesketch", "info")

                print(f"\n{'='*80}", flush=True)
                print(f"[WORKFLOW] Starting Timesketch automation pipeline", flush=True)
                print(f"[WORKFLOW] Run ID: {run_id}", flush=True)
                print(f"[WORKFLOW] This is a long-running process with 3 main phases:", flush=True)
                print(f"[WORKFLOW]   1. Monitor KAPE collection until complete", flush=True)
                print(f"[WORKFLOW]   2. Process collected files with Plaso", flush=True)
                print(f"[WORKFLOW]   3. Import timeline to Timesketch", flush=True)
                print(f"{'='*80}\n", flush=True)

                # Phase 1: Monitor flow completion
                update_job(flow_id, {'phase': 'Monitoring KAPE collection'})
                update_run_status(run_id, "running", progress=10)
                workflow_logger("=== PHASE 1: Monitoring KAPE Collection ===", "info")
                print(f"[WORKFLOW] === PHASE 1: Monitoring KAPE Collection ===\n", flush=True)

                # Pass run_id so monitor_flow_completion wires its CancelFlow
                # cleanup and exits promptly when the user clicks Stop while
                # KAPE is still running on the endpoint.
                flow_state = monitor_flow_completion(
                    client_id, flow_id,
                    timeout_seconds=monitor_timeout,
                    logger=workflow_logger,
                    run_id=run_id,
                )

                if flow_state == "CANCELLED":
                    workflow_logger("KAPE collection cancelled by user", "warning")
                    print(f"[WORKFLOW] User cancelled — exiting before Plaso", flush=True)
                    return

                if flow_state != "FINISHED":
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'KAPE collection failed',
                        'error': 'Flow did not complete successfully'
                    })
                    workflow_logger("Pipeline failed: KAPE collection did not complete", "error")
                    workflow_logger(f"Flow state was: {flow_state}", "error")
                    update_run_status(run_id, "failed", progress=0, error="KAPE collection did not complete successfully")
                    print(f"[WORKFLOW] ✗ Pipeline failed: KAPE collection did not complete", flush=True)
                    return

                workflow_logger("✓ KAPE collection completed successfully", "success")
                update_run_status(run_id, "running", progress=40)

                if cancel_event and cancel_event.is_set():
                    return

                # Phase 2: Export flow as ZIP and process it through the same pipeline
                # that the Upload Existing path uses. This avoids the 1 MiB chunk-
                # truncation bug in the previous live-filesystem read and gives the
                # automation identical forensic coverage to a manual upload.
                update_job(flow_id, {'phase': 'Exporting flow as ZIP'})
                workflow_logger("=== PHASE 2: Exporting Velociraptor flow as ZIP ===", "info")
                print(f"\n[WORKFLOW] === PHASE 2: Exporting Velociraptor flow as ZIP ===\n", flush=True)

                zip_path = os.path.join(PLASO_OUTPUT_DIR, f"flow_{flow_id}_{run_id}.zip")
                export_ok = export_flow_to_zip(client_id, flow_id, zip_path, logger=workflow_logger)
                if not export_ok:
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'Velociraptor ZIP export failed',
                        'error': 'Could not export flow as ZIP'
                    })
                    workflow_logger("Pipeline failed: Velociraptor ZIP export failed", "error")
                    update_run_status(run_id, "failed", progress=0, error="Could not export flow as ZIP")
                    # Still try to remove any partial ZIP left on Velociraptor's side
                    cleanup_flow_export(client_id, flow_id, logger=workflow_logger)
                    return

                update_run_status(run_id, "running", progress=50)

                if cancel_event and cancel_event.is_set():
                    # Clean up the local export and the Velociraptor-side copy
                    if os.path.exists(zip_path):
                        try:
                            os.remove(zip_path)
                        except Exception:
                            pass
                    cleanup_flow_export(client_id, flow_id, logger=workflow_logger)
                    return

                # Phase 3: Process ZIP via the shared Upload Existing code path.
                # Serialized by _PLASO_PIPELINE_SEMAPHORE so concurrent
                # Timesketch pipelines (multi-client triage) wait their turn —
                # Plaso + Timesketch upload is CPU/disk-heavy and two parallel
                # runs degrade both. KAPE and ZIP export above ran in parallel
                # across threads; only this final phase is serialized.
                settings = {
                    'sketch_name': sketch_name,
                    'timeline_name': timeline_name,
                    'sketch_id': sketch_id,
                    'client_name': client_name,  # we already know the real hostname
                    'plaso_parser': plaso_parser,
                    'plaso_workers': plaso_workers,
                    'plaso_hasher': plaso_hasher,
                    'plaso_hasher_size': plaso_hasher_size_mb,
                    'timesketch_processing_timeout': timesketch_processing_timeout,
                }

                update_job(flow_id, {'phase': 'Queued for Plaso (waiting for processing slot)'})
                workflow_logger("Waiting for Plaso processing slot (serialized across clients)", "info")
                print(f"[WORKFLOW] Waiting for Plaso processing slot...", flush=True)

                with _PLASO_PIPELINE_SEMAPHORE:
                    if cancel_event and cancel_event.is_set():
                        # Cancelled while waiting in line — release slot and bail.
                        if os.path.exists(zip_path):
                            try:
                                os.remove(zip_path)
                            except Exception:
                                pass
                        cleanup_flow_export(client_id, flow_id, logger=workflow_logger)
                        return

                    update_job(flow_id, {'phase': 'Processing with Plaso + Timesketch import'})
                    workflow_logger("=== PHASE 3: Processing ZIP with Plaso + Timesketch ===", "info")
                    print(f"\n[WORKFLOW] === PHASE 3: Processing ZIP ===\n", flush=True)

                    result = process_kape_upload(
                        zip_path=zip_path,
                        original_filename=os.path.basename(zip_path),
                        settings=settings,
                        run_id=run_id,
                        cleanup_zip=True,  # we own this ZIP, delete after processing
                    )

                # Clean up the Velociraptor-side exported ZIP regardless of Plaso/Timesketch outcome
                cleanup_flow_export(client_id, flow_id, logger=workflow_logger)

                if result and result.get('status') == 'completed':
                    update_job(flow_id, {
                        'status': 'completed',
                        'phase': 'Completed successfully',
                        'sketch_id': result.get('sketch_id'),
                        'timeline_id': result.get('timeline_id'),
                        'completed_at': int(time.time())
                    })

                    workflow_logger("✓✓✓ PIPELINE COMPLETED SUCCESSFULLY ✓✓✓", "success")
                    workflow_logger(f"Sketch: {sketch_name} (ID: {result.get('sketch_id')})", "success")
                    workflow_logger(f"Timeline: {timeline_name} (ID: {result.get('timeline_id')})", "success")

                    print(f"\n{'='*80}", flush=True)
                    print(f"[WORKFLOW] ✓✓✓ PIPELINE COMPLETED SUCCESSFULLY ✓✓✓", flush=True)
                    print(f"[WORKFLOW] Sketch: {sketch_name} (ID: {result.get('sketch_id')})", flush=True)
                    print(f"[WORKFLOW] Timeline: {timeline_name} (ID: {result.get('timeline_id')})", flush=True)
                    print(f"{'='*80}\n", flush=True)
                elif result and result.get('status') == 'no_events':
                    update_job(flow_id, {
                        'status': 'completed',
                        'phase': 'Completed - No events to import',
                        'error': None
                    })
                    # process_kape_upload already logged the warning; no further action
                else:
                    err = (result or {}).get('error', 'Unknown error')
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'Plaso/Timesketch processing failed',
                        'error': err
                    })
                    workflow_logger(f"Pipeline failed: {err}", "error")
                    # process_kape_upload sets the run status to failed already; don't double-set
                    print(f"[WORKFLOW] ✗ Pipeline failed: {err}", flush=True)

            except Exception as e:
                from services.workflow_service import is_cancelled
                if is_cancelled(run_id):
                    return
                error_detail = traceback.format_exc()
                update_job(flow_id, {
                    'status': 'failed',
                    'phase': 'Workflow error',
                    'error': str(e)
                })
                if run_id:
                    workflow_logger(f"Pipeline failed with exception: {str(e)}", "error")
                    workflow_logger(f"Stack trace: {error_detail}", "error")
                    update_run_status(run_id, "failed", progress=0, error=str(e))
                print(f"[WORKFLOW] ✗ Pipeline failed with exception: {e}", flush=True)
                traceback.print_exc()
            finally:
                from services.workflow_service import unregister_cancel
                unregister_cancel(run_id)

        # Start workflow in background thread (cancel event is registered inside the thread once run_id is known)
        workflow_thread = threading.Thread(target=timesketch_workflow, daemon=True)
        workflow_thread.start()

        print(f"[API] ✓ Timesketch pipeline started in background", flush=True)
        print(f"[API] Monitor backend logs for detailed progress\n", flush=True)

        return jsonify({
            "status": "processing",
            "flow_id": flow_id,
            "phase": "Starting pipeline",
            "message": "Timesketch import pipeline started. This is a long process with 3 phases: KAPE monitoring, Plaso processing, and Timesketch import. Monitor backend logs for detailed progress."
        })

    except Exception as e:
        print(f"[API] ✗ Error starting TimeSketch import: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@timesketch_bp.route('/api/timesketch/start-multi', methods=['POST'])
def start_multi_client_timesketch():
    """Start a single Timesketch workflow that fans out KAPE collection across
    multiple clients in parallel, then serializes Plaso + Timesketch upload
    in first-finished-first-processed order. All clients appear under one
    workflow row in the UI."""
    sys.stdout.flush()

    # Same Velociraptor pre-flight as /api/timesketch/import — multi-client
    # mode also dispatches Windows.KapeFiles.Targets, just across N clients.
    from services.container_status import require_velociraptor
    err, status = require_velociraptor('timesketch')
    if err:
        return jsonify(err), status

    try:
        data = request.get_json() or {}
        clients_in = data.get('clients') or []
        if not isinstance(clients_in, list) or not clients_in:
            return jsonify({"error": "clients (non-empty array) is required"}), 400

        # Normalize client list: [{client_id, client_name}, ...]
        clients = []
        for c in clients_in:
            cid = (c or {}).get('client_id')
            cname = (c or {}).get('client_name') or 'Unknown'
            if cid:
                clients.append({'client_id': cid, 'client_name': cname})
        if not clients:
            return jsonify({"error": "no valid client_id values in clients[]"}), 400

        # KAPE / blueprint settings (same shape as /api/velociraptor/timesketch)
        kape_target     = data.get('kape_target', '_KapeTriage')
        timeout_seconds = data.get('timeout_seconds', 10000)
        cpu_limit       = data.get('cpu_limit', 50)
        blueprint_id    = data.get('blueprint_id')
        blueprint_name  = data.get('blueprint', 'Unknown')

        # Resolve blueprint-derived KAPE/flow ceilings (mirror velociraptor_routes)
        kape_max_file_size       = 10737418240
        kape_max_hash_size       = 0
        kape_collection_policy   = 'ExcludeSigned'
        flow_max_rows            = 10000000
        flow_max_logs            = 1000000
        flow_max_upload_mb       = 51200
        if blueprint_id:
            from services.file_storage_service import get_timesketch_blueprint
            bp = get_timesketch_blueprint(blueprint_id)
            if bp:
                bp_s = bp.get('settings', {}) or {}
                kape_max_file_size     = bp_s.get('kape_max_file_size', kape_max_file_size)
                kape_max_hash_size     = bp_s.get('kape_max_hash_size', kape_max_hash_size)
                kape_collection_policy = bp_s.get('kape_collection_policy', kape_collection_policy)
                flow_max_rows          = bp_s.get('flow_max_rows', flow_max_rows)
                flow_max_logs          = bp_s.get('flow_max_logs', flow_max_logs)
                flow_max_upload_mb     = bp_s.get('flow_max_upload_mb', flow_max_upload_mb)

        # Timesketch + Plaso settings
        sketch_name      = data.get('sketch_name', f'Investigation_{datetime.now().strftime("%Y%m%d")}')
        sketch_id        = data.get('sketch_id')
        monitor_timeout  = data.get('monitor_timeout', 10000)
        plaso_parser     = data.get('plaso_parser', '')
        plaso_workers    = data.get('plaso_workers', 2)
        plaso_hasher     = data.get('plaso_hasher', '')
        plaso_hasher_size_mb           = data.get('plaso_hasher_size_mb', 0)
        timesketch_processing_timeout  = data.get('timesketch_processing_timeout', 259200)

        hostnames_list = [c['client_name'] for c in clients]
        hostnames_str  = ', '.join(hostnames_list)

        # ONE parent run for the whole multi-client pipeline.
        run_id = create_automation_run(
            automation_type="timesketch",
            name=f"TimeSketch Automation - {len(clients)} clients ({hostnames_str})",
            details={
                "multi_client": True,
                "client_count": len(clients),
                "hostnames": hostnames_list,
                "clients": [{**c, "kape_status": "pending", "plaso_status": "pending"} for c in clients],
                "sketch_name": sketch_name if not sketch_id else f"Existing Sketch #{sketch_id}",
                "sketch_id": sketch_id,
                "kape_target": kape_target,
                "timeout_seconds": timeout_seconds,
                "cpu_limit": cpu_limit,
                "monitor_timeout": monitor_timeout,
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_name,
            }
        )
        add_log_to_run(run_id, f"Starting multi-client TimeSketch automation for {len(clients)} clients: {hostnames_str}", "info")
        add_log_to_run(run_id, f"KAPE Target: {kape_target} | Blueprint: {blueprint_name}", "info")
        add_log_to_run(run_id, "Strategy: KAPE collection runs on all clients in parallel; Plaso + Timesketch upload runs one at a time (first-finished-first-processed).", "info")
        update_run_status(run_id, "running", progress=2)

        # Validate prerequisites once (Docker, Velociraptor container, etc.)
        valid, validation_msg = validate_automation_prerequisites()
        if not valid:
            add_log_to_run(run_id, f"✗ Prerequisites check failed: {validation_msg}", "error")
            update_run_status(run_id, "failed", progress=0, error=validation_msg)
            return jsonify({"error": f"Prerequisites failed: {validation_msg}"}), 500
        add_log_to_run(run_id, f"✓ {validation_msg}", "success")

        # Kick off KAPE for every client up-front (gRPC calls return instantly
        # with a flow_id; the actual collection runs on the endpoint).
        for c in clients:
            flow_id = run_kape_collection_grpc(
                c['client_id'], kape_target, timeout_seconds, cpu_limit,
                max_rows=flow_max_rows, max_logs=flow_max_logs,
                max_upload_mb=flow_max_upload_mb,
                max_file_size=kape_max_file_size,
                max_hash_size=kape_max_hash_size,
                collection_policy=kape_collection_policy,
            )
            if not flow_id:
                add_log_to_run(run_id, f"✗ Failed to start KAPE on {c['client_name']} ({c['client_id']})", "error")
                c['flow_id'] = None
                continue

            c['flow_id'] = flow_id
            c['kape_started_at'] = time.time()
            add_log_to_run(run_id, f"[KAPE] Started on {c['client_name']} → flow {flow_id}", "info")

            # Register in jobs dict so the flow is visible/cancellable elsewhere,
            # but the canonical state lives on the parent run_id.
            add_job(flow_id, {
                "flow_id": flow_id,
                "client_id": c['client_id'],
                "client_name": c['client_name'],
                "artifact_id": "kape",
                "artifact_name": "KAPE Collection",
                "kape_target": kape_target,
                "timeout_seconds": timeout_seconds,
                "cpu_limit": cpu_limit,
                "status": "collecting",
                "started_at": int(time.time()),
                "phase": "KAPE Collection (multi-client)",
                "run_id": run_id,
                "parent_multi": True,
            })

        # Drop clients whose KAPE didn't even start.
        live_clients = [c for c in clients if c.get('flow_id')]
        if not live_clients:
            update_run_status(run_id, "failed", progress=0, error="No KAPE collections could be started")
            return jsonify({"run_id": run_id, "error": "No KAPE collections could be started"}), 500

        # Register cancel event so the Stop button affects this run.
        from services.workflow_service import register_cancel_event, unregister_cancel, is_cancelled
        cancel_event = register_cancel_event(run_id)

        # --- The orchestrator -----------------------------------------------
        # N parallel threads each monitor their KAPE + export ZIP, then push
        # the resulting ZIP into a queue. ONE consumer thread does Plaso +
        # Timesketch upload, draining the queue in arrival order ("first
        # finished is first processed").
        # --------------------------------------------------------------------

        plaso_queue = queue.Queue()
        # plaso_in_flight: 0 or 1 — whether the consumer is currently mid-Plaso.
        # Used so the "queued behind X" log line reflects reality (Queue.qsize()
        # alone does NOT count the item currently being processed).
        state = {'kape_done': 0, 'plaso_done': 0, 'plaso_in_flight': 0, 'total': len(live_clients)}
        state_lock = threading.Lock()

        # KAPE typically wraps in 1–5 min for RegistryHives, up to 15+ min
        # for _KapeTriage. Plaso + Timesketch import on a triage zip is
        # usually 3–10 min. We don't get a real percentage from either, so
        # the heartbeat asymptotes per-client fractional progress to 0.85
        # over these soft deadlines — the final 0.15 fills in when the
        # phase actually completes. Without this the bar sits at 2% (or
        # 5%) for the entire KAPE+Plaso runtime and only jumps to 100%
        # at the very end.
        KAPE_SOFT_DEADLINE = 300.0
        PLASO_SOFT_DEADLINE = 600.0

        def _bump_progress():
            # KAPE phase weighted 40%, Plaso phase weighted 60%. Per-client
            # frac (0..1) lets the bar move mid-phase instead of jumping
            # only when whole clients finish — the heartbeat thread updates
            # frac periodically based on elapsed time.
            with state_lock:
                kape_units = sum(min(1.0, c.get('kape_frac', 0)) for c in live_clients)
                plaso_units = sum(min(1.0, c.get('plaso_frac', 0)) for c in live_clients)
            done_units = kape_units * 0.4 + plaso_units * 0.6
            pct = int(5 + (done_units / state['total']) * 95)
            update_run_status(run_id, "running", progress=min(pct, 99))

        def _heartbeat():
            """Smooth-progress ticker. Without this, a 1-client run sits at
            2% for the entire KAPE+Plaso runtime and only jumps to 100%
            at the very end."""
            while True:
                with state_lock:
                    all_done = (state['kape_done'] >= state['total']
                                and state['plaso_done'] >= state['total'])
                if all_done:
                    return
                if cancel_event.is_set():
                    return
                now = time.time()
                changed = False
                with state_lock:
                    for c in live_clients:
                        if c.get('flow_id') and 'kape_started_at' in c and c.get('kape_frac', 0) < 1.0:
                            est = min(0.85, (now - c['kape_started_at']) / KAPE_SOFT_DEADLINE)
                            if est > c.get('kape_frac', 0):
                                c['kape_frac'] = est
                                changed = True
                        if 'plaso_started_at' in c and c.get('plaso_frac', 0) < 1.0:
                            est = min(0.85, (now - c['plaso_started_at']) / PLASO_SOFT_DEADLINE)
                            if est > c.get('plaso_frac', 0):
                                c['plaso_frac'] = est
                                changed = True
                if changed:
                    _bump_progress()
                if cancel_event.wait(10):
                    return

        def _per_client_collect(c):
            """Monitor KAPE on one client and export its ZIP."""
            try:
                if cancel_event.is_set():
                    return
                add_log_to_run(run_id, f"[KAPE/{c['client_name']}] Monitoring flow {c['flow_id']}...", "info")
                flow_state = monitor_flow_completion(
                    c['client_id'], c['flow_id'],
                    timeout_seconds=monitor_timeout,
                    logger=lambda m, l='info': add_log_to_run(run_id, f"[KAPE/{c['client_name']}] {m}", l),
                    run_id=run_id,
                )

                if cancel_event.is_set():
                    return

                if flow_state != "FINISHED":
                    add_log_to_run(run_id, f"[KAPE/{c['client_name']}] ✗ Flow did not finish (state={flow_state})", "error")
                    update_job(c['flow_id'], {'status': 'failed', 'phase': 'KAPE failed', 'error': f'state={flow_state}'})
                    return

                add_log_to_run(run_id, f"[KAPE/{c['client_name']}] ✓ Collection complete — exporting ZIP", "success")
                zip_path = os.path.join(PLASO_OUTPUT_DIR, f"flow_{c['flow_id']}_{run_id}.zip")
                export_ok = export_flow_to_zip(
                    c['client_id'], c['flow_id'], zip_path,
                    logger=lambda m, l='info': add_log_to_run(run_id, f"[ZIP/{c['client_name']}] {m}", l),
                )
                if not export_ok:
                    add_log_to_run(run_id, f"[ZIP/{c['client_name']}] ✗ Export failed", "error")
                    update_job(c['flow_id'], {'status': 'failed', 'phase': 'ZIP export failed'})
                    return

                # Hand off to the Plaso consumer in completion order.
                # c_ref pins the consumer to the SAME dict instance we
                # update plaso_frac on — otherwise the spread copy diverges
                # and the heartbeat would see stale frac values.
                plaso_queue.put({**c, 'zip_path': zip_path, 'c_ref': c})
                with state_lock:
                    # Number of clients ahead in the pipeline = the one currently
                    # being processed (if any) + everyone still queued in front
                    # of us. qsize() after put includes us, so subtract 1.
                    ahead = state['plaso_in_flight'] + max(0, plaso_queue.qsize() - 1)
                if ahead:
                    add_log_to_run(run_id, f"[Queue/{c['client_name']}] Handed off to Plaso queue ({ahead} client(s) ahead — will wait their turn)", "info")
                else:
                    add_log_to_run(run_id, f"[Queue/{c['client_name']}] Handed off to Plaso queue (front of line — will process immediately)", "info")

            except Exception as e:
                add_log_to_run(run_id, f"[KAPE/{c['client_name']}] Exception: {e}", "error")
                traceback.print_exc()
            finally:
                with state_lock:
                    state['kape_done'] += 1
                    c['kape_frac'] = 1.0
                _bump_progress()

        def _plaso_consumer():
            """Pull one ZIP at a time from the queue and run Plaso + upload."""
            while True:
                # Stop once all collectors have finished AND queue is drained.
                with state_lock:
                    all_collectors_done = state['kape_done'] >= state['total']
                if all_collectors_done and plaso_queue.empty():
                    return

                try:
                    item = plaso_queue.get(timeout=2)
                except queue.Empty:
                    continue

                if cancel_event.is_set():
                    # Clean up the orphan ZIP if cancelled.
                    try:
                        if os.path.exists(item['zip_path']):
                            os.remove(item['zip_path'])
                    except Exception:
                        pass
                    cleanup_flow_export(item['client_id'], item['flow_id'], logger=lambda m, l='info': add_log_to_run(run_id, m, l))
                    plaso_queue.task_done()
                    continue

                try:
                    with state_lock:
                        state['plaso_in_flight'] = 1
                        item['c_ref']['plaso_started_at'] = time.time()
                    update_job(item['flow_id'], {'phase': 'Processing with Plaso + Timesketch import'})
                    add_log_to_run(run_id, f"[Plaso/{item['client_name']}] === Starting Plaso + Timesketch upload ===", "info")
                    settings = {
                        'sketch_name': sketch_name,
                        'timeline_name': f"{item['client_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        'sketch_id': sketch_id,
                        'client_name': item['client_name'],
                        'plaso_parser': plaso_parser,
                        'plaso_workers': plaso_workers,
                        'plaso_hasher': plaso_hasher,
                        'plaso_hasher_size': plaso_hasher_size_mb,
                        'timesketch_processing_timeout': timesketch_processing_timeout,
                    }
                    result = process_kape_upload(
                        zip_path=item['zip_path'],
                        original_filename=os.path.basename(item['zip_path']),
                        settings=settings,
                        run_id=run_id,
                        cleanup_zip=True,
                        # Multi-client mode: orchestrator owns the parent run's
                        # progress + status field. Otherwise each per-client call
                        # would overwrite the bar with its own 5→70→100% and
                        # briefly mark the whole run "completed" after the first.
                        suppress_status_writes=True,
                    )
                    cleanup_flow_export(item['client_id'], item['flow_id'], logger=lambda m, l='info': add_log_to_run(run_id, m, l))

                    if result and result.get('status') == 'completed':
                        add_log_to_run(run_id, f"[Plaso/{item['client_name']}] ✓ Imported (sketch {result.get('sketch_id')}, timeline {result.get('timeline_id')})", "success")
                        update_job(item['flow_id'], {'status': 'completed', 'phase': 'Completed', 'sketch_id': result.get('sketch_id'), 'timeline_id': result.get('timeline_id')})
                        # Land the sketch locator on the PARENT run. In
                        # multi-client mode process_kape_upload runs with
                        # suppress_status_writes=True (the orchestrator owns
                        # the status field), so its own details write is a
                        # no-op — without this the parent run keeps
                        # sketch_id=None and fusion falls back to resolving
                        # the sketch by NAME, which picks the wrong one as
                        # soon as two runs share a name. Every client here
                        # imports into the SAME sketch, so last-writer-wins
                        # is correct; timeline_id is per client and only the
                        # last is kept (fusion reads the sketch, not the
                        # timeline).
                        try:
                            from services.workflow_service import mutate_run_details

                            def _stamp(_d, _r=result):
                                if _r.get('sketch_id'):
                                    _d['sketch_id'] = _r.get('sketch_id')
                                if _r.get('timeline_id'):
                                    _d['timeline_id'] = _r.get('timeline_id')
                            mutate_run_details(run_id, _stamp)
                        except Exception as _e:
                            add_log_to_run(run_id, f"Could not record sketch id: {_e}", "warning")
                    elif result and result.get('status') == 'no_events':
                        add_log_to_run(run_id, f"[Plaso/{item['client_name']}] Completed — no events to import", "warning")
                        update_job(item['flow_id'], {'status': 'completed', 'phase': 'Completed (no events)'})
                    else:
                        err = (result or {}).get('error', 'unknown error')
                        add_log_to_run(run_id, f"[Plaso/{item['client_name']}] ✗ Failed: {err}", "error")
                        update_job(item['flow_id'], {'status': 'failed', 'phase': 'Plaso/Timesketch failed', 'error': err})
                except Exception as e:
                    add_log_to_run(run_id, f"[Plaso/{item['client_name']}] Exception: {e}", "error")
                    traceback.print_exc()
                finally:
                    with state_lock:
                        state['plaso_done'] += 1
                        state['plaso_in_flight'] = 0
                        item['c_ref']['plaso_frac'] = 1.0
                    _bump_progress()
                    plaso_queue.task_done()

        def _orchestrator():
            try:
                # Spawn one collector thread per client + the single consumer
                # + a heartbeat that smooths progress mid-phase so the bar
                # isn't stuck at 2% for the whole KAPE+Plaso runtime.
                collectors = [threading.Thread(target=_per_client_collect, args=(c,), daemon=True) for c in live_clients]
                consumer   = threading.Thread(target=_plaso_consumer, daemon=True)
                heartbeat  = threading.Thread(target=_heartbeat, daemon=True)
                consumer.start()
                heartbeat.start()
                for t in collectors:
                    t.start()
                for t in collectors:
                    t.join()
                consumer.join()
                heartbeat.join(timeout=12)

                if cancel_event.is_set():
                    add_log_to_run(run_id, "Pipeline cancelled by user", "warning")
                    update_run_status(run_id, "cancelled", progress=state['plaso_done'] * 100 // max(state['total'], 1))
                    return

                add_log_to_run(run_id, f"✓✓✓ Multi-client pipeline complete: KAPE {state['kape_done']}/{state['total']}, Plaso {state['plaso_done']}/{state['total']}", "success")
                update_run_status(run_id, "completed", progress=100)
            except Exception as e:
                add_log_to_run(run_id, f"Orchestrator exception: {e}", "error")
                traceback.print_exc()
                update_run_status(run_id, "failed", progress=0, error=str(e))
            finally:
                unregister_cancel(run_id)

        threading.Thread(target=_orchestrator, daemon=True).start()

        return jsonify({
            "status": "processing",
            "run_id": run_id,
            "clients": [{"client_id": c['client_id'], "client_name": c['client_name'], "flow_id": c.get('flow_id')} for c in clients],
            "message": f"Multi-client TimeSketch pipeline started for {len(live_clients)}/{len(clients)} clients."
        })

    except Exception as e:
        print(f"[API] ✗ Error starting multi-client TimeSketch pipeline: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@timesketch_bp.route('/api/timesketch/status')
def get_timesketch_status():
    """Get status of TimeSketch import jobs with phase information"""
    jobs = get_jobs()
    timesketch_jobs = [
        job for job in jobs.values()
        if job.get("artifact_id") == "kape" or "timesketch" in job.get("artifact_name", "").lower()
    ]

    # Add detailed phase information for each job
    for job in timesketch_jobs:
        if 'phase' not in job:
            if job.get('status') == 'collecting':
                job['phase'] = 'KAPE Collection'
            elif job.get('status') == 'processing':
                job['phase'] = 'Processing'
            elif job.get('status') == 'completed':
                job['phase'] = 'Completed'
            elif job.get('status') == 'failed':
                job['phase'] = 'Failed'

    return jsonify({"jobs": timesketch_jobs})

@timesketch_bp.route('/api/timesketch/sketches')
def get_timesketch_sketches():
    """Get list of existing sketches from Timesketch"""
    import subprocess
    try:
        ts_host = TIMESKETCH_CONFIG.get('host', 'http://localhost:5000')
        ts_username = TIMESKETCH_CONFIG.get('username', 'admin')
        ts_password = TIMESKETCH_CONFIG.get('password', 'admin')

        # Use timesketch CLI to list sketches
        cmd = [
            'python3', '-c',
            f'''
from timesketch_api_client import config as ts_config
from timesketch_api_client import client as ts_client

api_client = ts_client.TimesketchApi(
    host_uri="{ts_host}",
    username="{ts_username}",
    password="{ts_password}"
)

sketches = api_client.list_sketches()
for s in sketches:
    print(f"{{s.id}}|{{s.name}}|{{s.description}}")
'''
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        sketches = []
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if '|' in line:
                    parts = line.split('|', 2)
                    if len(parts) >= 2:
                        sketches.append({
                            'id': parts[0],
                            'name': parts[1],
                            'description': parts[2] if len(parts) > 2 else ''
                        })

        return jsonify({"sketches": sketches})

    except Exception as e:
        print(f"[TIMESKETCH] Error fetching sketches: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"sketches": [], "error": str(e)})
