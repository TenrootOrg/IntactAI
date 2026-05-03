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

from config import TIMESKETCH_CONFIG, VELOCIRAPTOR_CONTAINER, PLASO_IMAGE, PLASO_OUTPUT_DIR
from services import (
    get_job,
    update_job,
    create_automation_run,
    add_log_to_run,
    update_run_status,
    monitor_flow_completion,
    run_pinfo,
    import_to_timesketch,
    get_jobs
)
from services.velociraptor_service import export_flow_to_zip, cleanup_flow_export
from services.kape_upload_service import process_kape_upload

timesketch_bp = Blueprint('timesketch', __name__)


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

    try:
        data = request.get_json()
        flow_id = data.get('flow_id')
        client_id = data.get('client_id')
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
                            "cpu_limit": job_info.get('cpu_limit', 80),
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

                # Pass logger to monitor function for detailed logging
                flow_state = monitor_flow_completion(client_id, flow_id, timeout_seconds=monitor_timeout, logger=workflow_logger)

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

                # Phase 3: Process ZIP via the shared Upload Existing code path
                update_job(flow_id, {'phase': 'Processing with Plaso + Timesketch import'})
                workflow_logger("=== PHASE 3: Processing ZIP with Plaso + Timesketch ===", "info")
                print(f"\n[WORKFLOW] === PHASE 3: Processing ZIP ===\n", flush=True)

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
