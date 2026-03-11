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

from config import TIMESKETCH_CONFIG, VELOCIRAPTOR_CONTAINER, PLASO_IMAGE
from services import (
    get_job,
    update_job,
    create_automation_run,
    add_log_to_run,
    update_run_status,
    monitor_flow_completion,
    process_with_plaso,
    run_pinfo,
    import_to_timesketch,
    get_jobs
)

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
            """Complete Timesketch workflow: Monitor -> Plaso -> Import"""
            run_id = None
            plaso_file = None  # Track for cleanup
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

                # Phase 2: Process with Plaso
                update_job(flow_id, {'phase': 'Processing with Plaso'})
                workflow_logger("=== PHASE 2: Processing with Plaso ===", "info")
                if plaso_parser:
                    workflow_logger(f"Parser preset: {plaso_parser}", "info")
                workflow_logger(f"Workers: {plaso_workers}", "info")
                if plaso_hasher:
                    hasher_info = f"Hasher: {plaso_hasher}"
                    if plaso_hasher_size_mb > 0:
                        hasher_info += f" (files < {plaso_hasher_size_mb}MB)"
                    workflow_logger(hasher_info, "info")
                print(f"\n[WORKFLOW] === PHASE 2: Processing with Plaso ===\n", flush=True)

                # Pass logger to Plaso for detailed logging
                plaso_file = process_with_plaso(
                    client_id, flow_id, client_name,
                    logger=workflow_logger,
                    parser=plaso_parser,
                    workers=plaso_workers,
                    hasher=plaso_hasher,
                    hasher_file_size_mb=plaso_hasher_size_mb
                )

                if not plaso_file:
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'Plaso processing failed',
                        'error': 'Failed to process files with Plaso'
                    })
                    workflow_logger("Pipeline failed: Plaso processing failed", "error")
                    workflow_logger("Check the detailed logs above for error information", "error")
                    update_run_status(run_id, "failed", progress=0, error="Failed to process files with Plaso")
                    print(f"[WORKFLOW] ✗ Pipeline failed: Plaso processing failed", flush=True)
                    return

                workflow_logger(f"✓ Plaso processing completed: {plaso_file}", "success")
                update_run_status(run_id, "running", progress=60)

                # Phase 2.5: Run pinfo to verify Plaso file
                update_job(flow_id, {'phase': 'Verifying Plaso storage'})
                workflow_logger("=== PHASE 2.5: Verifying Plaso Storage (pinfo) ===", "info")
                print(f"\n[WORKFLOW] === PHASE 2.5: Verifying Plaso Storage ===\n", flush=True)

                pinfo_result = run_pinfo(plaso_file, logger=workflow_logger)

                if pinfo_result:
                    event_count = pinfo_result.get('event_count', 0)
                    if event_count == 0:
                        update_job(flow_id, {
                            'status': 'completed',
                            'phase': 'Completed - No events to import',
                            'error': None
                        })
                        workflow_logger("No events matched the selected parser - skipping Timesketch import", "warning")
                        workflow_logger("Tip: Try using 'Auto (All Parsers)' or a broader parser preset", "info")
                        update_run_status(run_id, "completed", progress=100)
                        print(f"[WORKFLOW] Completed - No events to import (parser mismatch)", flush=True)
                        return

                    workflow_logger(f"✓ Plaso file verified: {event_count} events ready for import", "success")
                else:
                    workflow_logger("⚠ Could not verify Plaso file with pinfo, continuing anyway...", "warning")

                update_run_status(run_id, "running", progress=70)

                # Phase 3: Import to Timesketch
                update_job(flow_id, {'phase': 'Importing to Timesketch'})
                workflow_logger("=== PHASE 3: Importing to Timesketch ===", "info")
                print(f"\n[WORKFLOW] === PHASE 3: Importing to Timesketch ===\n", flush=True)

                # Pass logger to Timesketch for detailed logging
                # If sketch_id provided, add to existing sketch; otherwise create new one
                result = import_to_timesketch(plaso_file, sketch_name, timeline_name, timesketch_config, logger=workflow_logger, sketch_id=sketch_id)

                if result:
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

                    # Cleanup plaso file after successful import
                    if plaso_file and os.path.exists(plaso_file):
                        try:
                            os.remove(plaso_file)
                            workflow_logger("Plaso file cleaned up", "info")
                        except Exception as cleanup_err:
                            workflow_logger(f"Warning: Could not clean up plaso file: {cleanup_err}", "warning")

                    update_run_status(run_id, "completed", progress=100)

                    print(f"\n{'='*80}", flush=True)
                    print(f"[WORKFLOW] ✓✓✓ PIPELINE COMPLETED SUCCESSFULLY ✓✓✓", flush=True)
                    print(f"[WORKFLOW] Sketch: {sketch_name} (ID: {result.get('sketch_id')})", flush=True)
                    print(f"[WORKFLOW] Timeline: {timeline_name} (ID: {result.get('timeline_id')})", flush=True)
                    print(f"{'='*80}\n", flush=True)
                else:
                    update_job(flow_id, {
                        'status': 'failed',
                        'phase': 'Timesketch import failed',
                        'error': 'Failed to import to Timesketch'
                    })
                    workflow_logger("Pipeline failed: Timesketch import failed", "error")
                    workflow_logger("Check the detailed logs above for error information", "error")
                    update_run_status(run_id, "failed", progress=0, error="Failed to import to Timesketch")
                    print(f"[WORKFLOW] ✗ Pipeline failed: Timesketch import failed", flush=True)

            except Exception as e:
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

                # Cleanup plaso file on failure too
                if plaso_file and os.path.exists(plaso_file):
                    try:
                        os.remove(plaso_file)
                        print(f"[WORKFLOW] Cleaned up plaso file: {plaso_file}", flush=True)
                    except:
                        pass

        # Start workflow in background thread
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


# =============================================================================
# Timesketch LLM Configuration
# =============================================================================

TIMESKETCH_CONFIG_PATH = '/app/config/timesketch/timesketch.conf'

@timesketch_bp.route('/api/timesketch/config/llm', methods=['GET'])
def get_timesketch_llm_config():
    """Get current Timesketch LLM configuration"""
    try:
        config = {
            'google_ai_key': '',
            'google_ai_model': 'gemini-2.5-flash',
            'ollama_url': '',
            'ollama_model': ''
        }

        # Read config file and extract LLM settings
        try:
            with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
                content = f.read()

            # Parse the LLM_PROVIDER_CONFIGS section
            import re

            # Extract Google AI API key from aistudio section
            match = re.search(r"'aistudio':\s*\{[^}]*'api_key':\s*'([^']*)'", content)
            if match:
                config['google_ai_key'] = match.group(1)

            # Extract Google AI model
            match = re.search(r"'aistudio':\s*\{[^}]*'model':\s*'([^']*)'", content)
            if match:
                config['google_ai_model'] = match.group(1)

            # Extract Ollama URL
            match = re.search(r"'ollama':\s*\{[^}]*'server_url':\s*'([^']*)'", content)
            if match:
                config['ollama_url'] = match.group(1)

            # Extract Ollama model
            match = re.search(r"'ollama':\s*\{[^}]*'model':\s*'([^']*)'", content)
            if match:
                config['ollama_model'] = match.group(1)

        except FileNotFoundError:
            print(f"[TIMESKETCH] Config file not found: {TIMESKETCH_CONFIG_PATH}", flush=True)

        return jsonify(config)

    except Exception as e:
        print(f"[TIMESKETCH] Error reading LLM config: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def _run_timesketch_settings_workflow(run_id, config_data):
    """Background worker for Timesketch settings update workflow"""
    import re

    google_ai_key = config_data.get('google_ai_key', '')
    google_ai_model = config_data.get('google_ai_model', 'gemini-2.5-flash')
    ollama_url = config_data.get('ollama_url', '')
    ollama_model = config_data.get('ollama_model', '')

    try:
        # Phase 1: Read existing config
        update_run_status(run_id, "running", progress=10)
        add_log_to_run(run_id, "Reading existing Timesketch configuration...")

        with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
            content = f.read()

        add_log_to_run(run_id, f"Successfully read config file: {TIMESKETCH_CONFIG_PATH}")

        # Phase 2: Update configuration
        update_run_status(run_id, "running", progress=20)
        add_log_to_run(run_id, "Building new LLM configuration...")

        # Build new LLM_PROVIDER_CONFIGS section
        new_llm_config = f'''LLM_PROVIDER_CONFIGS = {{
    'nl2q': {{
        'vertexai': {{
            'model': 'gemini-2.5-flash',
            'project_id': '',
        }},
    }},
    'llm_summarize': {{
        'aistudio': {{
            'model': '{google_ai_model}',
            'api_key': '{google_ai_key}',
        }},
    }},
    'llm_synthesize': {{
        'aistudio': {{
            'model': '{google_ai_model}',
            'api_key': '{google_ai_key}',
        }},
    }},
    'log_analyzer': {{
        'secgemini_log_analyzer_agent': {{
            'logs_processor_api_url': '',
            'api_key': '',
            'model': 'logs_analysis_agent-1.1',
            'base_url': '',
            'wss_url': '',
            'agents_config': {{}},
        }}
    }},
    'default': {{
        'ollama': {{
            'server_url': '{ollama_url}',
            'model': '{ollama_model}',
        }},
    }}
}}'''

        # Replace existing LLM_PROVIDER_CONFIGS section
        pattern = r"LLM_PROVIDER_CONFIGS\s*=\s*\{[\s\S]*?\n\}"
        if re.search(pattern, content):
            content = re.sub(pattern, new_llm_config, content)
            add_log_to_run(run_id, "Updated existing LLM_PROVIDER_CONFIGS section")
        else:
            content += '\n\n' + new_llm_config
            add_log_to_run(run_id, "Added new LLM_PROVIDER_CONFIGS section")

        # Phase 3: Write config file
        update_run_status(run_id, "running", progress=30)
        add_log_to_run(run_id, "Writing updated configuration to file...")

        with open(TIMESKETCH_CONFIG_PATH, 'w') as f:
            f.write(content)

        add_log_to_run(run_id, "Configuration file saved successfully", "success")

        # Log what was configured
        if google_ai_key:
            add_log_to_run(run_id, f"Configured Google AI Studio with model: {google_ai_model}")
        if ollama_url:
            add_log_to_run(run_id, f"Configured Ollama at {ollama_url} with model: {ollama_model}")

        # Phase 4: Restart containers
        update_run_status(run_id, "running", progress=40)
        containers = ['mssp_timesketch_web', 'mssp_timesketch_worker']

        for i, container in enumerate(containers):
            add_log_to_run(run_id, f"Restarting container: {container}...")

            result = subprocess.run(
                ['docker', 'restart', container],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                add_log_to_run(run_id, f"Failed to restart {container}: {result.stderr}", "error")
                update_run_status(run_id, "failed", error=f"Container restart failed: {container}")
                return

            add_log_to_run(run_id, f"Container {container} restart initiated", "success")
            update_run_status(run_id, "running", progress=50 + (i * 10))

        # Phase 5: Wait for containers to be healthy
        update_run_status(run_id, "running", progress=70)
        add_log_to_run(run_id, "Waiting for Timesketch containers to become healthy...")

        max_wait = 120  # 2 minutes max
        check_interval = 5
        elapsed = 0

        while elapsed < max_wait:
            time.sleep(check_interval)
            elapsed += check_interval

            # Check container health
            all_healthy = True
            for container in containers:
                result = subprocess.run(
                    ['docker', 'inspect', '--format', '{{.State.Health.Status}}', container],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                status = result.stdout.strip()
                if status != 'healthy':
                    # Also check if container is just running (no healthcheck defined)
                    result2 = subprocess.run(
                        ['docker', 'inspect', '--format', '{{.State.Status}}', container],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result2.stdout.strip() != 'running':
                        all_healthy = False
                        break

            progress = 70 + int((elapsed / max_wait) * 25)
            update_run_status(run_id, "running", progress=min(progress, 95))

            if all_healthy:
                # Verify Timesketch is responding
                try:
                    import urllib.request
                    req = urllib.request.urlopen('http://mssp_timesketch_web:5000/', timeout=5)
                    if req.status in [200, 302]:
                        add_log_to_run(run_id, "Timesketch web interface is responding", "success")
                        break
                except:
                    pass

            add_log_to_run(run_id, f"Waiting for containers... ({elapsed}s elapsed)")

        # Final status check - verify containers are actually running
        containers_ok = True
        for container in containers:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container}', '--format', '{{.Status}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            status = result.stdout.strip()
            add_log_to_run(run_id, f"Container {container}: {status}")

            # Check if container is running
            if not status or 'Up' not in status:
                containers_ok = False
                add_log_to_run(run_id, f"Container {container} is not running!", "error")

        # Verify Timesketch web is accessible
        ts_accessible = False
        try:
            import urllib.request
            req = urllib.request.urlopen('http://mssp_timesketch_web:5000/', timeout=10)
            if req.status in [200, 302]:
                ts_accessible = True
                add_log_to_run(run_id, "Timesketch web interface verified accessible", "success")
        except Exception as e:
            add_log_to_run(run_id, f"Timesketch web interface not accessible: {e}", "warning")

        # Determine final status
        if containers_ok and ts_accessible:
            update_run_status(run_id, "completed", progress=100)
            add_log_to_run(run_id, "Timesketch settings update completed successfully", "success")
        elif containers_ok:
            # Containers running but web not accessible yet - might still be starting
            update_run_status(run_id, "completed", progress=100)
            add_log_to_run(run_id, "Settings saved. Containers running but web interface may still be initializing.", "warning")
        else:
            update_run_status(run_id, "failed", error="Containers failed to start properly")
            add_log_to_run(run_id, "Settings workflow failed - containers not running", "error")

    except Exception as e:
        add_log_to_run(run_id, f"Error: {str(e)}", "error")
        update_run_status(run_id, "failed", error=str(e))
        traceback.print_exc()


@timesketch_bp.route('/api/timesketch/config/llm', methods=['PUT'])
def update_timesketch_llm_config():
    """Update Timesketch LLM configuration and restart containers (runs as workflow)"""
    try:
        data = request.get_json()

        # Create workflow run
        run_id = create_automation_run(
            automation_type="settings",
            name="Timesketch LLM Configuration",
            details={
                "google_ai_model": data.get('google_ai_model', 'gemini-2.5-flash'),
                "ollama_url": data.get('ollama_url', ''),
                "ollama_model": data.get('ollama_model', '')
            }
        )

        add_log_to_run(run_id, "Starting Timesketch settings update workflow...")
        add_log_to_run(run_id, f"Workflow ID: {run_id}")

        # Run in background thread
        thread = threading.Thread(
            target=_run_timesketch_settings_workflow,
            args=(run_id, data)
        )
        thread.daemon = True
        thread.start()

        return jsonify({
            "success": True,
            "message": "Settings workflow started",
            "run_id": run_id
        })

    except Exception as e:
        print(f"[TIMESKETCH] Error starting settings workflow: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
