#!/usr/bin/env python3
"""
Velociraptor Routes - Velociraptor endpoints
"""

from flask import Blueprint, jsonify, request, send_file
import time
import traceback
import sys
import json
import os
import threading

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services import (
    run_kape_collection_grpc,
    add_job,
    create_automation_run,
    add_log_to_run,
    update_run_status
)
from services.velociraptor_service import setup_velociraptor_connection, get_artifact_definitions
from services.offline_collector import (
    get_all_configs,
    get_config,
    save_config,
    delete_config,
    generate_collector,
    get_collector_file,
    import_results,
    init_offline_collector_index
)
from services.file_storage_service import get_agentic_blueprint, get_velociraptor_blueprint

velociraptor_bp = Blueprint('velociraptor', __name__)

@velociraptor_bp.route('/api/velociraptor/timesketch', methods=['POST'])
def run_timesketch_collection():
    """Run KAPE collection on a specific client for TimeSketch import using gRPC"""
    sys.stdout.flush()

    try:
        data = request.get_json()
        client_id = data.get('client_id')
        client_name = data.get('client_name', 'Unknown')  # Get client name (hostname)
        kape_target = data.get('kape_target', '_KapeTriage')  # Default to _KapeTriage
        timeout_seconds = data.get('timeout_seconds', 10000)  # Default ~2.8 hours
        cpu_limit = data.get('cpu_limit', 80)  # Default 80%
        blueprint_id = data.get('blueprint_id')
        blueprint_name = data.get('blueprint', 'Unknown')

        if not client_id:
            return jsonify({"error": "client_id is required"}), 400

        print(f"\n{'='*80}", flush=True)
        print(f"[API] Timesketch collection request received", flush=True)
        print(f"[API] Client ID: {client_id}", flush=True)
        print(f"[API] Client Name: {client_name}", flush=True)
        print(f"[API] KAPE Target: {kape_target}", flush=True)
        print(f"[API] Timeout: {timeout_seconds}s, CPU Limit: {cpu_limit}%", flush=True)
        print(f"{'='*80}\n", flush=True)

        # Run KAPE collection via gRPC
        flow_id = run_kape_collection_grpc(client_id, kape_target, timeout_seconds, cpu_limit)

        if not flow_id:
            print(f"[API] ✗ Failed to start KAPE collection", flush=True)
            return jsonify({"error": "Failed to start KAPE collection via gRPC"}), 500

        # Create workflow run immediately with client name
        run_id = create_automation_run(
            automation_type="timesketch",
            name=f"TimeSketch Automation - {client_name}",
            details={
                "flow_id": flow_id,
                "client_id": client_id,
                "client_name": client_name,
                "kape_target": kape_target,
                "timeout_seconds": timeout_seconds,
                "cpu_limit": cpu_limit,
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_name
            }
        )
        add_log_to_run(run_id, f"Starting TimeSketch automation for {client_name}", "info")
        add_log_to_run(run_id, f"KAPE Target: {kape_target}", "info")
        add_log_to_run(run_id, f"Collection timeout: {timeout_seconds}s, CPU limit: {cpu_limit}%", "info")
        update_run_status(run_id, "running", progress=5)

        # Track the job with run_id
        add_job(flow_id, {
            "flow_id": flow_id,
            "client_id": client_id,
            "client_name": client_name,
            "artifact_id": "kape",
            "artifact_name": "KAPE Collection",
            "kape_target": kape_target,
            "timeout_seconds": timeout_seconds,
            "cpu_limit": cpu_limit,
            "status": "collecting",
            "started_at": int(time.time()),
            "phase": "KAPE Collection",
            "run_id": run_id  # Store run_id for later use
        })

        print(f"[API] ✓ KAPE collection started successfully", flush=True)
        print(f"[API] Flow ID: {flow_id}", flush=True)
        print(f"[API] Workflow Run ID: {run_id}\n", flush=True)

        return jsonify({
            "flow_id": flow_id,
            "client_id": client_id,
            "client_name": client_name,
            "artifact": "KAPE Collection",
            "kape_target": kape_target,
            "status": "collecting",
            "phase": "KAPE Collection",
            "run_id": run_id,
            "message": "KAPE collection started. Call /api/timesketch/import with this flow_id to start the full pipeline."
        })

    except Exception as e:
        print(f"[API] ✗ Error starting KAPE collection: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/bestpractice', methods=['POST'])
def run_bestpractice_hunts():
    """Run multiple artifacts as hunts (BestPractice workflow)"""
    try:
        data = request.get_json()
        artifacts = data.get('artifacts', [])
        blueprint_name = data.get('blueprint_name', 'Custom')
        expire_minutes = data.get('expire_minutes', 120)
        timeout_seconds = data.get('timeout_seconds', 10000)
        cpu_limit = data.get('cpu_limit', 80)

        if not artifacts:
            return jsonify({"error": "artifacts list is required"}), 400

        print(f"\n{'='*80}", flush=True)
        print(f"[HUNT] Starting Velociraptor hunt: {blueprint_name}", flush=True)
        print(f"[HUNT] Artifacts: {len(artifacts)} artifacts", flush=True)
        print(f"[HUNT] Expire: {expire_minutes}m, Timeout: {timeout_seconds}s, CPU: {cpu_limit}%", flush=True)
        print(f"{'='*80}\n", flush=True)

        # Create workflow run entry
        run_id = create_automation_run(
            automation_type="velociraptor_hunt",
            name=f"{blueprint_name} ({len(artifacts)} artifacts)",
            details={"blueprint": blueprint_name, "artifact_count": len(artifacts), "expire_minutes": expire_minutes, "timeout_seconds": timeout_seconds, "cpu_limit": cpu_limit}
        )
        add_log_to_run(run_id, f"Starting hunt with {len(artifacts)} artifacts")
        add_log_to_run(run_id, f"Settings: Expire={expire_minutes}m, Timeout={timeout_seconds}s, CPU={cpu_limit}%")

        channel = setup_velociraptor_connection()
        if not channel:
            add_log_to_run(run_id, "ERROR: Failed to connect to Velociraptor", "error")
            update_run_status(run_id, "failed", progress=0)
            return jsonify({"error": "Failed to connect to Velociraptor", "run_id": run_id}), 500

        stub = api_pb2_grpc.APIStub(channel)

        # Convert expire_minutes to seconds for VQL
        expire_seconds = expire_minutes * 60

        # Build artifact list and spec for bulk hunt
        artifacts_list = json.dumps(artifacts)
        spec_parts = ", ".join([f'`{a}`=dict()' for a in artifacts])

        # Create single bulk hunt with all artifacts
        query = f"""
LET collection = hunt(
    description='{blueprint_name} ({len(artifacts)} artifacts)',
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    cpu_limit={cpu_limit}
)
SELECT HuntId FROM collection
"""

        add_log_to_run(run_id, f"Creating bulk hunt with {len(artifacts)} artifacts")
        print(f"[HUNT] Creating bulk hunt with {len(artifacts)} artifacts", flush=True)
        print(f"[HUNT] VQL Query:\n{query}", flush=True)

        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )

        hunt_id = None
        response_errors = []
        response_count = 0
        for response in stub.Query(request_obj, timeout=120):
            response_count += 1

            if response.log:
                log_msg = f"Velociraptor log: {response.log}"
                print(f"[HUNT] {log_msg}", flush=True)
                add_log_to_run(run_id, log_msg, "warning" if "error" in response.log.lower() else "info")

            if response.Response:
                print(f"[HUNT] Raw response: {response.Response[:500]}", flush=True)
                try:
                    resp_data = json.loads(response.Response)
                    if resp_data and len(resp_data) > 0:
                        hunt_id = resp_data[0].get('HuntId')
                        if hunt_id:
                            add_log_to_run(run_id, f"Hunt created: {hunt_id}", "info")
                except Exception as parse_err:
                    error_msg = f"Failed to parse response: {str(parse_err)}"
                    print(f"[HUNT] {error_msg}", flush=True)
                    add_log_to_run(run_id, error_msg, "error")
                    response_errors.append(error_msg)

        channel.close()

        results = []
        if hunt_id:
            print(f"[HUNT] Bulk hunt created: {hunt_id} ({len(artifacts)} artifacts)", flush=True)
            add_log_to_run(run_id, f"Bulk hunt created: {hunt_id} with {len(artifacts)} artifacts")
            update_run_status(run_id, "completed", progress=100)
            results = [{"artifact": "all", "hunt_id": hunt_id, "status": "success"}]
        else:
            failure_reasons = []
            if response_count == 0:
                failure_reasons.append("No responses received from Velociraptor")
            if response_errors:
                failure_reasons.append(f"Parse errors: {'; '.join(response_errors)}")
            if not failure_reasons:
                failure_reasons.append("Velociraptor returned responses but no HuntId was found")

            error_detail = " | ".join(failure_reasons)
            print(f"[HUNT] Failed to create bulk hunt: {error_detail}", flush=True)
            add_log_to_run(run_id, f"Failed: {error_detail}", "error")
            update_run_status(run_id, "failed", progress=0)
            results = [{"artifact": "all", "hunt_id": None, "status": "failed", "error": error_detail}]

        success_count = 1 if hunt_id else 0
        print(f"\n[HUNT] {'Hunt created' if hunt_id else 'Failed'}: {hunt_id or 'N/A'}\n", flush=True)

        return jsonify({
            "message": f"Created bulk hunt with {len(artifacts)} artifacts" if hunt_id else "Failed to create hunt",
            "run_id": run_id,
            "hunt_id": hunt_id,
            "results": results
        })

    except Exception as e:
        error_msg = f"Critical error in hunt workflow: {str(e)}"
        print(f"[HUNT] ✗ {error_msg}", flush=True)
        traceback.print_exc()

        # Try to log error to workflow if run_id exists
        try:
            if 'run_id' in locals():
                add_log_to_run(run_id, f"✗ {error_msg}", "error")
                add_log_to_run(run_id, f"Traceback: {traceback.format_exc()}", "error")
                update_run_status(run_id, "failed", progress=0)
        except:
            pass

        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/hunts/status', methods=['GET'])
def get_hunts_status():
    """Get status of recent hunts"""
    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return jsonify({"error": "Failed to connect to Velociraptor"}), 500

        stub = api_pb2_grpc.APIStub(channel)

        # Get recent hunts
        query = "SELECT hunt_id, description, state, create_time, start_time FROM hunts() ORDER BY create_time DESC LIMIT 10"

        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )

        hunts = []
        for response in stub.Query(request_obj, timeout=30):
            if response.Response:
                try:
                    resp_data = json.loads(response.Response)
                    if resp_data:
                        hunts.extend(resp_data)
                except:
                    pass

        channel.close()

        return jsonify({"hunts": hunts})

    except Exception as e:
        print(f"[HUNTS] ✗ Error getting hunt status: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Artifact Definitions
# ============================================================================

# Cache for artifact definitions (refreshed every 5 minutes)
_artifact_cache = {"data": None, "timestamp": 0}
_ARTIFACT_CACHE_TTL = 300  # 5 minutes


@velociraptor_bp.route('/api/velociraptor/artifacts', methods=['GET'])
def get_artifacts():
    """Get all available artifact definitions from Velociraptor.

    Returns cached data if available and fresh (< 5 min old).
    Use ?refresh=true to force refresh.
    """
    import time

    force_refresh = request.args.get('refresh', '').lower() == 'true'
    current_time = time.time()

    # Return cached data if fresh
    if not force_refresh and _artifact_cache["data"] and (current_time - _artifact_cache["timestamp"]) < _ARTIFACT_CACHE_TTL:
        return jsonify({
            "artifacts": _artifact_cache["data"],
            "cached": True,
            "count": len(_artifact_cache["data"])
        })

    # Fetch fresh data
    artifacts = get_artifact_definitions()

    if artifacts is None:
        # Return cached data if available, even if stale
        if _artifact_cache["data"]:
            return jsonify({
                "artifacts": _artifact_cache["data"],
                "cached": True,
                "stale": True,
                "count": len(_artifact_cache["data"]),
                "error": "Could not refresh - using stale cache"
            })
        return jsonify({"error": "Failed to connect to Velociraptor"}), 500

    # Update cache
    _artifact_cache["data"] = artifacts
    _artifact_cache["timestamp"] = current_time

    return jsonify({
        "artifacts": artifacts,
        "cached": False,
        "count": len(artifacts)
    })


# ============================================================================
# Offline Collector Routes
# ============================================================================

@velociraptor_bp.route('/api/velociraptor/offline/configs', methods=['GET'])
def list_offline_configs():
    """Get all offline collector configurations"""
    try:
        configs = get_all_configs()
        return jsonify({"configs": configs})
    except Exception as e:
        print(f"[OFFLINE] Error listing configs: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/configs', methods=['POST'])
def create_offline_config():
    """Create a new offline collector configuration"""
    try:
        data = request.get_json()

        if not data.get('config_name'):
            return jsonify({"error": "config_name is required"}), 400
        if not data.get('artifacts'):
            return jsonify({"error": "artifacts list is required"}), 400

        result = save_config(data)

        if result.get('success'):
            return jsonify(result), 201
        else:
            return jsonify(result), 500
    except Exception as e:
        print(f"[OFFLINE] Error creating config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['GET'])
def get_offline_config(config_id):
    """Get a specific configuration"""
    try:
        config = get_config(config_id)
        if config:
            return jsonify(config)
        return jsonify({"error": "Configuration not found"}), 404
    except Exception as e:
        print(f"[OFFLINE] Error getting config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['PUT'])
def update_offline_config(config_id):
    """Update an existing configuration"""
    try:
        data = request.get_json()

        # Check if config exists
        existing = get_config(config_id)
        if not existing:
            return jsonify({"error": "Configuration not found"}), 404

        # Merge existing with new data
        existing.update(data)
        result = save_config(existing, config_id)

        if result.get('success'):
            return jsonify(result)
        else:
            return jsonify(result), 500
    except Exception as e:
        print(f"[OFFLINE] Error updating config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['DELETE'])
def delete_offline_config(config_id):
    """Delete a configuration"""
    try:
        # Don't allow deleting templates
        config = get_config(config_id)
        if config and config.get('is_template'):
            return jsonify({"error": "Cannot delete default templates"}), 400

        result = delete_config(config_id)
        return jsonify(result)
    except Exception as e:
        print(f"[OFFLINE] Error deleting config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/generate', methods=['POST'])
def generate_offline_collector():
    """Generate an offline collector binary with workflow logging"""
    try:
        data = request.get_json()
        config_id = data.get('config_id')
        os_type = data.get('os', 'windows')

        if not config_id:
            return jsonify({"error": "config_id is required"}), 400

        if os_type not in ['windows', 'linux', 'darwin']:
            return jsonify({"error": "os must be windows, linux, or darwin"}), 400

        # Get config name for workflow
        config = get_config(config_id)
        config_name = config.get('config_name', config_id) if config else config_id

        # Look up blueprint display name from blueprints tables
        blueprint = get_agentic_blueprint(config_id) or get_velociraptor_blueprint(config_id)
        blueprint_display_name = blueprint.get('name', config_name) if blueprint else config_name

        # Create workflow run for tracking
        run_id = create_automation_run(
            automation_type="velociraptor_offline_collector",
            name=f"Generate Collector: {blueprint_display_name} ({os_type})",
            details={"config_id": config_id, "os": os_type, "config_name": config_name, "blueprint": blueprint_display_name, "blueprint_id": config_id}
        )

        add_log_to_run(run_id, f"Starting offline collector generation", "info")
        add_log_to_run(run_id, f"Configuration: {config_name}", "info")
        add_log_to_run(run_id, f"Target OS: {os_type}", "info")
        update_run_status(run_id, "running", progress=10)

        print(f"[OFFLINE] Generate request: config={config_id}, os={os_type}, run_id={run_id}", flush=True)

        # Run generation in background thread
        def do_generate():
            try:
                add_log_to_run(run_id, "Connecting to Velociraptor...", "info")
                update_run_status(run_id, "running", progress=20)

                result = generate_collector(config_id, os_type)

                if result.get('success'):
                    file_size = result.get('file_size', 0)
                    file_name = result.get('file_name', 'collector')
                    file_id = result.get('file_id', '')

                    add_log_to_run(run_id, f"Collector generated successfully", "success")
                    add_log_to_run(run_id, f"File: {file_name}", "info")
                    add_log_to_run(run_id, f"Size: {file_size / (1024*1024):.2f} MB", "info")
                    add_log_to_run(run_id, f"Download URL: /api/velociraptor/offline/download/{file_id}", "info")

                    if result.get('note'):
                        add_log_to_run(run_id, result['note'], "info")

                    # Store file_id in details for download button
                    update_run_status(run_id, "completed", progress=100, details={"file_id": file_id})
                else:
                    error = result.get('error', 'Unknown error')
                    add_log_to_run(run_id, f"Generation failed: {error}", "error")
                    update_run_status(run_id, "failed", progress=0, error=error)

            except Exception as e:
                error_msg = str(e)
                print(f"[OFFLINE] Background generation error: {error_msg}", flush=True)
                traceback.print_exc()
                add_log_to_run(run_id, f"Generation failed: {error_msg}", "error")
                update_run_status(run_id, "failed", progress=0, error=error_msg)

        thread = threading.Thread(target=do_generate, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Generation started for {config_name} ({os_type})"
        })

    except Exception as e:
        print(f"[OFFLINE] Error generating collector: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/download/<file_id>', methods=['GET'])
def download_offline_collector(file_id):
    """Download a generated collector file"""
    try:
        file_path = get_collector_file(file_id)

        if not file_path or not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        filename = os.path.basename(file_path)

        # Determine mimetype
        if filename.endswith('.exe'):
            mimetype = 'application/x-msdownload'
        elif filename.endswith('.ps1'):
            mimetype = 'text/plain'
        elif filename.endswith('.sh'):
            mimetype = 'text/x-sh'
        else:
            mimetype = 'application/octet-stream'

        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"[OFFLINE] Error downloading file: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_bp.route('/api/velociraptor/offline/import', methods=['POST'])
def import_offline_results():
    """Import offline collection results from ZIP file"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.endswith('.zip'):
            return jsonify({"error": "File must be a ZIP archive"}), 400

        # Check file size (limit to 500MB)
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)

        if file_size > 500 * 1024 * 1024:
            return jsonify({"error": "File too large (max 500MB)"}), 413

        # Save uploaded file temporarily
        import tempfile
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)

        print(f"[OFFLINE] Importing: {file.filename} ({file_size} bytes)", flush=True)

        result = import_results(temp_path, file.filename)

        return jsonify(result)
    except Exception as e:
        print(f"[OFFLINE] Error importing results: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


