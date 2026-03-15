#!/usr/bin/env python3
"""
Velociraptor Routes - Velociraptor endpoints
"""

from flask import Blueprint, jsonify, request
import time
import traceback
import sys
import json

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
from services.velociraptor_init_service import initialize_velociraptor_artifacts

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
