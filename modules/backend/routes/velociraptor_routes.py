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

        # If a blueprint was provided, load its settings so this manual-run
        # path uses the same ceilings as the scheduled path. Without this,
        # a manual "Run TimeSketch now" click would still hit Velociraptor's
        # 1 GiB hardcoded upload cap.
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
                bp_settings = bp.get('settings', {}) or {}
                kape_max_file_size     = bp_settings.get('kape_max_file_size', kape_max_file_size)
                kape_max_hash_size     = bp_settings.get('kape_max_hash_size', kape_max_hash_size)
                kape_collection_policy = bp_settings.get('kape_collection_policy', kape_collection_policy)
                flow_max_rows          = bp_settings.get('flow_max_rows', flow_max_rows)
                flow_max_logs          = bp_settings.get('flow_max_logs', flow_max_logs)
                flow_max_upload_mb     = bp_settings.get('flow_max_upload_mb', flow_max_upload_mb)

        print(f"\n{'='*80}", flush=True)
        print(f"[API] Timesketch collection request received", flush=True)
        print(f"[API] Client ID: {client_id}", flush=True)
        print(f"[API] Client Name: {client_name}", flush=True)
        print(f"[API] KAPE Target: {kape_target}", flush=True)
        print(f"[API] Timeout: {timeout_seconds}s, CPU Limit: {cpu_limit}%", flush=True)
        print(f"{'='*80}\n", flush=True)

        # Run KAPE collection via gRPC (resource caps + artifact env from blueprint)
        flow_id = run_kape_collection_grpc(
            client_id, kape_target, timeout_seconds, cpu_limit,
            max_rows=flow_max_rows,
            max_logs=flow_max_logs,
            max_upload_mb=flow_max_upload_mb,
            max_file_size=kape_max_file_size,
            max_hash_size=kape_max_hash_size,
            collection_policy=kape_collection_policy,
        )

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

        # Register cancel event so Stop can cancel the velociraptor
        # flow + abort the downstream /api/timesketch/import monitor.
        # The downstream import endpoint already has its own cancel
        # registration; this one covers the gap between KAPE dispatch
        # and the operator calling import.
        from services.workflow_service import register_cancel_event, register_cleanup
        register_cancel_event(run_id)
        # Cleanup callback cancels the Velociraptor flow when Stop is
        # clicked — so the endpoint stops collecting + uploading too.
        def _cancel_velo_flow(cid=client_id, fid=flow_id):
            try:
                import subprocess as _sp
                _sp.run(
                    f"docker exec intact_velociraptor /velociraptor/velociraptor "
                    f"--api_config /velociraptor/api.config.yaml --nobanner query "
                    f"\"SELECT cancel_flow(client_id='{cid}', flow_id='{fid}') FROM scope()\"",
                    shell=True, capture_output=True, timeout=10
                )
            except Exception:
                pass
        register_cleanup(run_id, _cancel_velo_flow)

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


def _create_single_velo_hunt(stub, artifacts, hunt_desc, expire_seconds, timeout_seconds,
                             cpu_limit, flow_max_rows, flow_max_bytes, log_fn):
    """Build + send the VQL `hunt()` call against the Velociraptor gRPC
    stub for a given artifact list, return `(hunt_id, error_str)`.

    Used by both the bulk path (artifacts = full list) and the
    per-artifact path (artifacts = a one-element list). Keeps the gRPC
    plumbing in one place."""
    artifacts_list = json.dumps(artifacts)
    spec_parts = ", ".join([f"`{a}`=dict()" for a in artifacts])
    # max_logs is rejected by hunt() (collect_client-only) so we omit.
    query = f"""
LET collection = hunt(
    description={json.dumps(hunt_desc)},
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
    request_obj = api_pb2.VQLCollectorArgs(
        max_wait=30,
        max_row=100,
        Query=[api_pb2.VQLRequest(VQL=query)],
    )
    hunt_id = None
    response_errors = []
    response_count = 0
    for response in stub.Query(request_obj, timeout=120):
        response_count += 1
        if response.log:
            log_fn(f"Velociraptor log: {response.log}",
                   "warning" if "error" in response.log.lower() else "info")
        if response.Response:
            try:
                resp_data = json.loads(response.Response)
                if resp_data:
                    hunt_id = (resp_data[0] or {}).get('HuntId') or hunt_id
            except Exception as parse_err:
                response_errors.append(f"parse: {parse_err}")
    if hunt_id:
        return hunt_id, None
    reasons = []
    if response_count == 0:
        reasons.append("no responses from Velociraptor")
    if response_errors:
        reasons.append("; ".join(response_errors))
    if not reasons:
        reasons.append("no HuntId in any response")
    return None, " | ".join(reasons)


@velociraptor_bp.route('/api/velociraptor/bestpractice', methods=['POST'])
def run_bestpractice_hunts():
    """Run multiple artifacts as hunts (BestPractice workflow).

    Two dispatch modes controlled by `per_artifact`:
      - false (default): one bulk hunt with every artifact in one
        Velociraptor hunt object + one workflow row.
      - true: one hunt PER artifact — N Velociraptor hunts + N workflow
        rows so the operator can monitor / cancel / re-run each
        artifact independently.
    """
    try:
        data = request.get_json()
        artifacts = data.get('artifacts', [])
        blueprint_name = data.get('blueprint_name', 'Custom')
        expire_minutes = data.get('expire_minutes', 120)
        timeout_seconds = data.get('timeout_seconds', 10000)
        cpu_limit = data.get('cpu_limit', 80)
        per_artifact = bool(data.get('per_artifact', False))
        # Optional blueprint_id lets us pull resource caps from the stored
        # blueprint settings (instead of inheriting old hardcoded defaults).
        # When absent, the request body can override directly via flow_max_*
        # keys, otherwise we apply the new conservative defaults.
        blueprint_id = data.get('blueprint_id')
        flow_max_rows      = 10000000
        flow_max_logs      = 1000000
        flow_max_upload_mb = 51200
        if blueprint_id:
            from services.file_storage_service import get_velociraptor_blueprint
            bp = get_velociraptor_blueprint(blueprint_id)
            if bp:
                bps = bp.get('settings', {}) or {}
                flow_max_rows      = bps.get('flow_max_rows', flow_max_rows)
                flow_max_logs      = bps.get('flow_max_logs', flow_max_logs)
                flow_max_upload_mb = bps.get('flow_max_upload_mb', flow_max_upload_mb)
        # Caller-supplied values take final priority
        flow_max_rows      = data.get('flow_max_rows', flow_max_rows)
        flow_max_logs      = data.get('flow_max_logs', flow_max_logs)
        flow_max_upload_mb = data.get('flow_max_upload_mb', flow_max_upload_mb)
        flow_max_bytes     = int(flow_max_upload_mb) * 1024 * 1024

        if not artifacts:
            return jsonify({"error": "artifacts list is required"}), 400

        print(f"\n{'='*80}", flush=True)
        print(f"[HUNT] Starting Velociraptor hunt: {blueprint_name}", flush=True)
        print(f"[HUNT] Artifacts: {len(artifacts)} artifacts (per_artifact={per_artifact})", flush=True)
        print(f"[HUNT] Expire: {expire_minutes}m, Timeout: {timeout_seconds}s, CPU: {cpu_limit}%", flush=True)
        print(f"{'='*80}\n", flush=True)

        # ───────────────────────────────────────────────────────────────
        # PER-ARTIFACT BRANCH — one workflow row + one Velociraptor hunt
        # per artifact. Branches off the bulk path entirely so the rest
        # of this function is the unchanged bulk behaviour.
        # ───────────────────────────────────────────────────────────────
        if per_artifact:
            expire_seconds = expire_minutes * 60
            channel = setup_velociraptor_connection()
            if not channel:
                return jsonify({"error": "Failed to connect to Velociraptor"}), 500
            stub = api_pb2_grpc.APIStub(channel)
            results = []
            run_ids = []
            # Register cancel for each row up front so the operator can
            # Stop the per-artifact dispatch loop mid-flight (e.g. when
            # they picked 30 artifacts and want to cancel after 3 hunts).
            from services.workflow_service import register_cancel_event, is_cancelled
            try:
                for a in artifacts:
                    rid = create_automation_run(
                        automation_type="velociraptor_hunt",
                        name=f"{blueprint_name} · {a}",
                        details={
                            "blueprint": blueprint_name,
                            "artifact_count": 1,
                            "artifact": a,
                            "expire_minutes": expire_minutes,
                            "timeout_seconds": timeout_seconds,
                            "cpu_limit": cpu_limit,
                            "per_artifact": True,
                        },
                    )
                    run_ids.append(rid)
                    register_cancel_event(rid)
                    # Honour Stop on THIS row before dispatching the
                    # next hunt. We can't kill an already-dispatched
                    # Velociraptor hunt from here (those run on the
                    # server side), but we can stop creating more.
                    if is_cancelled(rid):
                        update_run_status(rid, "cancelled")
                        results.append({"artifact": a, "run_id": rid, "hunt_id": None, "status": "cancelled"})
                        continue
                    add_log_to_run(rid, f"Starting per-artifact hunt for `{a}`")
                    add_log_to_run(rid, f"Settings: Expire={expire_minutes}m, Timeout={timeout_seconds}s, CPU={cpu_limit}%")
                    hunt_desc = f"{blueprint_name} · {a}"
                    hunt_id, err = _create_single_velo_hunt(
                        stub, [a], hunt_desc, expire_seconds, timeout_seconds,
                        cpu_limit, flow_max_rows, flow_max_bytes,
                        log_fn=lambda m, lvl='info', _rid=rid: add_log_to_run(_rid, m, lvl),
                    )
                    if hunt_id:
                        add_log_to_run(rid, f"Hunt created: {hunt_id}")
                        update_run_status(rid, "completed", progress=100)
                        results.append({"artifact": a, "run_id": rid, "hunt_id": hunt_id, "status": "success"})
                    else:
                        # Don't log error if this row got cancelled mid-create
                        if is_cancelled(rid):
                            results.append({"artifact": a, "run_id": rid, "hunt_id": None, "status": "cancelled"})
                            continue
                        add_log_to_run(rid, f"Failed: {err}", "error")
                        update_run_status(rid, "failed", progress=0)
                        results.append({"artifact": a, "run_id": rid, "hunt_id": None, "status": "failed", "error": err})
            finally:
                channel.close()
            success_n = sum(1 for r in results if r['status'] == 'success')
            print(f"[HUNT] Per-artifact dispatch: {success_n}/{len(artifacts)} hunts created", flush=True)
            return jsonify({
                "message": f"Dispatched {success_n}/{len(artifacts)} per-artifact hunts",
                "run_ids": run_ids,
                "results": results,
            })

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

        # hunt() rejects max_logs (collect_client-only arg), so we omit it.
        # flow_max_logs is still honored on the TimeSketch / collect_client path.
        _ = flow_max_logs  # intentionally unused here
        # Create single bulk hunt with all artifacts
        query = f"""
LET collection = hunt(
    description='{blueprint_name} ({len(artifacts)} artifacts)',
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
