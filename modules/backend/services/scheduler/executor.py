#!/usr/bin/env python3
"""
Scheduler Executor - Blueprint execution functions for scheduled jobs

Contains the callback functions that APScheduler invokes when jobs run.
"""

import re
import threading
from datetime import datetime

from services.file_storage_service import _get_connection as get_db_connection


def _job_case(job_meta):
    """The case a schedule's runs belong to. A run fired by the scheduler has no
    browser request, so without this every scheduled run landed in Default
    (2026-10-21). None -> Default, as before: a schedule from before case_id
    existed, or one whose case was deleted since (said, never filed under a case
    nobody can open)."""
    cid = (job_meta or {}).get("case_id") or None
    if not cid:
        return None
    try:
        from services.fusion import store
        if store.get_case(cid):
            return cid
    except Exception:                                      # noqa: BLE001 -- Default, as before
        pass
    print(f"[SCHEDULER] Job {job_meta.get('id')}: case {cid} no longer exists -- runs go to Default", flush=True)
    return None


def run_scheduled_blueprint(job_id: str):
    """Execute a scheduled blueprint run. This is the main APScheduler callback."""
    from services.agentic import run_agentic_pipeline
    from services.file_storage_service import get_velociraptor_blueprint, get_agentic_blueprint
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
    case_id = _job_case(job_meta)
    client_ids = json.loads(job_meta.get('client_ids', '[]'))
    # Per-type run options (JSON blob): CVE scan_mode/max_wait, Memory
    # include_yara/timeouts/case_name, Collection collection_minutes, Hunt
    # include_labels/per_artifact, AWS regions/scope_mode/…
    try:
        options = json.loads(job_meta.get('options') or '{}') or {}
    except Exception:
        options = {}

    try:
        if blueprint_type == 'agentic':
            # Get blueprint name
            agentic_bp = get_agentic_blueprint(blueprint_id)
            blueprint_name = agentic_bp.get('name', blueprint_id) if agentic_bp else blueprint_id

            # Collection window (minutes) — operator-set per schedule; default 30.
            try:
                collection_minutes = max(1, min(1440, int(options.get('collection_minutes', 30))))
            except Exception:
                collection_minutes = 30

            # Create automation run
            run_id = create_automation_run(
                case_id=case_id,
                automation_type="velociraptor_collection",
                name=f"Scheduled: {job_meta['name']}",
                details={
                    "blueprint_id": blueprint_id,
                    "blueprint": blueprint_name,
                    "client_ids": client_ids,
                    "collection_minutes": collection_minutes,
                    "scheduled_job_id": job_id
                }
            )

            # Run in background thread
            thread = threading.Thread(
                target=run_agentic_pipeline,
                args=(run_id, blueprint_id, client_ids, collection_minutes),
                daemon=True
            )
            thread.start()
            print(f"[SCHEDULER] Started agentic pipeline: run_id={run_id}", flush=True)

        elif blueprint_type == 'timesketch':
            # Timesketch automation - KAPE collection + Plaso + TimeSketch import
            run_timesketch_pipeline(job_meta, client_ids)
            print(f"[SCHEDULER] Started timesketch pipeline for {len(client_ids)} clients", flush=True)

        elif blueprint_type == 'memory':
            # Memory-forensics pipeline — per client. YARA toggle / timeouts /
            # case_name come from the job's options (see run_memory_scheduled).
            run_memory_scheduled(job_meta, client_ids, options)
            print(f"[SCHEDULER] Started memory pipeline for {len(client_ids)} clients", flush=True)

        elif blueprint_type == 'aws':
            # AWS (CloudTrail) — account-based/env-wide (no clients). blueprint +
            # regions/scope_mode from options. Runs in its own thread.
            run_aws_scheduled(job_meta['name'], blueprint_id, options, case_id=case_id)
            print(f"[SCHEDULER] Started AWS scan (env-wide)", flush=True)

        else:
            # Velociraptor Hunt (env-wide) — legacy 'velociraptor' + explicit 'hunt'.
            # include_labels / per_artifact from options.
            run_velociraptor_hunt(job_meta['name'], blueprint_id, client_ids, options, case_id=case_id)
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


def run_velociraptor_hunt(job_name: str, blueprint_id: str, client_ids: list, options: dict = None,
                          case_id: str = None):
    """Execute a Velociraptor hunt from a blueprint.

    options: {include_labels: [str] (target-label scoping — empty = all clients)}.
    """
    from services.file_storage_service import get_velociraptor_blueprint
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    from services.velociraptor_service import setup_velociraptor_connection
    import json

    options = options or {}
    include_labels = options.get('include_labels') or []
    if isinstance(include_labels, str):
        include_labels = [x.strip() for x in include_labels.split(',') if x.strip()]
    # VQL fragment scoping the hunt to specific client labels (mirrors
    # velociraptor_routes._hunt_labels_clause); empty = every enrolled client.
    labels_clause = f"    include_labels={json.dumps(include_labels)},\n" if include_labels else ""

    # Get blueprint
    blueprint = get_velociraptor_blueprint(blueprint_id)
    if not blueprint:
        print(f"[SCHEDULER] Blueprint not found: {blueprint_id}", flush=True)
        return

    # An artifact name goes between backticks in the VQL below: only real artifact
    # names (letters, digits . _ -) are sent, so a ` in an edited blueprint cannot
    # end the name and add VQL.
    artifacts = [a for a in blueprint.get('artifacts', []) if isinstance(a, str) and re.fullmatch(r"[\w.\-]+", a)]
    if len(artifacts) != len(blueprint.get('artifacts', [])):
        print(f"[SCHEDULER] Skipped invalid artifact name(s) in blueprint {blueprint_id}", flush=True)
    settings = blueprint.get('settings', {})
    expire_minutes = settings.get('hunt_expiry', 120)
    timeout_seconds = settings.get('timeout', 3600)
    cpu_limit = settings.get('cpu_limit', 50)
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
        case_id=case_id,
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
        # The job name is operator text: it goes in as a query PARAMETER (env), never
        # spliced into the VQL -- a ' in the name ended the string and anything after
        # it ran as server-side VQL. Numbers are forced to numbers for the same reason.
        description = f"Scheduled: {job_name} ({len(artifacts)} artifacts)"
        query = f"""
LET collection = hunt(
    description=HuntDescription,
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
{labels_clause}    expires=now() + {int(expire_seconds)},
    timeout={int(timeout_seconds)},
    max_rows={int(flow_max_rows)},
    max_bytes={int(flow_max_bytes)},
    cpu_limit={int(cpu_limit)}
)
SELECT HuntId FROM collection
"""

        add_log_to_run(run_id, f"Creating hunt with {len(artifacts)} artifacts")

        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            env=[api_pb2.VQLEnv(key="HuntDescription", value=description)],
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


def run_aws_scheduled(job_name: str, blueprint_id: str, options: dict = None, case_id: str = None):
    """Scheduled AWS (CloudTrail) scan — account-based/env-wide (no Velociraptor
    clients). Resolves the AWS blueprint, loads AWS config, and runs
    run_aws_pipeline in a daemon thread. Mirrors routes/aws_routes.start_scan.

    options: {scope_mode ('account_wide'|'targeted'), regions [str],
    max_events_per_region, target_principals, min_severity, cloudtrail_mode}."""
    import threading
    from services.workflow_service import create_automation_run, update_run_status
    from services.aws.pipeline import run_aws_pipeline, get_aws_blueprints

    options = options or {}
    scope_mode = (options.get('scope_mode') or 'account_wide').lower()
    if scope_mode not in ('targeted', 'account_wide'):
        scope_mode = 'account_wide'
    regions = options.get('regions') or []
    if isinstance(regions, str):
        regions = [r.strip() for r in regions.split(',') if r.strip()]
    try:
        mepr = int(options.get('max_events_per_region') or 0) or None
        if mepr is not None and mepr < 1:
            mepr = None
    except (TypeError, ValueError):
        mepr = None

    blueprint = next((b for b in get_aws_blueprints() if b.get('id') == blueprint_id), None)

    run_id = create_automation_run(
        case_id=case_id,
        automation_type='aws_scan',
        name=f"Scheduled: {job_name}",
        details={"source": "scheduler", "blueprint": blueprint_id,
                 "scope_mode": scope_mode, "regions": regions},
    )

    def _worker():
        try:
            update_run_status(run_id, 'running', progress=2)
            if not blueprint:
                update_run_status(run_id, 'failed', error=f"AWS blueprint not found: {blueprint_id}")
                return
            try:
                from routes.config_routes import _load_cloud_config
                aws_config = (_load_cloud_config() or {}).get('aws', {}) or {'region': 'us-east-1'}
            except Exception:
                aws_config = {'region': 'us-east-1'}
            pipe_options = {
                'scope_mode': scope_mode,
                'target_principals': options.get('target_principals') or [],
                'regions': regions or None,
                'max_events_per_region': mepr,
                'min_severity': options.get('min_severity', 'medium'),
                'cloudtrail_mode': options.get('cloudtrail_mode'),
                'time_filter': None,
            }
            run_aws_pipeline(run_id, aws_config, blueprint, pipe_options)
        except Exception as e:
            print(f"[SCHEDULER] AWS scheduled run error: {e}", flush=True)
            try:
                update_run_status(run_id, 'failed', error=str(e))
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()
    return run_id


# Scheduled Timesketch job id -> run_id still in progress. A fleet run takes
# days to weeks; a daily schedule must not stack a second pipeline on it.
_TIMESKETCH_ACTIVE = {}
_TIMESKETCH_ACTIVE_LOCK = threading.Lock()


def run_timesketch_pipeline(job_meta: dict, client_ids: list):
    """Execute a scheduled Timesketch run: KAPE -> Plaso -> Timesketch import
    for every client, as ONE workflow run through the same bounded pipeline as
    POST /api/timesketch/start-multi (kape_service.run_kape_timesketch_pipeline).

    This used to take each client through KAPE, wait, export and Plaso before
    starting the next, inside the APScheduler thread: an offline host held the
    queue for the full 10,000 s monitor timeout (300 offline hosts ~ 840 h), and
    its Plaso ran outside the start-multi limit. Clients not seen for
    TIMESKETCH_OFFLINE_SKIP_HOURS are skipped and named in the run log.
    Returns once the pipeline thread is started.
    """
    from services.kape_service import run_kape_timesketch_pipeline
    from services.velociraptor_service import get_clients_from_snapshot
    from services.workflow_service import (create_automation_run, add_log_to_run, update_run_status,
                                           register_cancel_event)
    from services.file_storage_service import get_timesketch_blueprint
    from config import TIMESKETCH_OFFLINE_SKIP_HOURS
    import time

    job_id = job_meta.get('id')
    job_name = job_meta.get('name', 'Scheduled Timesketch')
    with _TIMESKETCH_ACTIVE_LOCK:
        active = _TIMESKETCH_ACTIVE.get(job_id) if job_id else None
    if active:
        add_log_to_run(active, f"Scheduled firing at {datetime.utcnow().isoformat()}Z skipped: "
                               f"this run is still in progress", "warning")
        print(f"[SCHEDULER] Timesketch job {job_id} still running as {active}; skipping this firing", flush=True)
        return

    blueprint_id = job_meta.get('blueprint_id', '')
    sketch_name = job_meta.get('description', '') or f"Scheduled_{datetime.utcnow().strftime('%Y%m%d')}"

    # Load blueprint settings
    blueprint = get_timesketch_blueprint(blueprint_id) if blueprint_id else None
    settings = blueprint.get('settings', {}) if blueprint else {}
    blueprint_name = blueprint.get('name', blueprint_id) if blueprint else blueprint_id
    timeout_seconds = settings.get('collection_timeout', 10000)

    # KAPE artifact env params and flow-level limits. Defaults match
    # default_blueprints.yaml so even legacy DB rows that predate these keys
    # still get the bumped ceilings.
    kape_args = dict(
        kape_target=settings.get('kape_target', '_KapeTriage'),
        timeout_seconds=timeout_seconds,
        cpu_limit=settings.get('cpu_limit', 50),
        max_rows=settings.get('flow_max_rows', 10000000),
        max_logs=settings.get('flow_max_logs', 1000000),
        max_upload_mb=settings.get('flow_max_upload_mb', 51200),
        max_file_size=settings.get('kape_max_file_size', 10737418240),
        max_hash_size=settings.get('kape_max_hash_size', 0),
        collection_policy=settings.get('kape_collection_policy', 'ExcludeSigned'),
    )
    ts_settings = {
        'sketch_name': sketch_name,
        'plaso_parser': settings.get('plaso_parser'),
        'plaso_workers': settings.get('plaso_workers', 2),
        'plaso_hasher': settings.get('plaso_hasher'),
        'plaso_hasher_size': settings.get('plaso_hasher_size', 100),
        # Propagate the per-blueprint TS-processing wait timeout so
        # big collections aren't capped by the old hardcoded ~3 h.
        'timesketch_processing_timeout': settings.get('timesketch_processing_timeout', 259200),
    }

    # One query for every client's hostname and last check-in. last_seen_at 0
    # means unknown (API down -> snapshot fallback), which is not "offline".
    known = {c.get('client_id'): c for c in (get_clients_from_snapshot(include_offline=True) or [])}
    now_us = time.time() * 1e6
    clients, skipped = [], []
    for cid in client_ids:
        info = known.get(cid) or {}
        name = info.get('hostname') or cid
        seen = info.get('last_seen_at') or 0
        if TIMESKETCH_OFFLINE_SKIP_HOURS and seen and now_us - seen > TIMESKETCH_OFFLINE_SKIP_HOURS * 3600e6:
            skipped.append(f"{name} ({(now_us - seen) / 3600e6:.0f} h)")
        else:
            clients.append({'client_id': cid, 'client_name': name})

    label = (f"{len(clients)} clients ({', '.join(c['client_name'] for c in clients)})"
             if 0 < len(clients) <= 3 else f"{len(clients)} clients")
    run_id = create_automation_run(
        case_id=_job_case(job_meta),
        automation_type="timesketch",
        name=f"Scheduled: {job_name} - {label}",
        details={
            "multi_client": True,
            "client_count": len(clients),
            "clients": clients,
            "skipped_offline": len(skipped),
            "kape_target": kape_args['kape_target'],
            "sketch_name": sketch_name,
            "scheduled_job_id": job_id,
            "blueprint_id": blueprint_id,
            "blueprint": blueprint_name,
        }
    )
    add_log_to_run(run_id, f"Starting scheduled Timesketch pipeline for {len(clients)} clients")
    add_log_to_run(run_id, f"KAPE Target: {kape_args['kape_target']}")
    if skipped:
        shown = ', '.join(skipped[:20]) + (f", … (+{len(skipped) - 20} more)" if len(skipped) > 20 else "")
        add_log_to_run(run_id, f"Skipped {len(skipped)} client(s) not seen for over {TIMESKETCH_OFFLINE_SKIP_HOURS} h "
                               f"(TIMESKETCH_OFFLINE_SKIP_HOURS): {shown}", "warning")
    if not clients:
        update_run_status(run_id, "failed", progress=0, error="No client has been seen recently")
        return

    # Register a cancel event so the user can Stop a scheduled run from the
    # dashboard; the pipeline wires it into Velociraptor CancelFlow.
    cancel_event = register_cancel_event(run_id)
    update_run_status(run_id, "running", progress=2)
    if job_id:
        with _TIMESKETCH_ACTIVE_LOCK:
            _TIMESKETCH_ACTIVE[job_id] = run_id

    def _worker():
        try:
            run_kape_timesketch_pipeline(run_id, clients, kape_args, ts_settings, timeout_seconds, cancel_event)
        finally:
            if job_id:
                with _TIMESKETCH_ACTIVE_LOCK:
                    _TIMESKETCH_ACTIVE.pop(job_id, None)

    threading.Thread(target=_worker, daemon=True).start()


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


def run_memory_scheduled(job_meta: dict, client_ids: list, options: dict = None) -> None:
    """Dispatch a memory-forensics run from a scheduled blueprint.

    Memory acquisition is per-host (4-16 GB transient .raw, three
    concurrent copies during pipeline), and the hosts go ONE AFTER ANOTHER
    (operator decision 2026-10-14). One "memory_batch" run walks the list in a
    single thread; each host gets its own memory run when its turn comes, so
    no host row sits idle for hours (the orphan sweep fails a run silent for
    10 h). Stopping the batch stops it after the current host.

    options: {include_yara (bool), case_name, acquire_flow_timeout_s,
    plugin_timeout_s, yarascan_timeout_s} — the same per-run controls the
    Memory module page exposes.
    """
    import threading

    from services.memory.pipeline import run_memory_pipeline
    from services.storage.blueprint_store import get_memory_blueprint
    from services.workflow_service import create_automation_run, update_run_status, add_log_to_run

    if not client_ids:
        print("[SCHEDULER] memory: no client_ids — skipping", flush=True)
        return

    options = options or {}
    blueprint_id = job_meta.get("blueprint_id") or ""
    blueprint = get_memory_blueprint(blueprint_id) if blueprint_id else None
    settings = (blueprint.get("settings") if blueprint else {}) or {}
    # Mode derived exactly like the Memory module page (memory.js): empty plugin
    # set -> 'yara'; otherwise 'layered' if include-YARA is on, else 'plugin'.
    plugin_set = settings.get("plugin_set") or settings.get("plugins") or []
    include_yara = bool(options.get("include_yara", True))
    if not plugin_set:
        mode = "yara"
    else:
        mode = "layered" if include_yara else "plugin"
    case_name = options.get("case_name") or job_meta.get("name") or "Memory (scheduled)"
    # Optional per-run timeout overrides (seconds).
    timeouts = {}
    for k in ("acquire_flow_timeout_s", "plugin_timeout_s", "yarascan_timeout_s"):
        try:
            v = int(options.get(k) or 0)
            if v > 0:
                timeouts[k] = v
        except (TypeError, ValueError):
            pass

    from services.workflow_service import register_cancel_event, unregister_cancel

    case_id = _job_case(job_meta)
    batch_id = create_automation_run(
        case_id=case_id,
        automation_type="memory_batch",
        name=f"Memory ({mode}) — scheduled: {len(client_ids)} host(s), one after another",
        details={
            "trigger": "scheduled",
            "scheduled_job_id": job_meta.get("id"),
            "mode": mode,
            "client_ids": list(client_ids),
            "blueprint_id": blueprint_id or None,
            "case_name": case_name,
        },
    )
    stop = register_cancel_event(batch_id)
    update_run_status(batch_id, "running", progress=1)

    def _one_after_another():
        total, done = len(client_ids), 0
        try:
            for n, cid in enumerate(client_ids, 1):
                if stop.is_set():
                    add_log_to_run(batch_id, f"stopped — {total - n + 1} host(s) not started", "warning")
                    update_run_status(batch_id, "cancelled", progress=(n - 1) * 100 // total)
                    return
                run_id = create_automation_run(
                    case_id=case_id,
                    automation_type="memory",
                    name=f"Memory ({mode}) — scheduled: {cid}",
                    details={
                        "trigger": "scheduled",
                        "scheduled_job_id": job_meta.get("id"),
                        "batch_run_id": batch_id,
                        "mode": mode,
                        "client_id": cid,
                        "blueprint_id": blueprint_id or None,
                        "case_name": case_name,
                    },
                )
                add_log_to_run(batch_id, f"host {n}/{total}: {cid} → run {run_id}")
                add_log_to_run(run_id, f"scheduler: memory dispatch client={cid} mode={mode} "
                                       f"(host {n}/{total} of batch {batch_id})", "info")
                update_run_status(run_id, "running", progress=1)
                run_memory_pipeline(run_id=run_id, client_id=cid, mode=mode, case_name=case_name,
                                    blueprint=blueprint, timeouts=timeouts or None)
                done += 1
                if not stop.is_set():   # a Stop mid-host must not be flipped back to running
                    update_run_status(batch_id, "running", progress=max(1, done * 100 // total - 1))
            add_log_to_run(batch_id, f"all {total} host(s) done", "success")
            update_run_status(batch_id, "completed", progress=100)
        except Exception as e:
            add_log_to_run(batch_id, f"batch stopped by an error after {done}/{total}: {e}", "error")
            update_run_status(batch_id, "failed", error=str(e))
        finally:
            unregister_cancel(batch_id)

    threading.Thread(target=_one_after_another, daemon=True).start()
