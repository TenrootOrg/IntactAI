#!/usr/bin/env python3
"""
KAPE Service - KAPE collection functions
"""

import json
import os
import shutil
import threading
import time
import grpc
import traceback
import sys
from datetime import datetime
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from config import (PLASO_OUTPUT_DIR, PLASO_MAX_CONCURRENT, TIMESKETCH_MAX_COLLECTORS,
                    TIMESKETCH_EXPORT_MIN_FREE_GB)
from services.velociraptor_service import (setup_velociraptor_connection, cancel_flow,
                                           export_flow_to_zip, cleanup_flow_export)
from services.workflow_service import (get_cancel_event, register_cleanup, add_log_to_run,
                                       update_run_status, add_job, update_job, unregister_cancel)
from services.vql_safety import is_valid_client_id, is_valid_flow_id

def run_kape_collection_grpc(
    client_id,
    kape_target="KapeTriage",
    timeout_seconds=10000,
    cpu_limit=50,
    # Flow-level resource limits (passed to collect_client). Defaults match
    # the historical Velociraptor server defaults so callers that don't pass
    # these see identical pre-patch behavior.
    max_rows=1000000,
    max_logs=100000,
    max_upload_mb=1024,
    # KAPE artifact env parameters (passed to collect_client(env=dict(...))).
    # Defaults intentionally permissive on size + endpoint-friendly on hashing
    # for the "fast triage" workflow that's our default.
    max_file_size=10737418240,         # 10 GiB
    max_hash_size=0,                   # 0 = hashing disabled on endpoint
    collection_policy="ExcludeSigned",
):
    """Run KAPE collection on a client using gRPC API

    Args:
        client_id: Velociraptor client ID
        kape_target: KAPE target (e.g., '_KapeTriage', '_SANS_Triage', '_J')
        timeout_seconds: Collection timeout in seconds (default 10000 = ~2.8 hours)
        cpu_limit: CPU limit percentage on endpoint (default 50%)
        max_rows: Max rows the flow may produce (Velociraptor default: 1,000,000)
        max_logs: Max log lines the flow may produce (Velociraptor default: 100,000)
        max_upload_mb: Max megabytes the flow may upload (Velociraptor default: 1024)
        max_file_size: Per-file upload size cap in bytes for the kape artifact
        max_hash_size: Per-file hash size cap in bytes (0 disables hashing)
        collection_policy: ExcludeSigned | ExcludeMicrosoft | Default (filename
            filtering policy applied by the kape collection artifact itself)
    """
    sys.stdout.flush()
    print("=" * 80, flush=True)
    print(f"[KAPE] Starting KAPE collection", flush=True)
    print(f"[KAPE] Client ID: {client_id}", flush=True)
    print(f"[KAPE] Target: {kape_target}", flush=True)
    print(f"[KAPE] Timeout: {timeout_seconds}s, CPU Limit: {cpu_limit}%", flush=True)
    print(f"[KAPE] Flow caps: max_rows={max_rows}, max_logs={max_logs}, "
          f"max_upload_mb={max_upload_mb}", flush=True)
    print(f"[KAPE] Artifact env: MaxFileSize={max_file_size}, "
          f"MaxHashSize={max_hash_size}, CollectionPolicy={collection_policy}",
          flush=True)
    print("=" * 80, flush=True)

    # Defense-in-depth: client_id is interpolated directly into a VQL string
    # literal below with no escaping.
    if not is_valid_client_id(client_id):
        print(f"[KAPE] ✗ Rejecting invalid client_id: {client_id!r}", flush=True)
        return None

    try:
        # Setup gRPC connection
        print("[KAPE] Step 1/4: Setting up gRPC connection...", flush=True)
        channel = setup_velociraptor_connection()
        if not channel:
            print("[KAPE] ✗ Failed to setup gRPC connection", flush=True)
            return None

        stub = api_pb2_grpc.APIStub(channel)
        print("[KAPE] ✓ gRPC connection established", flush=True)

        # Build VQL query to collect KAPE artifacts
        print("[KAPE] Step 2/4: Building VQL query...", flush=True)
        artifact_name = 'Windows.Triage.Targets'
        timeout_ms = timeout_seconds * 1000  # Convert to milliseconds
        max_upload_bytes = int(max_upload_mb) * 1024 * 1024

        # Use env parameter with JSON-encoded arrays (same as Velociraptor UI)
        # Targets must be JSON string: "[\"AnyDesk\"]"
        import json
        targets_json = json.dumps([kape_target])

        # Note: this Velociraptor version's `collect_client()` rejects
        # `max_logs` ("Unexpected arg max_logs"). The blueprint still carries
        # `flow_max_logs` for forward-compat, but we don't pass it into the VQL.
        _ = max_logs  # intentionally unused
        vql_query = f"""
LET collection <= collect_client(
    client_id='{client_id}',
    artifacts='{artifact_name}',
    timeout={timeout_ms},
    cpu_limit={cpu_limit},
    max_rows={max_rows},
    max_bytes={max_upload_bytes},
    env=dict(
        Targets='''{targets_json}''',
        MaxFileSize='{max_file_size}',
        MaxHashSize='{max_hash_size}',
        CollectionPolicy='{collection_policy}'
    )
)
SELECT * FROM collection
"""

        print(f"[KAPE] VQL Query:", flush=True)
        print(f"{vql_query.strip()}", flush=True)

        # Execute query
        print("[KAPE] Step 3/4: Executing KAPE collection...", flush=True)
        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=100,
            Query=[api_pb2.VQLRequest(
                Name=artifact_name,
                VQL=vql_query
            )]
        )

        flow_id = None
        for response in stub.Query(request, timeout=30):
            if response.log:
                print(f"[KAPE] Server log: {response.log}", flush=True)

            if response.Response:
                print(f"[KAPE] Response received", flush=True)
                try:
                    response_data = json.loads(response.Response)
                    if isinstance(response_data, list) and len(response_data) > 0:
                        # Try both formats: collection.flow_id or direct flow_id
                        flow_id = response_data[0].get("flow_id")
                        if not flow_id:
                            # Try nested Flow format
                            flow_obj = response_data[0].get("Flow")
                            if flow_obj:
                                flow_id = flow_obj.get("flow_id")

                        if flow_id:
                            print(f"[KAPE] ✓ Collection started!", flush=True)
                            print(f"[KAPE] Flow ID: {flow_id}", flush=True)
                            break
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    print(f"[KAPE] ⚠ Could not parse flow_id: {e}", flush=True)
                    print(f"[KAPE] Response data: {response.Response}", flush=True)

        channel.close()

        if flow_id:
            print("[KAPE] Step 4/4: Collection initiated successfully", flush=True)
            print("=" * 80, flush=True)
            return flow_id
        else:
            print("[KAPE] ✗ No flow_id returned from server", flush=True)
            print("=" * 80, flush=True)
            return None

    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            print(f"[KAPE] ✗ gRPC call timed out", flush=True)
        else:
            print(f"[KAPE] ✗ gRPC error: {e.details()}", flush=True)
        print("=" * 80, flush=True)
        return None

    except Exception as e:
        print(f"[KAPE] ✗ Exception: {e}", flush=True)
        traceback.print_exc()
        print("=" * 80, flush=True)
        return None


def monitor_flow_completion(client_id, flow_id, timeout_seconds=10000, logger=None, run_id=None):
    """Monitor flow until completion with progress updates

    Args:
        client_id: Velociraptor client ID
        flow_id: Velociraptor flow ID
        timeout_seconds: Maximum time to wait for completion (default 10000 = ~2.8 hours)
        logger: Optional callback function(message, level) to log progress
        run_id: Optional workflow run_id. When provided, the polling loop
            respects the workflow Stop button: clicking Stop sends a
            CancelFlow to the Velociraptor server (so the actual KAPE
            collection terminates on the endpoint, not just our poll)
            and returns within ~5s instead of polling for hours.
    """

    # Defense-in-depth: both values are interpolated directly into a VQL
    # string literal in the polling query below with no escaping.
    if not is_valid_client_id(client_id) or not is_valid_flow_id(flow_id):
        print(f"[FLOW] ✗ Rejecting invalid client_id/flow_id: {client_id!r}/{flow_id!r}", flush=True)
        return None

    def log(message, level="info"):
        """Log to both stdout and optional callback"""
        print(f"[FLOW] {message}", flush=True)
        if logger:
            try:
                logger(f"[FLOW] {message}", level)
            except Exception as e:
                print(f"[FLOW] Logger error: {e}", flush=True)

    sys.stdout.flush()
    log("=" * 60)
    log("Monitoring flow completion")
    log(f"Client ID: {client_id}")
    log(f"Flow ID: {flow_id}")
    log(f"Timeout: {timeout_seconds}s ({timeout_seconds//60} minutes)")
    log("=" * 60)

    cancel_event = get_cancel_event(run_id) if run_id else None

    # Register a cleanup callback that sends CancelFlow to the Velociraptor
    # server. This fires the moment the user clicks Stop, even if our poll
    # is mid-sleep — the endpoint stops running KAPE within seconds rather
    # than waiting for the next poll iteration.
    if run_id:
        register_cleanup(
            run_id,
            lambda: cancel_flow(client_id, flow_id, logger=logger),
        )

    channel = None
    try:
        # Setup gRPC connection
        log("Setting up gRPC connection...")
        channel = setup_velociraptor_connection()
        if not channel:
            log("✗ Failed to setup gRPC connection", "error")
            log("Check that Velociraptor container is running and API is configured", "error")
            return None

        stub = api_pb2_grpc.APIStub(channel)
        log("✓ gRPC connection established")

        start_time = time.time()
        check_count = 0
        last_rows = 0
        # A flow on an endpoint that is not connected reads exactly like one
        # that is working: "State: RUNNING - Rows: 0", for the whole timeout.
        # 2026-10-05: a memory capture sat like that for 13 minutes (90 allowed)
        # on a PC last seen 45 minutes before; nothing said why. Ask when the
        # client last checked in and say so. Never aborts -- it may come back.
        _OFFLINE_AFTER_S, _REPEAT_S = 300, 600
        offline_checked_at, offline_said_at = 0.0, 0.0

        def client_silence_s():
            try:
                q = api_pb2.VQLCollectorArgs(max_wait=10, max_row=1, Query=[api_pb2.VQLRequest(
                    VQL=f"SELECT last_seen_at FROM clients(client_id='{client_id}')")])
                for resp in stub.Query(q, timeout=15):
                    if resp.Response:
                        rows = json.loads(resp.Response)
                        if rows and rows[0].get("last_seen_at"):
                            return time.time() - int(rows[0]["last_seen_at"]) / 1e6
            except Exception:
                return None
            return None

        while True:
            check_count += 1
            elapsed = int(time.time() - start_time)

            # Stop button: cleanup callback already sent CancelFlow to the
            # Velociraptor server. Exit our local poll so the workflow ends
            # promptly without waiting up to 30s for the next sleep cycle.
            if cancel_event is not None and cancel_event.is_set():
                log("Stop requested by user — abandoning flow monitor", "warning")
                return "CANCELLED"

            # Query flow state — use the LIGHT flows() projection, NOT
            # get_flow(...) SELECT *. The full flow object bloats during a
            # multi-GB upload (e.g. a memory image) and the streaming Query can
            # hang past its deadline, FREEZING the monitor so the run sticks at
            # "running" forever even though the acquisition finished. A small
            # projection returns instantly.
            vql_query = (f"SELECT state, total_collected_rows, status "
                         f"FROM flows(client_id='{client_id}', flow_id='{flow_id}')")

            request = api_pb2.VQLCollectorArgs(
                max_wait=10, max_row=10,
                Query=[api_pb2.VQLRequest(VQL=vql_query)]
            )

            state = None
            total_rows = 0
            error_msg = None

            try:
                for response in stub.Query(request, timeout=15):
                    if response.Response:
                        rows = json.loads(response.Response)
                        if rows and len(rows) > 0:
                            state = rows[0].get('state', 'UNKNOWN')
                            total_rows = rows[0].get('total_collected_rows', 0)
                            error_msg = rows[0].get('status', '')
                            break

            except grpc.RpcError as e:
                # A broken/stuck channel must not freeze the monitor — rebuild it
                # so the next poll can succeed instead of blocking indefinitely.
                log(f"⚠ Query error: {e.code()} - "
                    f"{e.details() if hasattr(e, 'details') else ''}; rebuilding gRPC channel",
                    "warning")
                try:
                    channel.close()
                except Exception:
                    pass
                channel = setup_velociraptor_connection()
                if channel:
                    stub = api_pb2_grpc.APIStub(channel)
            except json.JSONDecodeError as e:
                # Previously uncaught here — fell through to the outer except,
                # which ended the whole monitor loop (and leaked the channel)
                # on what is usually just one malformed/partial poll response.
                # Treat like a transient miss: keep last known state and retry
                # on the next poll instead of aborting the run.
                log(f"⚠ Could not parse flow state response: {e}", "warning")

            if total_rows == 0 and time.time() - offline_checked_at >= 60:
                offline_checked_at = time.time()
                quiet = client_silence_s()
                if quiet is not None and quiet >= _OFFLINE_AFTER_S \
                        and time.time() - offline_said_at >= _REPEAT_S:
                    offline_said_at = time.time()
                    log(f"⚠ The endpoint has not checked in for {int(quiet // 60)} min — it "
                        f"looks offline (powered off, asleep or no network). The collection "
                        f"starts when it reconnects; stop the run if it is not coming back.",
                        "warning")

            # Log progress every 5 checks or when rows change significantly
            if check_count % 5 == 1 or total_rows != last_rows:
                log(f"Check #{check_count} - Elapsed: {elapsed//60}m {elapsed%60}s - State: {state} - Rows: {total_rows}")
                last_rows = total_rows

            # Check state
            if state == "FINISHED":
                log(f"✓ Flow completed successfully!", "success")
                log(f"Total time: {elapsed}s ({elapsed//60}m {elapsed%60}s)", "success")
                log(f"Total rows collected: {total_rows}", "success")
                return "FINISHED"

            elif state in ("ERROR", "FAILED", "CANCELLED"):
                log(f"✗ Flow failed/cancelled with state: {state}", "error")
                if error_msg:
                    log(f"Error details: {error_msg}", "error")
                return state  # Return actual state so caller knows what happened

            # Check timeout
            if time.time() - start_time > timeout_seconds:
                log(f"✗ Timeout reached after {timeout_seconds}s", "error")
                log(f"Last known state: {state}, Rows collected: {total_rows}", "error")
                return None

            # Wait before next check (progressively longer waits)
            if elapsed < 60:
                wait_time = 5
            elif elapsed < 300:
                wait_time = 15
            else:
                wait_time = 30

            # cancel_event.wait returns True immediately on Stop — we don't
            # burn the full sleep window after a click.
            if cancel_event is not None:
                if cancel_event.wait(wait_time):
                    log("Stop requested by user — abandoning flow monitor", "warning")
                    return "CANCELLED"
            else:
                time.sleep(wait_time)

    except Exception as e:
        error_detail = traceback.format_exc()
        log(f"✗ Exception: {e}", "error")
        log(f"Stack trace: {error_detail}", "error")
        traceback.print_exc()
        return None
    finally:
        # Every return path above used to close the channel individually
        # (and a couple didn't — e.g. an uncaught JSONDecodeError falling
        # through to this outer except used to skip closing entirely).
        # Close exactly once here regardless of which path was taken.
        if channel:
            try:
                channel.close()
            except Exception:
                pass


def run_kape_timesketch_pipeline(run_id, clients, kape_args, ts_settings, monitor_timeout, cancel_event):
    """KAPE on many clients -> ZIP export -> Plaso -> Timesketch, under ONE run.

    Shared by POST /api/timesketch/start-multi and scheduled Timesketch jobs.
    Blocks the calling (background) thread until every client is done, sets
    the run's final status and unregisters its cancel event.

    clients: [{'client_id', 'client_name'}], mutated with flow_id/progress.
    kape_args: run_kape_collection_grpc keyword arguments.
    ts_settings: process_kape_upload settings minus client_name/timeline_name.

    Bounded so a 1,000-client run neither floods Velociraptor nor fills the
    disk. It used to start one monitor thread per client (~200 VQL queries/s)
    and export every finished collection at once into PLASO_OUTPUT_DIR (on the
    root filesystem, ~2 GB each) while one consumer ran Plaso AND waited for
    Timesketch indexing, one host at a time.
      * KAPE is still started on every client up front, so the endpoints
        collect in parallel as before;
      * at most TIMESKETCH_MAX_COLLECTORS flows are monitored/exported at once;
      * a flow is exported only when Plaso can take it: at most
        PLASO_MAX_CONCURRENT + 1 of this run's ZIPs exist at a time, and only
        with TIMESKETCH_EXPORT_MIN_FREE_GB free;
      * Plaso itself is limited process-wide inside process_kape_upload;
      * the Timesketch indexing wait runs in the client's own thread holding
        no slot, so the next Plaso job starts as soon as one finishes.
    """
    from concurrent.futures import ThreadPoolExecutor
    from services.kape_upload_service import process_kape_upload

    def log(msg, level='info'):
        add_log_to_run(run_id, msg, level)

    live = []
    lock = threading.Lock()
    state = {'kape_done': 0, 'plaso_done': 0, 'total': 0}
    staged = threading.BoundedSemaphore(PLASO_MAX_CONCURRENT + 1)
    plaso_threads = []
    finished = threading.Event()

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
        # KAPE phase weighted 40%, Plaso phase weighted 60%.
        with lock:
            kape_units = sum(min(1.0, c.get('kape_frac', 0)) for c in live)
            plaso_units = sum(min(1.0, c.get('plaso_frac', 0)) for c in live)
            total = max(state['total'], 1)
        pct = int(5 + ((kape_units * 0.4 + plaso_units * 0.6) / total) * 95)
        update_run_status(run_id, "running", progress=min(pct, 99))

    def _heartbeat():
        # Ends on `finished`, not on "every client counted done": a client
        # whose KAPE failed never reached the Plaso count, so the old loop
        # never ended.
        while not finished.wait(10):
            now = time.time()
            changed = False
            with lock:
                for c in live:
                    for key, start, deadline in (('kape_frac', 'kape_started_at', KAPE_SOFT_DEADLINE),
                                                 ('plaso_frac', 'plaso_started_at', PLASO_SOFT_DEADLINE)):
                        if start in c and c.get(key, 0) < 1.0:
                            est = min(0.85, (now - c[start]) / deadline)
                            if est > c.get(key, 0):
                                c[key] = est
                                changed = True
            if changed:
                _bump_progress()

    def _acquire(sem):
        """Block on sem, but give up when the run is stopped."""
        while not sem.acquire(timeout=5):
            if cancel_event.is_set():
                return False
        if cancel_event.is_set():
            sem.release()
            return False
        return True

    def _room_to_export(name):
        """PLASO_OUTPUT_DIR is on the root filesystem; a full disk takes the
        whole appliance down, not just this run. Wait up to 30 min for this
        or another run's Plaso stage to free space, then skip the host."""
        need = TIMESKETCH_EXPORT_MIN_FREE_GB * 1024 ** 3
        deadline = time.time() + 1800
        warned = False
        while True:
            try:
                os.makedirs(PLASO_OUTPUT_DIR, exist_ok=True)
                free = shutil.disk_usage(PLASO_OUTPUT_DIR).free
            except OSError:
                return True     # cannot measure: let the export fail on its own
            if free >= need:
                return True
            if not warned:
                log(f"[ZIP/{name}] Only {free / 1024 ** 3:.1f} GB free in {PLASO_OUTPUT_DIR} "
                    f"(need {TIMESKETCH_EXPORT_MIN_FREE_GB} GB, TIMESKETCH_EXPORT_MIN_FREE_GB) "
                    f"— waiting up to 30 min for space", "warning")
                warned = True
            if time.time() >= deadline or cancel_event.wait(60):
                return False

    def _dispatch():
        for c in clients:
            if cancel_event.is_set():
                return
            flow_id = run_kape_collection_grpc(c['client_id'], **kape_args)
            if not flow_id:
                log(f"✗ Failed to start KAPE on {c['client_name']} ({c['client_id']})", "error")
                c['flow_id'] = None
                continue
            c['flow_id'] = flow_id
            c['kape_started_at'] = time.time()
            log(f"[KAPE] Started on {c['client_name']} → flow {flow_id}")
            # Register in jobs dict so the flow is visible/cancellable elsewhere,
            # but the canonical state lives on the parent run_id.
            add_job(flow_id, {
                "flow_id": flow_id,
                "client_id": c['client_id'],
                "client_name": c['client_name'],
                "artifact_id": "kape",
                "artifact_name": "KAPE Collection",
                "kape_target": kape_args.get('kape_target'),
                "timeout_seconds": kape_args.get('timeout_seconds'),
                "cpu_limit": kape_args.get('cpu_limit'),
                "status": "collecting",
                "started_at": int(time.time()),
                "phase": "KAPE Collection (multi-client)",
                "run_id": run_id,
                "parent_multi": True,
            })
            with lock:
                live.append(c)
                state['total'] = len(live)

    def _process(c, zip_path):
        """Plaso + Timesketch for one client, in its own thread."""
        name = c['client_name']
        released = []

        def plaso_done():
            if not released:
                released.append(True)
                staged.release()
        try:
            with lock:
                c['plaso_started_at'] = time.time()
            update_job(c['flow_id'], {'phase': 'Processing with Plaso + Timesketch import'})
            log(f"[Plaso/{name}] === Starting Plaso + Timesketch upload ===")
            settings = dict(ts_settings, client_name=name,
                            timeline_name=f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            result = process_kape_upload(
                zip_path=zip_path,
                original_filename=os.path.basename(zip_path),
                settings=settings,
                run_id=run_id,
                cleanup_zip=True,
                # This function owns the parent run's progress + status.
                # Otherwise each per-client call would overwrite the bar with
                # its own 5→70→100% and briefly mark the whole run "completed"
                # after the first.
                suppress_status_writes=True,
                on_plaso_done=plaso_done,
            )
            cleanup_flow_export(c['client_id'], c['flow_id'], logger=log)
            status = (result or {}).get('status')
            if status == 'completed':
                log(f"[Plaso/{name}] ✓ Imported (sketch {result.get('sketch_id')}, timeline {result.get('timeline_id')})", "success")
                update_job(c['flow_id'], {'status': 'completed', 'phase': 'Completed', 'sketch_id': result.get('sketch_id'), 'timeline_id': result.get('timeline_id')})
            elif status == 'no_events':
                log(f"[Plaso/{name}] Completed — no events to import", "warning")
                update_job(c['flow_id'], {'status': 'completed', 'phase': 'Completed (no events)'})
            elif status != 'cancelled':
                err = (result or {}).get('error', 'unknown error')
                log(f"[Plaso/{name}] ✗ Failed: {err}", "error")
                update_job(c['flow_id'], {'status': 'failed', 'phase': 'Plaso/Timesketch failed', 'error': err})
        except Exception as e:
            log(f"[Plaso/{name}] Exception: {e}", "error")
            traceback.print_exc()
        finally:
            plaso_done()
            with lock:
                state['plaso_done'] += 1
                c['plaso_frac'] = 1.0
            _bump_progress()

    def _collect(c):
        """Monitor KAPE on one client, then export its ZIP once Plaso can take it."""
        name = c['client_name']
        handed_off = False
        try:
            if cancel_event.is_set():
                return
            log(f"[KAPE/{name}] Monitoring flow {c['flow_id']}...")
            flow_state = monitor_flow_completion(
                c['client_id'], c['flow_id'],
                timeout_seconds=monitor_timeout,
                logger=lambda m, l='info': log(f"[KAPE/{name}] {m}", l),
                run_id=run_id,
            )
            if cancel_event.is_set():
                return
            if flow_state != "FINISHED":
                log(f"[KAPE/{name}] ✗ Flow did not finish (state={flow_state})", "error")
                update_job(c['flow_id'], {'status': 'failed', 'phase': 'KAPE failed', 'error': f'state={flow_state}'})
                return

            log(f"[KAPE/{name}] ✓ Collection complete — exporting when Plaso is ready for it", "success")
            if not _acquire(staged):
                return
            try:
                if not _room_to_export(name):
                    if not cancel_event.is_set():
                        log(f"[ZIP/{name}] ✗ Skipped: not enough free space in {PLASO_OUTPUT_DIR} to export", "error")
                        update_job(c['flow_id'], {'status': 'failed', 'phase': 'Not enough disk space to export'})
                    return
                zip_path = os.path.join(PLASO_OUTPUT_DIR, f"flow_{c['flow_id']}_{run_id}.zip")
                if not export_flow_to_zip(c['client_id'], c['flow_id'], zip_path,
                                          logger=lambda m, l='info': log(f"[ZIP/{name}] {m}", l)):
                    log(f"[ZIP/{name}] ✗ Export failed", "error")
                    update_job(c['flow_id'], {'status': 'failed', 'phase': 'ZIP export failed'})
                    return
                t = threading.Thread(target=_process, args=(c, zip_path), daemon=True)
                with lock:
                    plaso_threads.append(t)
                t.start()
                handed_off = True
            finally:
                if not handed_off:
                    staged.release()
        except Exception as e:
            log(f"[KAPE/{name}] Exception: {e}", "error")
            traceback.print_exc()
        finally:
            with lock:
                state['kape_done'] += 1
                c['kape_frac'] = 1.0
                if not handed_off:
                    c['plaso_frac'] = 1.0   # nothing more will happen for this host
            _bump_progress()

    try:
        _dispatch()
        if cancel_event.is_set():
            log("Pipeline cancelled by user", "warning")
            update_run_status(run_id, "cancelled", progress=0)
            return
        if not live:
            log("✗ No KAPE collections could be started", "error")
            update_run_status(run_id, "failed", progress=0, error="No KAPE collections could be started")
            return
        log(f"KAPE started on {len(live)}/{len(clients)} clients; monitoring {TIMESKETCH_MAX_COLLECTORS} at a time "
            f"(TIMESKETCH_MAX_COLLECTORS), Plaso {PLASO_MAX_CONCURRENT} at a time (PLASO_MAX_CONCURRENT)")

        threading.Thread(target=_heartbeat, daemon=True).start()
        with ThreadPoolExecutor(max_workers=TIMESKETCH_MAX_COLLECTORS) as pool:
            list(pool.map(_collect, live))
        # ponytail: indexing waits are one sleeping thread each, unbounded;
        # they only pile up if Timesketch indexes slower than Plaso produces.
        for t in list(plaso_threads):
            t.join()

        if cancel_event.is_set():
            log("Pipeline cancelled by user", "warning")
            update_run_status(run_id, "cancelled", progress=state['plaso_done'] * 100 // max(state['total'], 1))
            return
        log(f"✓✓✓ Multi-client pipeline complete: KAPE {state['kape_done']}/{state['total']}, "
            f"Plaso {state['plaso_done']}/{state['total']}", "success")
        update_run_status(run_id, "completed", progress=100)
    except Exception as e:
        log(f"Orchestrator exception: {e}", "error")
        traceback.print_exc()
        update_run_status(run_id, "failed", progress=0, error=str(e))
    finally:
        finished.set()
        unregister_cancel(run_id)
