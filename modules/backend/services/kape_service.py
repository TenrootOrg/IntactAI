#!/usr/bin/env python3
"""
KAPE Service - KAPE collection functions
"""

import json
import time
import grpc
import traceback
import sys
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection, cancel_flow
from services.workflow_service import get_cancel_event, register_cleanup
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
