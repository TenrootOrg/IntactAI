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

from services.velociraptor_service import setup_velociraptor_connection

def run_kape_collection_grpc(client_id, kape_target="KapeTriage", timeout_seconds=10000, cpu_limit=80):
    """Run KAPE collection on a client using gRPC API

    Args:
        client_id: Velociraptor client ID
        kape_target: KAPE target (e.g., '_KapeTriage', '_SANS_Triage', '_J')
        timeout_seconds: Collection timeout in seconds (default 10000 = ~2.8 hours)
        cpu_limit: CPU limit percentage on endpoint (default 80%)
    """
    sys.stdout.flush()
    print("=" * 80, flush=True)
    print(f"[KAPE] Starting KAPE collection", flush=True)
    print(f"[KAPE] Client ID: {client_id}", flush=True)
    print(f"[KAPE] Target: {kape_target}", flush=True)
    print(f"[KAPE] Timeout: {timeout_seconds}s, CPU Limit: {cpu_limit}%", flush=True)
    print("=" * 80, flush=True)

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

        # Use env parameter with JSON-encoded arrays (same as Velociraptor UI)
        # Targets must be JSON string: "[\"AnyDesk\"]"
        import json
        targets_json = json.dumps([kape_target])

        vql_query = f"""
LET collection <= collect_client(
    client_id='{client_id}',
    artifacts='{artifact_name}',
    timeout={timeout_ms},
    cpu_limit={cpu_limit},
    env=dict(Targets='''{targets_json}''')
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


def monitor_flow_completion(client_id, flow_id, timeout_seconds=10000, logger=None):
    """Monitor flow until completion with progress updates

    Args:
        client_id: Velociraptor client ID
        flow_id: Velociraptor flow ID
        timeout_seconds: Maximum time to wait for completion (default 10000 = ~2.8 hours)
        logger: Optional callback function(message, level) to log progress
    """

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

            # Query flow state
            vql_query = f"LET collection <= get_flow(client_id='{client_id}', flow_id='{flow_id}') SELECT * FROM collection"

            request = api_pb2.VQLCollectorArgs(
                Query=[api_pb2.VQLRequest(VQL=vql_query)]
            )

            state = None
            total_rows = 0
            error_msg = None

            try:
                for response in stub.Query(request, timeout=10):
                    if response.Response:
                        rows = json.loads(response.Response)
                        if rows and len(rows) > 0:
                            state = rows[0].get('state', 'UNKNOWN')
                            total_rows = rows[0].get('total_collected_rows', 0)
                            error_msg = rows[0].get('status', '')
                            break

            except grpc.RpcError as e:
                log(f"⚠ Query error: {e.code()} - {e.details() if hasattr(e, 'details') else ''}", "warning")

            # Log progress every 5 checks or when rows change significantly
            if check_count % 5 == 1 or total_rows != last_rows:
                log(f"Check #{check_count} - Elapsed: {elapsed//60}m {elapsed%60}s - State: {state} - Rows: {total_rows}")
                last_rows = total_rows

            # Check state
            if state == "FINISHED":
                log(f"✓ Flow completed successfully!", "success")
                log(f"Total time: {elapsed}s ({elapsed//60}m {elapsed%60}s)", "success")
                log(f"Total rows collected: {total_rows}", "success")
                channel.close()
                return "FINISHED"

            elif state in ("ERROR", "FAILED", "CANCELLED"):
                log(f"✗ Flow failed/cancelled with state: {state}", "error")
                if error_msg:
                    log(f"Error details: {error_msg}", "error")
                channel.close()
                return state  # Return actual state so caller knows what happened

            # Check timeout
            if time.time() - start_time > timeout_seconds:
                log(f"✗ Timeout reached after {timeout_seconds}s", "error")
                log(f"Last known state: {state}, Rows collected: {total_rows}", "error")
                channel.close()
                return None

            # Wait before next check (progressively longer waits)
            if elapsed < 60:
                wait_time = 5
            elif elapsed < 300:
                wait_time = 15
            else:
                wait_time = 30

            time.sleep(wait_time)

    except Exception as e:
        error_detail = traceback.format_exc()
        log(f"✗ Exception: {e}", "error")
        log(f"Stack trace: {error_detail}", "error")
        traceback.print_exc()
        return None
