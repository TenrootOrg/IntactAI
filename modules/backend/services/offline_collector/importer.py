#!/usr/bin/env python3
"""
Offline Collector Importer - Import offline collection results to Velociraptor
"""

import os
import re
import json
import time
import subprocess
import zipfile

from services.offline_collector.constants import VELOCIRAPTOR_CONTAINER


def import_results(zip_file_path, original_filename="import.zip", run_id=None):
    """Import offline collection results to Velociraptor using Server.Utils.ImportCollection

    Args:
        zip_file_path: Path to the uploaded ZIP file (must be from official Velociraptor collector)
        original_filename: Original filename of the upload
        run_id: Optional workflow run_id (created in pre-create hook)

    Returns:
        dict with import status
    """
    import yaml
    import grpc
    from pyvelociraptor import api_pb2, api_pb2_grpc
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status

    try:
        # Use existing run_id or create new one
        if not run_id:
            run_id = create_automation_run(
                "velociraptor_offline_import",
                f"Import: {original_filename}",
                {"filename": original_filename, "path": zip_file_path}
            )
            add_log_to_run(run_id, f"Starting import of {original_filename}")
            update_run_status(run_id, "running", progress=10)
        else:
            add_log_to_run(run_id, "=== Starting Velociraptor Import ===")

        # Get file size
        file_size = os.path.getsize(zip_file_path)
        add_log_to_run(run_id, f"File size: {file_size / 1024 / 1024:.2f} MB")

        # Extract hostname from filename (Collection-HOSTNAME-timestamp.zip)
        hostname_match = re.search(r'Collection-([^-]+)-', original_filename)
        hostname = hostname_match.group(1) if hostname_match else "OfflineClient"
        add_log_to_run(run_id, f"Client hostname: {hostname}")
        print(f"[OFFLINE] Importing collection for hostname: {hostname}", flush=True)

        update_run_status(run_id, "running", progress=15)

        # Verify this is a valid Velociraptor collection ZIP
        add_log_to_run(run_id, "Verifying ZIP contents...")
        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zf:
                file_list = zf.namelist()
                has_context = any('collection_context.json' in f for f in file_list)
                print(f"[OFFLINE] ZIP contents: {file_list[:10]}...", flush=True)
                add_log_to_run(run_id, f"ZIP contains {len(file_list)} files")
                if not has_context:
                    add_log_to_run(run_id, "Warning: ZIP missing collection_context.json - may not import correctly", "warning")
                else:
                    add_log_to_run(run_id, "Valid Velociraptor collection format detected")
        except Exception as e:
            print(f"[OFFLINE] Error checking ZIP: {e}", flush=True)
            add_log_to_run(run_id, f"Warning: Could not verify ZIP: {str(e)}", "warning")

        add_log_to_run(run_id, "Importing to Velociraptor via Server.Utils.ImportCollection")
        update_run_status(run_id, "running", progress=20)

        # Step 1: Copy ZIP to Velociraptor container
        add_log_to_run(run_id, "Copying ZIP to Velociraptor server...")
        container_path = f"/tmp/offline_import_{int(time.time())}.zip"

        copy_cmd = f"docker cp {zip_file_path} {VELOCIRAPTOR_CONTAINER}:{container_path}"
        result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            raise Exception(f"Failed to copy ZIP to Velociraptor: {result.stderr}")

        print(f"[OFFLINE] Copied ZIP to {VELOCIRAPTOR_CONTAINER}:{container_path}", flush=True)
        add_log_to_run(run_id, f"ZIP copied to Velociraptor server at {container_path}")

        update_run_status(run_id, "running", progress=40)

        # Step 2: Setup gRPC connection to Velociraptor
        add_log_to_run(run_id, "Connecting to Velociraptor API...")

        # Load API config from container
        config_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} cat /velociraptor/api.config.yaml"
        config_result = subprocess.run(config_cmd, shell=True, capture_output=True, text=True, timeout=10)

        if config_result.returncode != 0:
            raise Exception(f"Failed to get API config: {config_result.stderr}")

        config = yaml.safe_load(config_result.stdout)

        # Setup gRPC credentials
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )

        max_message_size = 100 * 1024 * 1024  # 100MB
        channel = grpc.secure_channel(
            config["api_connection_string"],
            creds,
            (
                ("grpc.ssl_target_name_override", "VelociraptorServer"),
                ("grpc.max_receive_message_length", max_message_size),
                ("grpc.max_send_message_length", max_message_size),
            )
        )
        stub = api_pb2_grpc.APIStub(channel)

        update_run_status(run_id, "running", progress=50)

        # Step 3: Run Server.Utils.ImportCollection artifact
        add_log_to_run(run_id, "Running Velociraptor import artifact...")

        # Build VQL to run the import using collect_client for server artifact
        # ClientId="auto" creates a new client, Hostname is required for new clients
        vql_query = f'''SELECT collect_client(
            client_id="server",
            artifacts="Server.Utils.ImportCollection",
            spec=dict(
                `Server.Utils.ImportCollection`=dict(
                    ClientId="auto",
                    Hostname="{hostname}",
                    Path="{container_path}"
                )
            )
        ) AS Collection FROM scope()'''

        print(f"[OFFLINE] Running VQL: {vql_query[:200]}...", flush=True)
        add_log_to_run(run_id, f"Executing Server.Utils.ImportCollection for hostname: {hostname}")

        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(VQL=vql_query)]
        )

        client_id = None
        flow_id = None
        total_rows = 0
        artifacts = []

        # Execute import with timeout
        add_log_to_run(run_id, "Sending import request to Velociraptor (this may take a while)...")
        import_response_raw = None
        for response in stub.Query(request, timeout=300):
            if response.log:
                print(f"[OFFLINE] Server log: {response.log}", flush=True)
                add_log_to_run(run_id, f"Velociraptor: {response.log[:150]}")

            if response.Response:
                import_response_raw = response.Response
                print(f"[OFFLINE] Full response: {response.Response}", flush=True)
                try:
                    parsed = json.loads(response.Response)
                    print(f"[OFFLINE] Parsed response: {json.dumps(parsed, indent=2)[:1000]}", flush=True)

                    if isinstance(parsed, list) and len(parsed) > 0:
                        collection_result = parsed[0].get("Collection")

                        # Handle None result
                        if collection_result is None:
                            print(f"[OFFLINE] Collection result is None, raw: {parsed[0]}", flush=True)
                            add_log_to_run(run_id, "Warning: Collection result was None")
                            continue

                        # The result structure from collect_client
                        if isinstance(collection_result, dict):
                            print(f"[OFFLINE] Collection result keys: {collection_result.keys()}", flush=True)

                            # collect_client returns the flow info directly
                            flow_id = collection_result.get("flow_id") or collection_result.get("session_id")
                            client_id = collection_result.get("client_id")

                            # Also check request sub-object
                            if "request" in collection_result:
                                req = collection_result["request"]
                                flow_id = flow_id or req.get("flow_id") or req.get("session_id")
                                client_id = client_id or req.get("client_id")

                            print(f"[OFFLINE] Extracted - client_id: {client_id}, flow_id: {flow_id}", flush=True)
                            if flow_id:
                                add_log_to_run(run_id, f"Import flow started: {flow_id}")

                except json.JSONDecodeError as e:
                    print(f"[OFFLINE] JSON decode error: {e}", flush=True)
                    add_log_to_run(run_id, f"JSON parse error: {str(e)}")
                    continue

        channel.close()

        update_run_status(run_id, "running", progress=80)

        # Step 4: Wait for the import to complete and verify
        print(f"[OFFLINE] Waiting for import flow to complete...", flush=True)
        add_log_to_run(run_id, "Waiting for import to complete...")
        time.sleep(5)  # Give more time for the import flow to complete

        # Query for import results to get the ACTUAL imported client info
        # The server flow runs ImportCollection which creates/updates a client
        # We need to query the flow RESULTS to get the imported client_id
        imported_client_id = None
        imported_flow_id = None

        if flow_id:
            add_log_to_run(run_id, f"Server import flow: {flow_id}")
            print(f"[OFFLINE] Querying import flow results...", flush=True)

            # Query flow RESULTS to get the actual imported client info
            # Server.Utils.ImportCollection outputs info about what was imported
            try:
                channel2 = grpc.secure_channel(
                    config["api_connection_string"],
                    creds,
                    (
                        ("grpc.ssl_target_name_override", "VelociraptorServer"),
                        ("grpc.max_receive_message_length", max_message_size),
                        ("grpc.max_send_message_length", max_message_size),
                    )
                )
                stub2 = api_pb2_grpc.APIStub(channel2)

                # First, query the artifact results to get imported client info
                results_query = f"SELECT * FROM source(client_id='server', flow_id='{flow_id}', artifact='Server.Utils.ImportCollection')"
                print(f"[OFFLINE] Querying import results: {results_query}", flush=True)

                results_request = api_pb2.VQLCollectorArgs(
                    Query=[api_pb2.VQLRequest(VQL=results_query)]
                )

                for response in stub2.Query(results_request, timeout=60):
                    if response.Response:
                        print(f"[OFFLINE] Import results response: {response.Response}", flush=True)
                        results_data = json.loads(response.Response)
                        if results_data and len(results_data) > 0:
                            result_row = results_data[0]
                            print(f"[OFFLINE] Import result keys: {list(result_row.keys())}", flush=True)
                            print(f"[OFFLINE] Import result: {json.dumps(result_row, indent=2)[:2000]}", flush=True)

                            # Extract the imported client_id and flow_id from results
                            imported_client_id = (
                                result_row.get("ClientId") or
                                result_row.get("client_id") or
                                result_row.get("NewClientId") or
                                result_row.get("new_client_id")
                            )
                            imported_flow_id = (
                                result_row.get("FlowId") or
                                result_row.get("flow_id") or
                                result_row.get("ImportedFlowId")
                            )

                            # Get count info from results
                            total_rows = (
                                result_row.get("TotalRows") or
                                result_row.get("total_rows") or
                                result_row.get("RowCount") or
                                result_row.get("ImportedRows") or
                                len(results_data)  # At minimum, count the result rows
                            )

                            # Get artifacts info
                            artifacts = (
                                result_row.get("Artifacts") or
                                result_row.get("artifacts") or
                                result_row.get("ImportedArtifacts") or
                                []
                            )

                            add_log_to_run(run_id, f"Import results: client={imported_client_id}, flow={imported_flow_id}, rows={total_rows}")

                # If we found the imported client, update our variables
                if imported_client_id:
                    client_id = imported_client_id
                    add_log_to_run(run_id, f"Imported client ID: {client_id}")
                if imported_flow_id:
                    flow_id = imported_flow_id

                # Also query the server flow metadata for state
                add_log_to_run(run_id, "Checking import flow status...")
                flow_query = f"SELECT * FROM flows(client_id='server', flow_id='{flow_id}')"
                print(f"[OFFLINE] Querying server flow: {flow_query}", flush=True)

                flow_request = api_pb2.VQLCollectorArgs(
                    Query=[api_pb2.VQLRequest(VQL=flow_query)]
                )

                for response in stub2.Query(flow_request, timeout=30):
                    if response.Response:
                        print(f"[OFFLINE] Flow query response: {response.Response[:1000]}", flush=True)
                        flow_data = json.loads(response.Response)
                        if flow_data and len(flow_data) > 0:
                            flow_info = flow_data[0]
                            print(f"[OFFLINE] Flow info keys: {list(flow_info.keys())}", flush=True)

                            # Check flow state
                            flow_state = flow_info.get("state") or flow_info.get("State") or ""
                            print(f"[OFFLINE] Flow state: {flow_state}", flush=True)
                            add_log_to_run(run_id, f"Server flow state: {flow_state}")

                # Query for the imported client by hostname or client_id
                add_log_to_run(run_id, "Verifying imported client...")
                if imported_client_id:
                    client_query = f"SELECT client_id, os_info.hostname, os_info.system FROM clients(client_id='{imported_client_id}')"
                else:
                    client_query = f"SELECT client_id, os_info.hostname, os_info.system FROM clients(search='host:{hostname}')"
                print(f"[OFFLINE] Querying clients: {client_query}", flush=True)

                client_request = api_pb2.VQLCollectorArgs(
                    Query=[api_pb2.VQLRequest(VQL=client_query)]
                )

                for response in stub2.Query(client_request, timeout=30):
                    if response.Response:
                        print(f"[OFFLINE] Client query response: {response.Response}", flush=True)
                        client_data = json.loads(response.Response)
                        if client_data and len(client_data) > 0:
                            client_info = client_data[0]
                            print(f"[OFFLINE] Found client: {client_info}", flush=True)
                            # Use client_id from query if we didn't get it from results
                            if not imported_client_id:
                                imported_client_id = client_info.get("client_id")
                                client_id = imported_client_id
                            add_log_to_run(run_id, f"Found imported client: {client_info.get('os_info.hostname', hostname)} ({imported_client_id or client_id})")

                channel2.close()
            except Exception as e:
                print(f"[OFFLINE] Error getting flow details: {e}", flush=True)
                import traceback
                traceback.print_exc()
                add_log_to_run(run_id, f"Warning: Could not get flow details: {str(e)}")

        # Step 5: Cleanup container file
        add_log_to_run(run_id, "Cleaning up temporary files...")
        cleanup_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} rm -f {container_path}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True)

        # Cleanup uploaded file
        try:
            os.remove(zip_file_path)
            add_log_to_run(run_id, "Upload file cleaned up")
        except:
            pass

        update_run_status(run_id, "running", progress=95)

        # Final summary
        if client_id and flow_id:
            # Build more informative message
            if total_rows > 0:
                detail_msg = f"{total_rows} rows collected"
            else:
                detail_msg = "Collection imported"

            if artifacts:
                detail_msg += f", {len(artifacts)} artifact(s)"

            add_log_to_run(run_id, f"Import complete: {detail_msg}")
            add_log_to_run(run_id, f"Artifacts: {', '.join(artifacts) if artifacts else 'Check Velociraptor UI for details'}")
            update_run_status(run_id, "completed", progress=100)

            print(f"[OFFLINE] Import complete! Client: {client_id}, Flow: {flow_id}", flush=True)
            print(f"[OFFLINE] Total rows: {total_rows}, Artifacts: {artifacts}", flush=True)

            return {
                "success": True,
                "run_id": run_id,
                "client_id": client_id,
                "flow_id": flow_id,
                "hostname": hostname,
                "total_rows": total_rows,
                "artifacts": artifacts,
                "message": f"Successfully imported to Velociraptor. Client: {hostname} ({client_id}). {detail_msg}. View in Velociraptor UI for full details."
            }
        else:
            # Import may have worked but we couldn't get the IDs
            add_log_to_run(run_id, "Import completed but could not retrieve client/flow IDs")
            update_run_status(run_id, "completed", progress=100)

            return {
                "success": True,
                "run_id": run_id,
                "hostname": hostname,
                "message": "Import sent to Velociraptor. Check Velociraptor UI for results."
            }

    except grpc.RpcError as e:
        error_msg = f"gRPC error: {e.details() if hasattr(e, 'details') else str(e)}"
        print(f"[OFFLINE] {error_msg}", flush=True)

        if run_id:
            try:
                add_log_to_run(run_id, f"Import failed: {error_msg}", "error")
                update_run_status(run_id, "failed", progress=0, error=error_msg)
            except:
                pass

        # Cleanup
        try:
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)
        except:
            pass

        return {"success": False, "run_id": run_id, "error": error_msg}

    except Exception as e:
        error_msg = str(e)
        print(f"[OFFLINE] Import error: {error_msg}", flush=True)
        import traceback
        traceback.print_exc()

        if run_id:
            try:
                add_log_to_run(run_id, f"Import failed: {error_msg}", "error")
                update_run_status(run_id, "failed", progress=0, error=error_msg)
            except:
                pass

        # Cleanup on error
        try:
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)
        except:
            pass

        return {"success": False, "run_id": run_id, "error": error_msg}
