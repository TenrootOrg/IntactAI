#!/usr/bin/env python3
"""
Velociraptor Service - gRPC connection, VQL queries, client operations
"""

import subprocess
import json
import time
import yaml
import os
import grpc
import traceback
import sys
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from config import VELOCIRAPTOR_CONTAINER, VELOCIRAPTOR_API_CONFIG_PATH, VELOCIRAPTOR_SNAPSHOT_PATH

# Cached API configuration
velociraptor_api_config = None

def get_clients_from_snapshot():
    """Get clients directly from Velociraptor API using VQL query (real-time data)"""
    try:
        print("[CLIENT-LIST] Querying clients via VQL API (real-time)...", flush=True)

        # Setup gRPC connection
        channel = setup_velociraptor_connection()
        if not channel:
            print("[CLIENT-LIST] Failed to setup connection, falling back to snapshot file", flush=True)
            return get_clients_from_snapshot_file()

        stub = api_pb2_grpc.APIStub(channel)

        # VQL query to get all clients with their info
        # Only include clients seen in the last 10 minutes (600 seconds)
        vql_query = """
        SELECT client_id,
               os_info.hostname AS hostname,
               os_info.system AS os,
               os_info.release AS os_version,
               last_seen_at,
               last_ip,
               timestamp(epoch=now()) AS current_time
        FROM clients()
        WHERE client_id != 'server'
          AND last_seen_at > now() - 600
        """

        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=vql_query)]
        )

        clients = []
        for response in stub.Query(request, timeout=15):
            if response.Response:
                try:
                    result = json.loads(response.Response)
                    if isinstance(result, list):
                        for item in result:
                            if isinstance(item, dict):
                                # Convert last_seen_at to microseconds (frontend expects microseconds)
                                # Timestamp formats: seconds (10), milliseconds (13), microseconds (16), nanoseconds (19)
                                last_seen = item.get('last_seen_at', 0)
                                if last_seen:
                                    # Detect format by magnitude (10^N)
                                    if last_seen > 100000000000000000:  # Nanoseconds (> 10^17, 18+ digits)
                                        last_seen = last_seen // 1000  # Convert ns to μs
                                    elif last_seen > 100000000000000:  # Already microseconds (> 10^14, 15-17 digits)
                                        pass  # Keep as-is, already in microseconds
                                    elif last_seen > 10000000000:  # Milliseconds (> 10^10, 11-14 digits)
                                        last_seen = last_seen * 1000  # Convert ms to μs
                                    # Otherwise assume seconds or invalid

                                clients.append({
                                    "client_id": item.get('client_id', ''),
                                    "hostname": item.get('hostname', 'Unknown'),
                                    "os": item.get('os', 'Unknown'),
                                    "os_version": item.get('os_version', ''),
                                    "last_seen_at": last_seen,
                                    "last_ip": item.get('last_ip', '')
                                })
                except json.JSONDecodeError as e:
                    print(f"[CLIENT-LIST] Error parsing VQL response: {e}", flush=True)
                    continue

        channel.close()
        print(f"[CLIENT-LIST] ✓ Found {len(clients)} clients via VQL API", flush=True)
        return clients

    except Exception as e:
        print(f"[CLIENT-LIST] Error querying via API: {e}", flush=True)
        traceback.print_exc()
        # Fallback to snapshot file method
        return get_clients_from_snapshot_file()


def get_clients_from_snapshot_file():
    """Read clients from Velociraptor snapshot file (fallback method only)"""
    try:
        print("[CLIENT-LIST] Using fallback snapshot file method...", flush=True)
        cmd = [
            "docker", "exec", VELOCIRAPTOR_CONTAINER,
            "cat", VELOCIRAPTOR_SNAPSHOT_PATH
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            clients = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)

                        # Get client_id from JSON (should be present directly)
                        client_id = data.get('client_id', '')

                        # Skip server and non-client entries
                        if not client_id or client_id == 'server' or not client_id.startswith('C.'):
                            continue

                        # Decode the hex-encoded info field
                        if 'info' in data:
                            info_hex = data['info']
                            info_bytes = bytes.fromhex(info_hex)
                            info_str = info_bytes.decode('utf-8', errors='ignore')

                            # Extract hostname (appears after client_id)
                            hostname = "Unknown"
                            if "DESKTOP-" in info_str:
                                # Find DESKTOP- pattern
                                idx = info_str.find("DESKTOP-")
                                if idx != -1:
                                    # Extract until next non-alphanumeric
                                    hostname = ""
                                    for char in info_str[idx:]:
                                        if char.isalnum() or char in ['-', '_']:
                                            hostname += char
                                        else:
                                            break

                            # Extract OS (windows/linux/mac appears in the data)
                            os_system = "Unknown"
                            if "windows" in info_str.lower():
                                os_system = "Windows"
                            elif "linux" in info_str.lower():
                                os_system = "Linux"
                            elif "darwin" in info_str.lower() or "mac" in info_str.lower():
                                os_system = "macOS"

                            # Extract IP (looks for pattern like 192.168.1.29)
                            last_ip = ""
                            import re
                            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', info_str)
                            if ip_match:
                                last_ip = ip_match.group(1)

                            # Try to extract timestamp (last_seen_at)
                            # Use current time in microseconds (dashboard expects microseconds)
                            last_seen_at = int(time.time() * 1000000)

                            clients.append({
                                "client_id": client_id,
                                "hostname": hostname,
                                "os": os_system,
                                "os_version": "",
                                "last_seen_at": last_seen_at,
                                "last_ip": last_ip
                            })
                    except Exception as e:
                        print(f"[CLIENT-LIST] Error parsing client record: {e}", flush=True)
                        continue
            print(f"[CLIENT-LIST] Found {len(clients)} clients from snapshot file", flush=True)
            return clients
        return []
    except Exception as e:
        print(f"[CLIENT-LIST] Error reading snapshot: {e}", flush=True)
        return []

def load_velociraptor_api_config():
    """Load Velociraptor API configuration from container"""
    global velociraptor_api_config

    if velociraptor_api_config:
        print("[CONFIG] Using cached API configuration")
        return velociraptor_api_config

    try:
        print("[CONFIG] Loading Velociraptor API configuration from container...")
        # Copy api.config.yaml from Velociraptor container
        cmd = [
            "docker", "exec", VELOCIRAPTOR_CONTAINER,
            "cat", VELOCIRAPTOR_API_CONFIG_PATH
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            velociraptor_api_config = yaml.safe_load(result.stdout)
            print("[CONFIG] ✓ Successfully loaded Velociraptor API configuration")
            print(f"[CONFIG] Has client_cert: {bool(velociraptor_api_config.get('client_cert'))}")
            print(f"[CONFIG] Has client_private_key: {bool(velociraptor_api_config.get('client_private_key'))}")
            print(f"[CONFIG] Has ca_certificate: {bool(velociraptor_api_config.get('ca_certificate'))}")
            return velociraptor_api_config
        else:
            print(f"[CONFIG] ✗ Failed to load API config: {result.stderr}")
            return None
    except Exception as e:
        print(f"[CONFIG] ✗ Exception loading API config: {e}")
        traceback.print_exc()
        return None

def setup_velociraptor_connection():
    """Setup gRPC connection to Velociraptor API"""
    try:
        # Copy API config from Velociraptor container to local path
        config_path = "/tmp/api.config.yaml"

        # Check if we need to copy the config
        if not os.path.exists(config_path):
            print("[GRPC] Copying API config from Velociraptor container...", flush=True)
            result = subprocess.run([
                "docker", "exec", VELOCIRAPTOR_CONTAINER,
                "cat", VELOCIRAPTOR_API_CONFIG_PATH
            ], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                with open(config_path, 'w') as f:
                    f.write(result.stdout)
                print("[GRPC] API config copied successfully", flush=True)
            else:
                print(f"[GRPC] Failed to copy config: {result.stderr}", flush=True)
                return None
        else:
            print("[GRPC] Using existing API config", flush=True)

        # Load the YAML configuration
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        # Prepare the credentials for the gRPC connection
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )

        # Set gRPC options - increase message size for large artifacts like Hayabusa
        # Default is 4MB, but forensic artifacts can return 30MB+
        max_message_size = 100 * 1024 * 1024  # 100MB
        options = (
            ("grpc.ssl_target_name_override", "VelociraptorServer"),
            ("grpc.max_receive_message_length", max_message_size),
            ("grpc.max_send_message_length", max_message_size),
        )

        # Establish the secure channel
        channel = grpc.secure_channel(config["api_connection_string"], creds, options)
        print(f"[GRPC] Secure channel established to {config['api_connection_string']}", flush=True)
        return channel

    except Exception as e:
        print(f"[GRPC] Connection setup failed: {e}", flush=True)
        traceback.print_exc()
        sys.stdout.flush()
        sys.stderr.flush()
        return None

def create_velociraptor_hunt(artifact_name, description="", cpu_limit=90):
    """Create a real hunt in Velociraptor using gRPC API

    Args:
        artifact_name: Name of the artifact to hunt
        description: Hunt description
        cpu_limit: CPU limit percentage (default 90%)
    """
    sys.stdout.flush()
    print("=" * 80, flush=True)
    print(f"[HUNT] Creating hunt for artifact: {artifact_name}", flush=True)
    print(f"[HUNT] Description: {description}", flush=True)
    print(f"[HUNT] CPU Limit: {cpu_limit}%", flush=True)
    print("=" * 80, flush=True)

    try:
        # Setup gRPC connection
        channel = setup_velociraptor_connection()
        if not channel:
            print("[HUNT] ✗ Failed to setup gRPC connection")
            return None

        stub = api_pb2_grpc.APIStub(channel)

        # Build VQL query to create hunt
        # Using default parameters similar to risx-mssp-python
        expire_seconds = 86400  # 24 hours
        timeout_seconds = 600   # 10 minutes
        max_rows = 1000000
        max_bytes = 1048576000  # ~1GB

        vql_query = f"""
LET collection = hunt(
    description='MSSP Hunt: {description}',
    artifacts='{artifact_name}',
    spec=dict(`{artifact_name}`=dict()),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    max_rows={max_rows},
    max_bytes={max_bytes},
    cpu_limit={cpu_limit}
) SELECT HuntId FROM collection
"""

        print(f"[HUNT] Executing VQL query via gRPC...")
        print(f"[HUNT] VQL: {vql_query.strip()}")

        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(VQL=vql_query)]
        )

        hunt_id = None
        timeout_seconds = 30

        # Execute query and get hunt ID
        for response in stub.Query(request, timeout=timeout_seconds):
            if response.log:
                print(f"[HUNT] Server log: {response.log}")

            if response.Response:
                print(f"[HUNT] Received response: {response.Response}")
                try:
                    parsed_json = json.loads(response.Response)
                    if isinstance(parsed_json, list) and len(parsed_json) > 0:
                        result_obj = parsed_json[0]
                        if isinstance(result_obj, dict) and "HuntId" in result_obj:
                            hunt_id = result_obj["HuntId"]
                            print(f"[HUNT] ✓ Successfully created hunt!")
                            print(f"[HUNT] Hunt ID: {hunt_id}")
                            break
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    print(f"[HUNT] ⚠ Could not parse HuntId: {e}")
                    continue

        channel.close()

        if hunt_id:
            print("=" * 80)
            return hunt_id
        else:
            print("[HUNT] ✗ No HuntId returned from server")
            print("=" * 80)
            return None

    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            print(f"[HUNT] ✗ gRPC call timed out")
        else:
            print(f"[HUNT] ✗ gRPC error: {e.details()}")
        print("=" * 80)
        return None

    except Exception as e:
        print(f"[HUNT] ✗ Exception: {e}")
        traceback.print_exc()
        print("=" * 80)
        return None


def load_tools_config():
    """Load tools inventory configuration from YAML file."""
    # Try /app/data first (container mount), then fallback to relative path
    paths_to_try = [
        '/app/data/tools_inventory.yaml',
        os.path.join(os.path.dirname(__file__), '..', 'data', 'tools_inventory.yaml')
    ]
    for config_path in paths_to_try:
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            print(f"[TOOLS] Error loading {config_path}: {e}", flush=True)
    print("[TOOLS] Could not find tools_inventory.yaml", flush=True)
    return None


def download_tools_to_inventory(logger=None):
    """Configure tools to be served locally from Velociraptor server.

    Tools are loaded from data/tools_inventory.yaml which maps:
    - tool_name: Velociraptor tool name
    - file_pattern: Regex to match downloaded file in tools_directory

    Uses inventory_add(tool=X, serve_locally=TRUE, file=<path>) to serve tools.
    """
    import re

    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS] {msg}", flush=True)

    log("Starting tool inventory configuration...")

    # Load tools config
    config = load_tools_config()
    if not config:
        log("Failed to load tools_inventory.yaml", "error")
        return {"success": False, "error": "Config file not found"}

    # Get tools directory from config
    settings = config.get('settings', {})
    tools_directory = settings.get('tools_directory', '/tools')

    channel = setup_velociraptor_connection()
    if not channel:
        log("Failed to connect to Velociraptor", "error")
        return {"success": False, "error": "Connection failed"}

    stub = api_pb2_grpc.APIStub(channel)
    results = {"configured": [], "failed": [], "skipped": [], "already_served": [], "file_not_found": []}

    # Get tools from velociraptor_inventory section
    inventory_tools = config.get('velociraptor_inventory', [])
    enabled_tools = [t for t in inventory_tools if t.get('enabled', True)]

    log(f"Found {len(enabled_tools)} enabled tools in config")
    log(f"Tools directory: {tools_directory}")

    try:
        # First, check what's already served locally
        log("Checking current server inventory...")
        served_tools = set()
        try:
            vql = "SELECT name, serve_locally FROM inventory() WHERE serve_locally = true"
            request = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=200,
                Query=[api_pb2.VQLRequest(VQL=vql)]
            )

            for response in stub.Query(request, timeout=35):
                if response.Response:
                    data = json.loads(response.Response)
                    for item in data:
                        served_tools.add(item.get('name', ''))

            log(f"Currently {len(served_tools)} tools served locally")
        except Exception as e:
            log(f"Could not query inventory: {str(e)[:50]}", "warning")

        # Get list of available files in tools directory
        available_files = []
        try:
            vql = f'SELECT Name FROM glob(globs="*", root="{tools_directory}") WHERE NOT IsDir'
            request = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=500,
                Query=[api_pb2.VQLRequest(VQL=vql)]
            )

            for response in stub.Query(request, timeout=35):
                if response.Response:
                    data = json.loads(response.Response)
                    available_files = [item.get('Name', '') for item in data]

            log(f"Found {len(available_files)} files in tools directory")
        except Exception as e:
            log(f"Could not list tools directory: {str(e)[:50]}", "warning")
            log("Make sure tools directory is mounted in Velociraptor container", "warning")

        if not available_files:
            log("No files found in tools directory - skipping tool configuration", "warning")
            channel.close()
            return {
                "success": True,
                "results": results,
                "summary": "No tools to configure (directory empty or not mounted)"
            }

        # Configure each enabled tool
        for tool in enabled_tools:
            tool_name = tool.get('tool_name', '')
            file_pattern = tool.get('file_pattern', '')

            if not tool_name or not file_pattern:
                results["skipped"].append(tool_name or "Unknown")
                continue

            # Check if already served
            if tool_name in served_tools:
                results["already_served"].append(tool_name)
                continue

            # Find matching file
            matched_file = None
            try:
                pattern = re.compile(file_pattern)
                for filename in available_files:
                    if pattern.match(filename):
                        matched_file = filename
                        break
            except re.error:
                log(f"  {tool_name}: Invalid regex pattern", "warning")
                results["failed"].append(tool_name)
                continue

            if not matched_file:
                results["file_not_found"].append(tool_name)
                continue

            # Configure tool with inventory_add
            try:
                file_path = f"{tools_directory}/{matched_file}"
                vql = f'''
                SELECT * FROM inventory_add(
                    tool="{tool_name}",
                    serve_locally=TRUE,
                    file="{file_path}",
                    filename="{matched_file}",
                    accessor="file"
                )
                '''
                request = api_pb2.VQLCollectorArgs(
                    max_wait=60,
                    max_row=10,
                    Query=[api_pb2.VQLRequest(VQL=vql)]
                )

                for response in stub.Query(request, timeout=65):
                    pass  # Just execute

                log(f"  ✓ {tool_name} -> {matched_file}", "success")
                results["configured"].append(tool_name)

            except Exception as e:
                log(f"  ✗ {tool_name}: {str(e)[:40]}", "warning")
                results["failed"].append(tool_name)

        # Final inventory check
        log("Verifying final inventory status...")
        try:
            vql = "SELECT name, serve_locally FROM inventory()"
            request = api_pb2.VQLCollectorArgs(
                max_wait=30,
                max_row=200,
                Query=[api_pb2.VQLRequest(VQL=vql)]
            )

            served_count = 0
            total_count = 0
            for response in stub.Query(request, timeout=35):
                if response.Response:
                    data = json.loads(response.Response)
                    if data:
                        total_count = len(data)
                        served_count = sum(1 for t in data if t.get('serve_locally'))

            log(f"Server inventory: {served_count}/{total_count} tools served locally", "info")
        except Exception as e:
            log(f"Could not query inventory: {str(e)[:50]}", "warning")

        channel.close()

        configured = len(results['configured'])
        already = len(results['already_served'])
        not_found = len(results['file_not_found'])
        skipped = len(results['skipped'])
        failed = len(results['failed'])

        summary = f"Configured: {configured}, Already served: {already}, File not found: {not_found}, Skipped: {skipped}, Failed: {failed}"
        log(f"Tool configuration complete. {summary}", "success")

        return {
            "success": True,
            "results": results,
            "summary": summary
        }

    except Exception as e:
        try:
            channel.close()
        except:
            pass
        log(f"Tool configuration failed: {str(e)}", "error")
        return {"success": False, "error": str(e)}


def get_artifact_definitions():
    """Get all artifact definitions from Velociraptor.

    Returns a list of artifact names that are available in the server.
    This is used to dynamically populate blueprint artifact selectors.
    """
    try:
        print("[ARTIFACTS] Querying artifact definitions from Velociraptor...", flush=True)

        channel = setup_velociraptor_connection()
        if not channel:
            print("[ARTIFACTS] Failed to setup connection", flush=True)
            return None

        stub = api_pb2_grpc.APIStub(channel)

        # Query CLIENT artifacts only - exclude server, monitoring, and admin artifacts
        # type="client" means it runs on endpoints, not server-side
        # Exclude Admin.* (administrative operations) and Demo.* (demo artifacts)
        vql_query = """
        SELECT name, description, type
        FROM artifact_definitions()
        WHERE type = 'client'
          AND NOT name =~ '^Server\\.'
          AND NOT name =~ '^Admin\\.'
          AND NOT name =~ '^Demo\\.'
          AND NOT name =~ 'Monitor'
        ORDER BY name
        """

        request = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=2000,
            Query=[api_pb2.VQLRequest(VQL=vql_query)]
        )

        artifacts = []
        for response in stub.Query(request, timeout=60):
            if response.Response:
                try:
                    result = json.loads(response.Response)
                    if isinstance(result, list):
                        for item in result:
                            if isinstance(item, dict):
                                artifacts.append({
                                    "name": item.get('name', ''),
                                    "description": item.get('description', '')[:200] if item.get('description') else '',
                                    "type": item.get('type', '')
                                })
                except json.JSONDecodeError as e:
                    print(f"[ARTIFACTS] Error parsing response: {e}", flush=True)
                    continue

        channel.close()
        print(f"[ARTIFACTS] ✓ Found {len(artifacts)} artifacts", flush=True)
        return artifacts

    except Exception as e:
        print(f"[ARTIFACTS] Error querying artifacts: {e}", flush=True)
        traceback.print_exc()
        return None


def get_tools_inventory_config():
    """Get the current tools inventory configuration."""
    config = load_tools_config()
    if not config:
        return None

    # Flatten all tool categories into a summary
    summary = {
        "velociraptor_inventory": [],
        "settings": config.get('settings', {}),
        "total_enabled": 0,
        "total_disabled": 0
    }

    # Velociraptor inventory tools - using new field names
    for tool in config.get('velociraptor_inventory', []):
        enabled = tool.get('enabled', True)
        summary["velociraptor_inventory"].append({
            "tool_name": tool.get('tool_name'),
            "file_pattern": tool.get('file_pattern'),
            "enabled": enabled
        })
        if enabled:
            summary["total_enabled"] += 1
        else:
            summary["total_disabled"] += 1

    return summary
