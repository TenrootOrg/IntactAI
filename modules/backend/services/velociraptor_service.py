#!/usr/bin/env python3
"""
Velociraptor Service - gRPC connection, VQL queries, client operations
"""

import subprocess
import json
import shlex
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

def get_clients_from_snapshot(include_offline=False):
    """Get clients directly from Velociraptor API using VQL query (real-time data).

    Args:
        include_offline: When False (default), filter to clients seen in
            the last 10 minutes — appropriate for new-collection mode where
            offline endpoints cannot receive a hunt. When True, return all
            enrolled clients regardless of last-seen time — needed for
            existing-flow analysis where the data is already collected and
            client liveness is irrelevant.
    """
    try:
        print(f"[CLIENT-LIST] Querying clients via VQL API (real-time, include_offline={include_offline})...", flush=True)

        # Setup gRPC connection
        channel = setup_velociraptor_connection()
        if not channel:
            print("[CLIENT-LIST] Failed to setup connection, falling back to snapshot file", flush=True)
            return get_clients_from_snapshot_file()

        stub = api_pb2_grpc.APIStub(channel)

        # VQL query to get clients with their info. Online filter only
        # applied when include_offline=False — for existing-flow analysis
        # we want every enrolled client visible since the data was
        # collected previously.
        liveness_clause = "" if include_offline else "  AND last_seen_at > now() - 600"
        vql_query = f"""
        SELECT client_id,
               os_info.hostname AS hostname,
               os_info.system AS os,
               os_info.release AS os_version,
               labels AS labels,
               last_seen_at,
               last_ip,
               timestamp(epoch=now()) AS current_time
        FROM clients()
        WHERE client_id != 'server'{liveness_clause}
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

                                # Velociraptor's built-in labels start with "label:"
                                # in some columns; here `labels` is the plain list.
                                _labels = item.get('labels') or []
                                if not isinstance(_labels, list):
                                    _labels = [str(_labels)]
                                clients.append({
                                    "client_id": item.get('client_id', ''),
                                    "hostname": item.get('hostname', 'Unknown'),
                                    "os": item.get('os', 'Unknown'),
                                    "os_version": item.get('os_version', ''),
                                    "labels": [str(l) for l in _labels if l],
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
        # Always re-copy the API config from the Velociraptor container rather
        # than caching: a stale /tmp/api.config.yaml with an out-of-date hostname
        # breaks every subsequent gRPC call. The copy is a cheap `docker exec
        # cat` of a small YAML.
        config_path = "/tmp/api.config.yaml"
        print("[GRPC] Copying API config from Velociraptor container...", flush=True)
        result = subprocess.run([
            "docker", "exec", VELOCIRAPTOR_CONTAINER,
            "cat", VELOCIRAPTOR_API_CONFIG_PATH
        ], capture_output=True, text=True, timeout=5)

        if result.returncode != 0:
            print(f"[GRPC] Failed to copy config: {result.stderr}", flush=True)
            return None

        with open(config_path, 'w') as f:
            f.write(result.stdout)

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


def get_hunt_description(hunt_id):
    """Return a Velociraptor hunt's description string (or '' if unknown).

    The agentic blueprints stamp every hunt/collector they generate with an
    '[Agentic]' description (e.g. '[Agentic] Quick Wins Extended (15 artifacts)').
    For an OFFLINE-COLLECTOR import that description is the only agentic-provenance
    signal that survives the ZIP round-trip (the IntactAI blueprint_id does not),
    so fusion reads it back here to decide whether the import is an agentic run."""
    if not hunt_id:
        return ""
    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return ""
        stub = api_pb2_grpc.APIStub(channel)
        vql = ("SELECT hunt_description FROM hunts() "
               f"WHERE hunt_id = '{hunt_id}' LIMIT 1")
        req = api_pb2.VQLCollectorArgs(
            max_wait=10, max_row=1,
            Query=[api_pb2.VQLRequest(VQL=vql)],
        )
        for resp in stub.Query(req, timeout=15):
            if resp.Response:
                try:
                    rows = json.loads(resp.Response)
                except json.JSONDecodeError:
                    continue
                if isinstance(rows, list) and rows:
                    return str(rows[0].get("hunt_description") or "")
        return ""
    except Exception as e:
        print(f"[GRPC] get_hunt_description({hunt_id}) failed: {e}", flush=True)
        return ""


def create_velociraptor_hunt(
    artifact_name,
    description="",
    cpu_limit=90,
    # Hunt resource limits — replace what used to be hardcoded right below.
    # Defaults match the historical hardcoded values so callers that don't
    # pass anything see identical pre-patch behavior.
    expire_seconds=86400,
    timeout_seconds=600,
    max_rows=1000000,
    max_bytes=1048576000,   # ~1 GiB
    max_logs=100000,
):
    """Create a real hunt in Velociraptor using gRPC API

    Args:
        artifact_name: Name of the artifact to hunt
        description: Hunt description
        cpu_limit: CPU limit percentage (default 90%)
        expire_seconds: Seconds until the hunt expires (default 86400 = 24h)
        timeout_seconds: Seconds before the hunt's per-client collection times out
        max_rows: Hard cap on rows the hunt may collect across all clients
        max_bytes: Hard cap on bytes uploaded across all clients
        max_logs: Hard cap on log lines emitted across all clients
    """
    sys.stdout.flush()
    print("=" * 80, flush=True)
    print(f"[HUNT] Creating hunt for artifact: {artifact_name}", flush=True)
    print(f"[HUNT] Description: {description}", flush=True)
    print(f"[HUNT] CPU Limit: {cpu_limit}%", flush=True)
    print(f"[HUNT] Resource caps: max_rows={max_rows}, max_logs={max_logs}, "
          f"max_bytes={max_bytes}", flush=True)
    print("=" * 80, flush=True)

    try:
        # Setup gRPC connection
        channel = setup_velociraptor_connection()
        if not channel:
            print("[HUNT] ✗ Failed to setup gRPC connection")
            return None

        stub = api_pb2_grpc.APIStub(channel)

        # Build VQL query to create hunt. The resource limits used to be
        # hardcoded right here; now they're parameters from the blueprint.

        # Note: hunt() accepts max_rows + max_bytes but NOT max_logs (that's a
        # collect_client-only arg). max_logs in the blueprint is honored on
        # the TimeSketch / collect_client path; here we just skip it.
        _ = max_logs  # intentionally unused for hunt VQL
        vql_query = f"""
LET collection = hunt(
    description='Intact.AI Hunt: {description}',
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


def export_flow_to_zip(client_id: str, flow_id: str, out_path: str, logger=None, timeout: int = 900) -> bool:
    """Ask Velociraptor to package a finished flow as a ZIP and copy it to out_path.

    Velociraptor stores uploaded files as 1MB zlib-compressed chunks and only
    reassembles them into whole files when a flow is exported via this API.
    Reading live from /var./clients/.../uploads/ returns truncated first-chunk
    data, which is why that path was producing 6x fewer Plaso events than
    running Plaso against an exported ZIP.

    Args:
        client_id: Velociraptor client id (C.xxxxx)
        flow_id: Velociraptor flow id (F.xxxxx)
        out_path: absolute path on the backend host/container where the ZIP
            should end up
        logger: optional callable(msg, level) for progress logging
        timeout: seconds to wait for packaging to complete

    Returns:
        True on success, False on any failure (logs the reason via logger).
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        else:
            print(f"[VELO-EXPORT] [{level}] {msg}", flush=True)

    channel = setup_velociraptor_connection()
    if not channel:
        log("Failed to connect to Velociraptor gRPC", "error")
        return False

    try:
        stub = api_pb2_grpc.APIStub(channel)

        vql = (
            "SELECT create_flow_download("
            f"client_id='{client_id}', flow_id='{flow_id}', "
            "wait=TRUE, type='full') AS download_path FROM scope()"
        )

        log(f"Requesting ZIP export for {flow_id} on {client_id} (may take a few minutes)...")

        request = api_pb2.VQLCollectorArgs(
            max_wait=timeout,
            max_row=10,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )

        success = False
        for response in stub.Query(request, timeout=timeout + 60):
            if response.Response:
                try:
                    rows = json.loads(response.Response)
                    if rows:
                        log(f"Velociraptor finished packaging ZIP for {flow_id}")
                        success = True
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        log(f"VQL error while requesting export: {e}", "error")
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass

    if not success:
        log("Velociraptor did not return a successful download path", "warning")
        # Proceed anyway — the ZIP might still be on disk from a previous run.

    # The ZIP lives inside the Velociraptor container. Pull it out with
    # `docker exec` (to locate the actual filename) + `docker cp` (to
    # stream it to the host). The previous alpine sidecar approach
    # (`docker run --rm --volumes-from intact_velociraptor alpine ...`)
    # broke on airgapped boxes because docker would try to pull
    # `alpine:latest` from Docker Hub at runtime. exec+cp uses only the
    # already-running container — zero network dependency.
    out_dir = os.path.dirname(out_path) or "/tmp"
    os.makedirs(out_dir, exist_ok=True)

    src_dir = f"/var./downloads/{client_id}/{flow_id}"
    locate_cmd = [
        "docker", "exec", VELOCIRAPTOR_CONTAINER, "sh", "-c",
        f"ls -1 {src_dir}/*.zip 2>/dev/null | head -1",
    ]
    log(f"$ {shlex.join(locate_cmd)}")
    try:
        locate = subprocess.run(locate_cmd, capture_output=True, text=True, timeout=30)
        zip_src = locate.stdout.strip()
        if locate.returncode != 0 or not zip_src:
            log(f"No ZIP found in {src_dir}: {locate.stderr.strip() or '(empty result)'}", "error")
            return False
    except subprocess.TimeoutExpired:
        log(f"Timed out locating ZIP in {src_dir}", "error")
        return False
    except Exception as e:
        log(f"docker exec failed locating ZIP: {e}", "error")
        return False

    cp_cmd = ["docker", "cp", f"{VELOCIRAPTOR_CONTAINER}:{zip_src}", out_path]
    log(f"$ {shlex.join(cp_cmd)}")
    try:
        result = subprocess.run(cp_cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            log(f"Failed to copy ZIP out of Velociraptor container: {result.stderr.strip()}", "error")
            return False
    except subprocess.TimeoutExpired:
        log("Timed out copying ZIP from Velociraptor container", "error")
        return False
    except Exception as e:
        log(f"docker cp failed copying ZIP: {e}", "error")
        return False

    try:
        os.chmod(out_path, 0o644)
    except OSError:
        pass

    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        log(f"Export completed but output file missing or empty: {out_path}", "error")
        return False

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    log(f"ZIP export ready at {out_path} ({size_mb:.1f} MB)", "success")
    return True


def cleanup_flow_export(client_id: str, flow_id: str, logger=None) -> None:
    """Remove the server-side ZIP Velociraptor created for a flow export.

    After `export_flow_to_zip()` has copied the ZIP out to the backend's
    workspace and it's been processed, we no longer need the original
    sitting in Velociraptor's `/var./downloads/{client_id}/{flow_id}/`
    directory taking up disk space. Best-effort — failures are logged
    but never raise.
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        else:
            print(f"[VELO-EXPORT] [{level}] {msg}", flush=True)

    script = (
        f"rm -rf /var./downloads/{client_id}/{flow_id} 2>/dev/null || true"
    )
    # docker exec into the running container instead of spinning up an
    # alpine sidecar — same reasoning as export_flow_to_zip(): airgapped
    # boxes don't have alpine pre-pulled and `docker run alpine` would
    # try to reach Docker Hub at runtime.
    cleanup_cmd = [
        "docker", "exec", VELOCIRAPTOR_CONTAINER, "sh", "-c", script,
    ]
    log(f"$ {shlex.join(cleanup_cmd)}")
    try:
        subprocess.run(
            cleanup_cmd,
            capture_output=True, text=True, timeout=60
        )
        log(f"Removed Velociraptor-side export dir for flow {flow_id}")
    except Exception as e:
        log(f"Could not remove Velociraptor-side export dir: {e}", "warning")


def cancel_flow(client_id: str, flow_id: str, logger=None) -> bool:
    """Send Velociraptor a CancelFlow request via VQL — stops a running collection.

    Used by the workflow Stop button across all KAPE / agentic / scheduled
    paths so the actual collection on the endpoint terminates, not just our
    local poll. Best-effort: never raises. Returns True on apparent success.

    Mirrors the in-line VQL the agentic pipeline already issues from
    `agentic.collectors.cancel_collections` — pulled out here so any caller
    can use it without importing from agentic.
    """
    def log(msg, level="info"):
        if logger:
            try:
                logger(msg, level)
            except Exception:
                pass
        else:
            print(f"[VELO-CANCEL] [{level}] {msg}", flush=True)

    if not client_id or not flow_id:
        return False

    channel = setup_velociraptor_connection()
    if not channel:
        log("Could not connect to Velociraptor to cancel flow", "warning")
        return False

    try:
        from pyvelociraptor.api_pb2 import VQLCollectorArgs, VQLRequest
        from pyvelociraptor.api_pb2_grpc import APIStub
    except ImportError:
        # Fall back to the import shape the agentic collectors use.
        from services.agentic.collectors import api_pb2, api_pb2_grpc  # type: ignore
        VQLCollectorArgs = api_pb2.VQLCollectorArgs
        VQLRequest = api_pb2.VQLRequest
        APIStub = api_pb2_grpc.APIStub

    try:
        stub = APIStub(channel)
        query = (
            f"SELECT cancel_flow(client_id='{client_id}', flow_id='{flow_id}') "
            f"FROM scope()"
        )
        request_obj = VQLCollectorArgs(
            max_wait=10,
            max_row=10,
            Query=[VQLRequest(VQL=query)],
        )
        for _ in stub.Query(request_obj, timeout=15):
            pass
        log(f"Sent CancelFlow for {flow_id} on {client_id}")
        return True
    except Exception as e:
        log(f"Could not cancel flow {flow_id} on {client_id}: {e}", "warning")
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass


def tools_not_served_locally():
    """Return names of Velociraptor tools that have an upstream download URL but
    are NOT served locally.

    When a hunt runs an artifact needing one of these, Velociraptor has the
    ENDPOINT fetch the tool from that URL at collection time — which fails on an
    air-gapped network with a confusing DNS/timeout error. Best-effort; returns
    [] on any error.
    """
    channel = setup_velociraptor_connection()
    if not channel:
        return []
    try:
        stub = api_pb2_grpc.APIStub(channel)
        vql = ("SELECT name, url, serve_locally FROM inventory() "
               "WHERE NOT serve_locally AND url =~ 'https?://'")
        req = api_pb2.VQLCollectorArgs(
            max_wait=20, max_row=500,
            Query=[api_pb2.VQLRequest(VQL=vql)],
        )
        names = []
        for resp in stub.Query(req, timeout=30):
            if resp.Response:
                try:
                    for row in json.loads(resp.Response):
                        n = row.get("name")
                        if n:
                            names.append(n)
                except (json.JSONDecodeError, ValueError):
                    pass
        return names
    except Exception:
        return []
    finally:
        try:
            channel.close()
        except Exception:
            pass


def hunt_tool_preflight(logger):
    """Clear pre-hunt error handling for the air-gap tool case.

    If endpoint tools aren't served locally AND there's no internet, warn —
    naming the at-risk tools — so a failed collection reads as "tool X not
    served locally / needs internet" instead of a cryptic endpoint DNS error.
    It's a warning, not a hard stop: the hunt may not use any of those tools.
    """
    try:
        from services.connectivity import has_internet
        missing = tools_not_served_locally()
        if not missing or has_internet():
            return
        shown = ", ".join(missing[:8]) + ("…" if len(missing) > 8 else "")
        logger(
            f"⚠ {len(missing)} tool(s) are not served locally and there is no "
            f"internet ({shown}). Any artifact that needs one of these will fail "
            f"on the endpoint. Fix: run Settings → Maintenance → Refresh Tool "
            f"Inventory while online, then re-run.",
            "warning",
        )
    except Exception:
        pass


def purge_velociraptor_data(logger=None, delete_flows=True,
                            delete_monitoring=True, delete_hunts=True):
    """Safely remove COLLECTED DATA from the Velociraptor server while keeping
    every client enrolled.

    Uses the server's own VQL deletion primitives over the gRPC API — the same
    logic as the Server.Utils.DeleteManyFlows / Server.Utils.DeleteMonitoringData
    / Server.Hunts.CancelAndDelete server artifacts — so the datastore index
    stays consistent. We deliberately do NOT `rm -rf` the datastore folders:
    that leaves dangling flow/hunt index entries and can corrupt the store.

    - flows:      flow_delete() for every flow of every client. This is the
                  bulk of the datastore (clients/<id>/artifacts/).
    - monitoring: file_store_delete() over clients/<id>/monitoring[_logs]/**.
    - hunts:      hunt_delete(really_do_it=true) for every hunt.

    Client identity (client_info/) and registration are untouched, so clients
    stay enrolled and visible — only their collected data is removed. The
    standalone `velociraptor query` CLI can't see the live client index, which
    is why the old docker-exec purge silently freed nothing; the gRPC API runs
    in the proper server context. Best-effort, never raises. Returns counts.
    """
    def log(msg, level="info"):
        if logger:
            try:
                logger(msg, level)
            except Exception:
                pass
        else:
            print(f"[VELO-PURGE] [{level}] {msg}", flush=True)

    out = {"hunts": 0, "flows": 0, "data_files": 0, "monitoring": 0, "errors": []}
    channel = setup_velociraptor_connection()
    if not channel:
        log("Could not connect to Velociraptor — skipping data purge", "warning")
        out["errors"].append("no connection")
        return out

    def _run(vql, timeout):
        stub = api_pb2_grpc.APIStub(channel)
        req = api_pb2.VQLCollectorArgs(
            max_wait=10, max_row=2000000,
            Query=[api_pb2.VQLRequest(VQL=vql)],
        )
        rows = []
        for resp in stub.Query(req, timeout=timeout):
            if resp.Response:
                try:
                    r = json.loads(resp.Response)
                    if isinstance(r, list):
                        rows.extend(r)
                except json.JSONDecodeError:
                    pass
        return rows

    try:
        # 1. Live hunts — hunt_delete also removes their per-client collected
        #    files (when the hunt metadata still exists).
        if delete_hunts:
            try:
                log("Deleting hunts…")
                rows = _run(
                    "SELECT hunt_id, "
                    "hunt_delete(hunt_id=hunt_id, really_do_it=true) AS deleted "
                    "FROM hunts()",
                    timeout=600,
                )
                out["hunts"] = len(rows)
                log(f"Deleted {out['hunts']} hunt(s)", "success")
            except Exception as e:
                log(f"Hunt deletion error: {e}", "warning")
                out["errors"].append(f"hunts: {e}")

        # 2. Live flows — flow_delete removes the collection metadata + files.
        if delete_flows:
            try:
                log("Deleting tracked flows…")
                rows = _run(
                    "SELECT client_id, session_id, "
                    "flow_delete(client_id=client_id, flow_id=session_id, really_do_it=true) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT client_id, session_id FROM flows(client_id=client_id) }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["flows"] = len(rows)
                log(f"Deleted {out['flows']} tracked flow(s)", "success")
            except Exception as e:
                log(f"Flow deletion error: {e}", "warning")
                out["errors"].append(f"flows: {e}")

            # 3. Residual collected-result files. Hunt/flow deletion above
            #    leaves ORPHANED result files when the originating hunt/flow
            #    metadata is already gone (flows()/hunts() return nothing but
            #    clients/<id>/artifacts/ still holds gigabytes — e.g. repeated
            #    Windows.Hayabusa.Rules result sets). file_store_delete() is
            #    Velociraptor's own filestore API (same primitive the
            #    DeleteMonitoringData artifact uses), so this stays index-safe —
            #    NOT an rm -rf. Client identity is untouched.
            try:
                log("Sweeping residual collected-result files…")
                rows = _run(
                    "SELECT OSPath, file_store_delete(path=OSPath) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT OSPath FROM glob("
                    "globs=['/artifacts/**', '/collections/**', '/uploads/**', '/tmp/**'], "
                    "accessor='fs', root='/clients/' + client_id) WHERE NOT IsDir }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["data_files"] = len(rows)
                log(f"Removed {out['data_files']} residual result file(s)", "success")
            except Exception as e:
                log(f"Residual sweep error: {e}", "warning")
                out["errors"].append(f"residual: {e}")

        # 4. Client monitoring (event) data.
        if delete_monitoring:
            try:
                log("Deleting client monitoring data…")
                rows = _run(
                    "SELECT OSPath, file_store_delete(path=OSPath) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT OSPath FROM glob("
                    "globs=['/monitoring/**', '/monitoring_logs/**'], "
                    "accessor='fs', root='/clients/' + client_id) WHERE NOT IsDir }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["monitoring"] = len(rows)
                log(f"Deleted {out['monitoring']} monitoring file(s)", "success")
            except Exception as e:
                log(f"Monitoring deletion error: {e}", "warning")
                out["errors"].append(f"monitoring: {e}")
    finally:
        try:
            channel.close()
        except Exception:
            pass

    return out
