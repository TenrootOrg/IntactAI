#!/usr/bin/env python3
"""
Client Installer Service - Serve client installers with on-demand MSI generation
"""

import os
import subprocess
import json
import time
import yaml
import grpc
import traceback
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from config import VELOCIRAPTOR_CONTAINER, VELOCIRAPTOR_API_CONFIG_PATH

# Client installers directory (mounted from host)
CLIENT_INSTALLER_DIR = "/app/client_installers"

# MSI filename (always same name, overwritten on regeneration)
MSI_FILENAME = "velociraptor-client-windows.msi"


def setup_velociraptor_connection():
    """Setup gRPC connection to Velociraptor API"""
    try:
        config_path = "/tmp/api.config.yaml"

        if not os.path.exists(config_path):
            print("[MSI-GEN] Copying API config from Velociraptor container...", flush=True)
            result = subprocess.run([
                "docker", "exec", VELOCIRAPTOR_CONTAINER,
                "cat", VELOCIRAPTOR_API_CONFIG_PATH
            ], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                with open(config_path, 'w') as f:
                    f.write(result.stdout)
            else:
                print(f"[MSI-GEN] Failed to copy config: {result.stderr}", flush=True)
                return None

        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )

        max_message_size = 100 * 1024 * 1024  # 100MB
        options = (
            ("grpc.ssl_target_name_override", "VelociraptorServer"),
            ("grpc.max_receive_message_length", max_message_size),
            ("grpc.max_send_message_length", max_message_size),
        )
        channel = grpc.secure_channel(config["api_connection_string"], creds, options)
        return channel

    except Exception as e:
        print(f"[MSI-GEN] Connection setup failed: {e}", flush=True)
        return None


def generate_msi_via_artifact():
    """Generate MSI using Server.Utils.CreateMSI artifact via gRPC API"""
    print("[MSI-GEN] Starting MSI generation...", flush=True)

    try:
        channel = setup_velociraptor_connection()
        if not channel:
            print("[MSI-GEN] Failed to connect to Velociraptor", flush=True)
            return False

        stub = api_pb2_grpc.APIStub(channel)

        # Schedule server artifact collection via gRPC
        vql = 'SELECT collect_client(client_id="server", artifacts=["Server.Utils.CreateMSI"]) AS Flow FROM scope()'

        request = api_pb2.VQLCollectorArgs(
            max_wait=60,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )

        print("[MSI-GEN] Scheduling Server.Utils.CreateMSI collection...", flush=True)

        flow_id = None
        for response in stub.Query(request, timeout=60):
            if response.Response:
                try:
                    result = json.loads(response.Response)
                    if isinstance(result, list) and len(result) > 0:
                        flow_data = result[0].get('Flow', {})
                        flow_id = flow_data.get('flow_id')
                        print(f"[MSI-GEN] Flow created: {flow_id}", flush=True)
                except Exception as e:
                    print(f"[MSI-GEN] Parse error: {e}", flush=True)

        channel.close()

        if not flow_id:
            print("[MSI-GEN] No flow_id returned", flush=True)
            return False

        # Wait for collection to complete
        print("[MSI-GEN] Waiting for MSI generation...", flush=True)
        time.sleep(15)

        # Copy the MSI from the collection folder
        return copy_msi_from_collection(flow_id)

    except Exception as e:
        print(f"[MSI-GEN] Error: {e}", flush=True)
        traceback.print_exc()
        return False


def copy_msi_from_collection(flow_id):
    """Copy MSI from server artifact collection folder"""
    print(f"[MSI-GEN] Looking for MSI in flow {flow_id}...", flush=True)

    try:
        # MSI is stored in: /var./clients/server/collections/{flow_id}/uploads/scope/
        msi_pattern = f"/var./clients/server/collections/{flow_id}/uploads/scope/*.msi"

        result = subprocess.run([
            "docker", "exec", VELOCIRAPTOR_CONTAINER,
            "sh", "-c", f"ls -1 {msi_pattern} 2>/dev/null | head -1"
        ], capture_output=True, text=True, timeout=10)

        msi_path_in_container = result.stdout.strip()

        if not msi_path_in_container:
            print(f"[MSI-GEN] No MSI found in collection {flow_id}", flush=True)
            return False

        print(f"[MSI-GEN] Found: {msi_path_in_container}", flush=True)

        # Copy to client_installers
        local_msi_path = os.path.join(CLIENT_INSTALLER_DIR, MSI_FILENAME)

        copy_result = subprocess.run([
            "docker", "cp",
            f"{VELOCIRAPTOR_CONTAINER}:{msi_path_in_container}",
            local_msi_path
        ], capture_output=True, text=True, timeout=30)

        if copy_result.returncode != 0:
            print(f"[MSI-GEN] Copy failed: {copy_result.stderr}", flush=True)
            return False

        if os.path.exists(local_msi_path):
            file_size = os.path.getsize(local_msi_path)
            print(f"[MSI-GEN] ✓ MSI ready: {local_msi_path} ({file_size} bytes)", flush=True)
            return True

        return False

    except Exception as e:
        print(f"[MSI-GEN] Error: {e}", flush=True)
        traceback.print_exc()
        return False


def download_client_installer(platform):
    """Get the path to a client installer, generating MSI on-demand if needed

    Args:
        platform: One of 'windows-msi', 'windows-exe', 'windows', 'linux', 'mac'

    Returns:
        str: Path to the installer file, or None if not found
    """
    print(f"[CLIENT-DL] Request for {platform} installer", flush=True)

    # Map platform names to actual filenames
    platform_map = {
        "windows-msi": "velociraptor-client-windows.msi",
        "windows": "velociraptor-client-windows.exe",  # Fallback to EXE for 'windows'
        "windows-exe": "velociraptor-client-windows.exe",
        "linux": "velociraptor-client-linux",
        "mac": "velociraptor-client-mac"
    }

    if platform not in platform_map:
        print(f"[CLIENT-DL] Invalid platform: {platform}", flush=True)
        return None

    filename = platform_map[platform]
    file_path = os.path.join(CLIENT_INSTALLER_DIR, filename)

    # For MSI, generate on-demand if not present or generate fresh each time
    if platform == "windows-msi":
        print(f"[CLIENT-DL] MSI requested, generating on-demand...", flush=True)
        if generate_msi_via_artifact():
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                file_size = os.path.getsize(file_path)
                print(f"[CLIENT-DL] ✓ MSI ready: {filename} ({file_size} bytes)", flush=True)
                return file_path
        else:
            print(f"[CLIENT-DL] MSI generation failed, checking for existing file...", flush=True)

    # Check if file exists and has content
    if os.path.exists(file_path):
        file_size = os.path.getsize(file_path)
        if file_size > 0:
            print(f"[CLIENT-DL] ✓ Serving {filename} ({file_size} bytes)", flush=True)
            return file_path
        else:
            print(f"[CLIENT-DL] ✗ File is empty: {filename}", flush=True)
            return None
    else:
        print(f"[CLIENT-DL] ✗ File not found: {filename}", flush=True)
        return None


# Legacy function stubs (for backwards compatibility)
def generate_all_client_installers(logger_func=None):
    """Legacy function - clients are now generated during installation"""
    def log(message, level="info"):
        print(f"[CLIENT-GEN] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[CLIENT-GEN] {message}", level)
            except:
                pass

    log("Client installers are pre-generated during platform installation")
    log(f"Checking for pre-generated clients in {CLIENT_INSTALLER_DIR}...")

    results = {
        "windows_exe": {"success": False},
        "linux": {"success": False},
        "mac": {"success": False}
    }

    platform_files = {
        "windows_exe": "velociraptor-client-windows.exe",
        "linux": "velociraptor-client-linux",
        "mac": "velociraptor-client-mac"
    }

    success_count = 0
    for platform_name, filename in platform_files.items():
        file_path = os.path.join(CLIENT_INSTALLER_DIR, filename)
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            file_size = os.path.getsize(file_path)
            log(f"✓ {platform_name.upper()}: Found ({file_size} bytes)")
            results[platform_name]["success"] = True
            results[platform_name]["path"] = file_path
            success_count += 1
        else:
            log(f"✗ {platform_name.upper()}: Not found", "warning")

    if success_count > 0:
        log(f"Found {success_count}/3 pre-generated client installers")
        return {
            "success": True,
            "results": results,
            "message": f"{success_count}/3 clients available"
        }
    else:
        log("No pre-generated clients found!", "error")
        return {
            "success": False,
            "error": "No clients available",
            "results": results
        }


# Backwards compatibility alias
generate_windows_msi_clients = generate_all_client_installers
