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

# Where Server.Utils.CreateMSI drops its output inside the Velociraptor
# container. Note the literal `/var.` — that is the real path on this image,
# not a typo.
_SERVER_COLLECTIONS = "/var./clients/server/collections"


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


def _discard(path):
    """Remove a staged file, ignoring the case where it never appeared."""
    try:
        os.remove(path)
    except OSError:
        pass


def purge_msi_collection_uploads():
    """Drop the MSI payloads left behind by past CreateMSI runs.

    Every generation schedules a fresh server-artifact collection, and each one
    parks a ~26 MB MSI under its own flow directory forever. Nothing read those
    copies — the file the Downloads page serves is the one copied out to
    CLIENT_INSTALLER_DIR — so on a box where operators pull the installer
    regularly they were pure growth (measured: 180 KB -> 53 MB over two
    downloads). Now each run leaves nothing, so successive builds overwrite
    rather than accumulate.

    Deletes only the `uploads/` subtree, and only from collections that
    actually hold an MSI. The flow's own record is left alone: Velociraptor's
    audit trail of what ran stays intact, and the bytes are what mattered.

    Best-effort by design — this is disk hygiene, and failing it must never
    fail the download or the upgrade that triggered it.
    """
    script = (
        f'n=0; '
        f'for d in {_SERVER_COLLECTIONS}/F.*/; do '
        f'  if ls "$d"uploads/scope/*.msi >/dev/null 2>&1; then '
        f'    rm -rf "$d"uploads && n=$((n+1)); '
        f'  fi; '
        f'done; echo "$n"'
    )
    try:
        result = subprocess.run(
            ["docker", "exec", VELOCIRAPTOR_CONTAINER, "sh", "-c", script],
            capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"[MSI-GEN] Upload purge failed: {result.stderr.strip()[:200]}",
                  flush=True)
            return 0
        purged = int((result.stdout or "0").strip() or 0)
        if purged:
            print(f"[MSI-GEN] Reclaimed MSI uploads from {purged} collection(s)",
                  flush=True)
        return purged
    except Exception as e:
        print(f"[MSI-GEN] Upload purge raised: {e}", flush=True)
        return 0


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

        # Copy to client_installers. Land it on a temp name in the SAME
        # directory and rename into place: every generation overwrites one
        # fixed path that the download route serves straight to the browser,
        # so writing in place means a second request can be handed a
        # half-written installer — and a truncated MSI fails on the endpoint,
        # not here. os.replace is atomic within a filesystem, so a reader sees
        # either the old file or the new one, never a partial. This matters
        # more now that a Velociraptor upgrade regenerates in the background.
        local_msi_path = os.path.join(CLIENT_INSTALLER_DIR, MSI_FILENAME)
        staged_path = local_msi_path + ".partial"

        copy_result = subprocess.run([
            "docker", "cp",
            f"{VELOCIRAPTOR_CONTAINER}:{msi_path_in_container}",
            staged_path
        ], capture_output=True, text=True, timeout=30)

        if copy_result.returncode != 0:
            print(f"[MSI-GEN] Copy failed: {copy_result.stderr}", flush=True)
            _discard(staged_path)
            return False

        if not (os.path.exists(staged_path) and os.path.getsize(staged_path) > 0):
            print("[MSI-GEN] Copy produced no data", flush=True)
            _discard(staged_path)
            return False

        file_size = os.path.getsize(staged_path)
        os.replace(staged_path, local_msi_path)
        print(f"[MSI-GEN] ✓ MSI ready: {local_msi_path} ({file_size} bytes)", flush=True)

        # The payload is now in CLIENT_INSTALLER_DIR; the server-side copy has
        # no further reader, so reclaim it instead of stacking another ~26 MB.
        purge_msi_collection_uploads()
        return True

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
