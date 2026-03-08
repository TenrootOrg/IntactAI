#!/usr/bin/env python3
"""
Offline Collector Generator - Generate and package offline collectors
"""

import os
import json
import time
import shutil
import subprocess
import zipfile
from datetime import datetime

from services.offline_collector.constants import (
    COLLECTOR_OUTPUT_DIR,
    VELOCIRAPTOR_CONTAINER,
    VELO_CLIENT_PATHS,
    DEFAULT_ARTIFACTS,
    ONLINE_REQUIRED_ARTIFACTS,
    EMBEDDABLE_TOOLS,
    TOOL_DEPENDENT_ARTIFACTS
)
from services.offline_collector.config import get_config


def get_blueprint_as_config(blueprint_id):
    """Try to load a blueprint as an offline collector config.

    This allows using unified forensics blueprints for offline collector generation.
    """
    try:
        from routes.blueprint_routes import load_velociraptor_blueprints, load_agentic_blueprints

        # Check velociraptor blueprints
        velo_blueprints = load_velociraptor_blueprints()
        for bp in velo_blueprints:
            if bp.get('id') == blueprint_id:
                return {
                    'config_id': bp['id'],
                    'config_name': bp.get('name', blueprint_id),
                    'artifacts': bp.get('artifacts', []),
                    'parameters': {
                        'CpuLimit': bp.get('settings', {}).get('cpu_limit', 50),
                        'MaxExecutionTimeInSeconds': bp.get('settings', {}).get('timeout', 3600)
                    }
                }

        # Check agentic blueprints
        agentic_blueprints = load_agentic_blueprints()
        for bp in agentic_blueprints:
            if bp.get('id') == blueprint_id:
                return {
                    'config_id': bp['id'],
                    'config_name': bp.get('name', blueprint_id),
                    'artifacts': bp.get('artifacts', []),
                    'parameters': {
                        'CpuLimit': bp.get('settings', {}).get('cpu_limit', 50),
                        'MaxExecutionTimeInSeconds': bp.get('settings', {}).get('timeout', 3600)
                    }
                }

        return None
    except Exception as e:
        print(f"[OFFLINE] Error loading blueprint {blueprint_id}: {e}", flush=True)
        return None


def generate_collector(config_id, os_type="windows"):
    """Generate an offline collector using Velociraptor's Generic Collector.

    The Generic Collector has NO size limit (unlike platform-specific collectors
    which are limited to ~80KB embedded config). It also embeds tools that have
    serve_locally=true configured on the server.

    Args:
        config_id: The configuration ID or blueprint ID to use
        os_type: Target OS (windows, linux, darwin) - used for naming only

    Returns:
        dict with success status, file_id, file_name, file_path
    """
    import yaml
    import grpc
    from pyvelociraptor import api_pb2, api_pb2_grpc

    print(f"[OFFLINE] Generating Generic Collector (no size limit) for config={config_id}", flush=True)

    try:
        # First try to load as a blueprint (unified forensics system)
        config = get_blueprint_as_config(config_id)

        # Fall back to old config system if not a blueprint
        if not config:
            config = get_config(config_id)

        if not config:
            return {"success": False, "error": f"Configuration or blueprint '{config_id}' not found. Make sure you've selected a valid blueprint."}

        # Create output directory
        os.makedirs(COLLECTOR_OUTPUT_DIR, exist_ok=True)

        config_name = config.get("config_name", "Collection")
        safe_name = config_name.replace(" ", "_").replace("/", "-").replace("[", "").replace("]", "").replace("(", "").replace(")", "")

        # Get artifacts and parameters
        artifacts = config.get("artifacts", DEFAULT_ARTIFACTS)
        parameters = config.get("parameters", {})

        # Filter out truly online-only artifacts
        filtered_artifacts = [a for a in artifacts if a not in ONLINE_REQUIRED_ARTIFACTS]
        skipped = [a for a in artifacts if a in ONLINE_REQUIRED_ARTIFACTS]

        if skipped:
            print(f"[OFFLINE] Skipped {len(skipped)} online-only artifacts: {skipped}", flush=True)

        print(f"[OFFLINE] Artifacts to include: {len(filtered_artifacts)}", flush=True)

        # Setup gRPC connection to Velociraptor
        print(f"[OFFLINE] Connecting to Velociraptor API...", flush=True)

        config_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} cat /velociraptor/api.config.yaml"
        config_result = subprocess.run(config_cmd, shell=True, capture_output=True, text=True, timeout=10)

        if config_result.returncode != 0:
            print(f"[OFFLINE] Failed to get API config", flush=True)
            return {"success": False, "error": "Failed to get Velociraptor API config"}

        api_config = yaml.safe_load(config_result.stdout)

        creds = grpc.ssl_channel_credentials(
            root_certificates=api_config["ca_certificate"].encode("utf8"),
            private_key=api_config["client_private_key"].encode("utf8"),
            certificate_chain=api_config["client_cert"].encode("utf8"),
        )

        max_message_size = 100 * 1024 * 1024  # 100MB
        channel = grpc.secure_channel(
            api_config["api_connection_string"],
            creds,
            (
                ("grpc.ssl_target_name_override", "VelociraptorServer"),
                ("grpc.max_receive_message_length", max_message_size),
                ("grpc.max_send_message_length", max_message_size),
            )
        )
        stub = api_pb2_grpc.APIStub(channel)

        # Build artifacts list as VQL array
        artifacts_vql = "[" + ", ".join(f'"{a}"' for a in filtered_artifacts) + "]"

        # Use "Generic" OS type - this has NO size limit and embeds tools
        vql_query = f'''SELECT collect_client(
            client_id="server",
            artifacts="Server.Utils.CreateCollector",
            spec=dict(
                `Server.Utils.CreateCollector`=dict(
                    OS="Generic",
                    artifacts={artifacts_vql},
                    parameters=dict(),
                    target="ZIP",
                    target_args=dict(Filename="Collector_{safe_name}"),
                    opt_verbose="Y",
                    opt_banner="N",
                    opt_prompt="N",
                    opt_admin="Y",
                    opt_cpu_limit={parameters.get('CpuLimit', 50)},
                    opt_timeout={parameters.get('MaxExecutionTimeInSeconds', 3600)}
                )
            )
        ) AS Collection FROM scope()'''

        print(f"[OFFLINE] Running Server.Utils.CreateCollector with OS=Generic...", flush=True)

        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(VQL=vql_query)]
        )

        flow_id = None

        # Execute the collector creation
        for response in stub.Query(request, timeout=300):
            if response.log:
                print(f"[OFFLINE] Server log: {response.log}", flush=True)

            if response.Response:
                print(f"[OFFLINE] Response: {response.Response[:300]}", flush=True)
                try:
                    parsed = json.loads(response.Response)
                    if isinstance(parsed, list) and len(parsed) > 0:
                        collection_result = parsed[0].get("Collection")
                        if collection_result and isinstance(collection_result, dict):
                            flow_id = collection_result.get("flow_id") or collection_result.get("session_id")
                            if not flow_id and "request" in collection_result:
                                flow_id = collection_result["request"].get("flow_id")
                except json.JSONDecodeError:
                    continue

        channel.close()

        if not flow_id:
            print(f"[OFFLINE] No flow_id returned", flush=True)
            return {"success": False, "error": "Velociraptor did not return a flow ID"}

        print(f"[OFFLINE] Collector creation flow: {flow_id}", flush=True)
        print(f"[OFFLINE] Waiting for collector compilation...", flush=True)

        # Wait for the collector to be generated
        datastore_path = "/var."
        collector_base_path = f"{datastore_path}/clients/server/collections/{flow_id}/uploads"
        max_wait = 180  # 3 minutes for large collectors
        poll_interval = 5
        elapsed = 0
        files_in_upload = []

        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval

            # Check flow state
            flow_json_path = f"{datastore_path}/clients/server/collections/{flow_id}.json.db"
            flow_check_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} cat \"{flow_json_path}\" 2>/dev/null"
            flow_result = subprocess.run(flow_check_cmd, shell=True, capture_output=True, text=True, timeout=10)

            if flow_result.returncode == 0 and flow_result.stdout.strip():
                try:
                    flow_data = json.loads(flow_result.stdout.strip())
                    flow_state = flow_data.get("state", "")
                    flow_status = flow_data.get("status", "")

                    if flow_state == "ERROR":
                        print(f"[OFFLINE] Flow ERROR: {flow_status}", flush=True)
                        return {"success": False, "error": f"Collector creation failed: {flow_status}"}
                    elif flow_state == "FINISHED":
                        print(f"[OFFLINE] Flow completed successfully", flush=True)
                        break
                except json.JSONDecodeError:
                    pass

            # Check for generated files
            list_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} find {collector_base_path} -type f 2>/dev/null"
            list_result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True, timeout=30)

            files_in_upload = list_result.stdout.strip().split('\n') if list_result.stdout.strip() else []
            files_in_upload = [f for f in files_in_upload if f]

            if files_in_upload:
                # Look for the Generic collector file (ends with .zip typically)
                collector_files = [f for f in files_in_upload if 'Collector' in f or f.endswith('.zip')]
                if collector_files:
                    print(f"[OFFLINE] Collector generating... ({elapsed}s)", flush=True)

        # Final file check
        if not files_in_upload:
            list_cmd = f"docker exec {VELOCIRAPTOR_CONTAINER} find {collector_base_path} -type f 2>/dev/null"
            list_result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True, timeout=30)
            files_in_upload = list_result.stdout.strip().split('\n') if list_result.stdout.strip() else []
            files_in_upload = [f for f in files_in_upload if f]

        print(f"[OFFLINE] Files in upload dir: {files_in_upload}", flush=True)

        # Find the collector file
        collector_path_in_container = None
        for f in files_in_upload:
            if 'Collector' in f and f.endswith('.zip'):
                collector_path_in_container = f
                break

        if not collector_path_in_container and files_in_upload:
            collector_path_in_container = files_in_upload[0]

        if not collector_path_in_container:
            return {"success": False, "error": "Collector file not found in Velociraptor output"}

        print(f"[OFFLINE] Found collector at: {collector_path_in_container}", flush=True)

        # Create temp directory for bundle
        bundle_dir = os.path.join(COLLECTOR_OUTPUT_DIR, f"bundle_generic_{safe_name}_{int(time.time())}")
        os.makedirs(bundle_dir, exist_ok=True)

        # Copy the generic collector file
        collector_local = os.path.join(bundle_dir, "collector_config")
        copy_cmd = f"docker cp '{VELOCIRAPTOR_CONTAINER}:{collector_path_in_container}' '{collector_local}'"
        copy_result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True, timeout=60)

        if copy_result.returncode != 0:
            shutil.rmtree(bundle_dir, ignore_errors=True)
            return {"success": False, "error": f"Failed to copy collector: {copy_result.stderr}"}

        print(f"[OFFLINE] Copied generic collector config ({os.path.getsize(collector_local)} bytes)", flush=True)

        # Copy Velociraptor binary for the target OS
        if os_type == "windows":
            velo_binary_name = "velociraptor.exe"
            velo_src = VELO_CLIENT_PATHS["windows"]
        elif os_type == "darwin":
            velo_binary_name = "velociraptor"
            velo_src = VELO_CLIENT_PATHS["darwin"]
        else:
            velo_binary_name = "velociraptor"
            velo_src = VELO_CLIENT_PATHS["linux"]

        velo_dest = os.path.join(bundle_dir, velo_binary_name)

        # Try to copy velociraptor binary
        if os.path.exists(velo_src) and os.path.getsize(velo_src) > 1000000:
            shutil.copy2(velo_src, velo_dest)
            print(f"[OFFLINE] Copied Velociraptor binary: {velo_binary_name}", flush=True)
        else:
            shutil.rmtree(bundle_dir, ignore_errors=True)
            return {"success": False, "error": f"Velociraptor binary not found: {velo_src}"}

        # Create launch script
        if os_type == "windows":
            script_name = "Run_Collector.bat"
            # Escape parentheses in config name for BAT compatibility
            safe_bat_name = config_name.replace('(', '^(').replace(')', '^)')
            # Full BAT with escaped config name
            script_content = (
                '@echo off\r\n'
                'cd /d "%~dp0"\r\n'
                'echo.\r\n'
                'echo ============================================\r\n'
                f'echo   {safe_bat_name}\r\n'
                'echo   Velociraptor Collector\r\n'
                'echo ============================================\r\n'
                'echo   Directory: %CD%\r\n'
                'echo ============================================\r\n'
                'echo.\r\n'
                'if not exist velociraptor.exe (\r\n'
                '  echo ERROR: velociraptor.exe not found!\r\n'
                '  goto done\r\n'
                ')\r\n'
                'if not exist collector_config (\r\n'
                '  echo ERROR: collector_config not found!\r\n'
                '  goto done\r\n'
                ')\r\n'
                'echo [+] Starting collection...\r\n'
                'echo.\r\n'
                'velociraptor.exe -- --embedded_config collector_config\r\n'
                'echo.\r\n'
                'echo ============================================\r\n'
                'echo   Collection finished!\r\n'
                'echo   Look for Collection-*.zip in this folder\r\n'
                'echo ============================================\r\n'
                ':done\r\n'
                'echo.\r\n'
                'pause\r\n'
            )
        else:
            script_name = "run_collector.sh"
            script_content = f'''#!/bin/bash
# ============================================
# {config_name}
# Generic Collector (embedded tools, no size limit)
# ============================================
# Run with: sudo ./run_collector.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "============================================"
echo "  {config_name}"
echo "  Velociraptor Generic Collector"
echo "============================================"
echo ""

if [ ! -f "./velociraptor" ]; then
    echo "ERROR: velociraptor binary not found!"
    exit 1
fi

chmod +x ./velociraptor

echo "[*] Starting collection with embedded tools..."
./velociraptor -- --embedded_config collector_config

echo ""
echo "============================================"
echo "Collection complete!"
echo "Look for Collection-*.zip in this directory."
echo "============================================"
'''

        script_path = os.path.join(bundle_dir, script_name)
        if os_type == "windows":
            # Write BAT as binary - content already has CRLF
            with open(script_path, 'wb') as f:
                f.write(script_content.encode('ascii'))
        else:
            with open(script_path, 'w') as f:
                f.write(script_content)
            os.chmod(script_path, 0o755)

        # Create final ZIP bundle
        output_filename = f"OfflineCollector_{safe_name}_{os_type}.zip"
        output_path = os.path.join(COLLECTOR_OUTPUT_DIR, output_filename)

        if os.path.exists(output_path):
            os.remove(output_path)

        print(f"[OFFLINE] Creating ZIP bundle: {output_filename}", flush=True)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(velo_dest, velo_binary_name)
            zf.write(collector_local, "collector_config")
            zf.write(script_path, script_name)

        # Cleanup temp directory
        shutil.rmtree(bundle_dir, ignore_errors=True)

        if not os.path.exists(output_path):
            return {"success": False, "error": "ZIP file not created"}

        file_size = os.path.getsize(output_path)
        print(f"[OFFLINE] Verified file ready: {output_filename} ({file_size} bytes)", flush=True)

        return {
            "success": True,
            "file_id": f"{safe_name}_{os_type}",
            "file_name": output_filename,
            "file_path": output_path,
            "file_size": file_size,
            "type": "generic",
            "note": f"Generic Collector with embedded tools. Extract and run {script_name} as admin."
        }

    except grpc.RpcError as e:
        error_msg = f"gRPC error: {e.details() if hasattr(e, 'details') else str(e)}"
        print(f"[OFFLINE] {error_msg}", flush=True)
        return {"success": False, "error": error_msg}

    except subprocess.TimeoutExpired:
        print(f"[OFFLINE] Generation timed out", flush=True)
        return {"success": False, "error": "Collector generation timed out"}

    except Exception as e:
        print(f"[OFFLINE] Error generating collector: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}


def create_collection_script(config, file_id, os_type, output_path):
    """Create a ZIP bundle with Velociraptor binary and collection script

    For script-based collectors (fallback mode), we filter out artifacts that
    require downloading external tools since the collector must work fully offline.
    """
    try:
        raw_artifacts = config.get("artifacts", DEFAULT_ARTIFACTS)
        config_name = config.get("config_name", "Collection")
        parameters = config.get("parameters", {})

        # Filter out artifacts that require internet/downloads
        # These artifacts download external tools and won't work offline
        artifacts = [a for a in raw_artifacts if a not in ONLINE_REQUIRED_ARTIFACTS]
        skipped_artifacts = [a for a in raw_artifacts if a in ONLINE_REQUIRED_ARTIFACTS]

        if skipped_artifacts:
            print(f"[OFFLINE] Skipped {len(skipped_artifacts)} online-only artifacts: {skipped_artifacts}", flush=True)
            print(f"[OFFLINE] Collecting {len(artifacts)} offline-safe artifacts", flush=True)

        # Determine paths based on OS - use consistent "velociraptor_client" name
        if os_type == "windows":
            velo_binary_name = "velociraptor_client.exe"
            script_name = "Collect.bat"
            velo_src = VELO_CLIENT_PATHS["windows"]
        elif os_type == "darwin":
            velo_binary_name = "velociraptor_client"
            script_name = "collect.sh"
            velo_src = VELO_CLIENT_PATHS["darwin"]
        else:
            velo_binary_name = "velociraptor_client"
            script_name = "collect.sh"
            velo_src = VELO_CLIENT_PATHS["linux"]

        # Create temp directory for bundle
        bundle_dir = os.path.join(COLLECTOR_OUTPUT_DIR, f"bundle_{file_id}")
        os.makedirs(bundle_dir, exist_ok=True)

        # Copy Velociraptor binary - try multiple sources
        velo_dest = os.path.join(bundle_dir, velo_binary_name)
        binary_found = False

        # Try 1: Copy from nginx container
        copy_cmd = f"docker cp mssp_nginx:{velo_src} {velo_dest}"
        result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and os.path.exists(velo_dest) and os.path.getsize(velo_dest) > 1000000:
            binary_found = True
            print(f"[OFFLINE] Got binary from nginx container", flush=True)

        # Try 2: Direct path from VELO_CLIENT_PATHS (mounted volume)
        if not binary_found:
            if os.path.exists(velo_src) and os.path.getsize(velo_src) > 1000000:
                shutil.copy2(velo_src, velo_dest)
                binary_found = True
                print(f"[OFFLINE] Got binary from mounted downloads: {velo_src}", flush=True)

        # Try 3: Copy from Velociraptor container (Linux only)
        if not binary_found and os_type == "linux":
            copy_cmd = f"docker cp {VELOCIRAPTOR_CONTAINER}:/velociraptor/velociraptor {velo_dest}"
            result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0 and os.path.exists(velo_dest) and os.path.getsize(velo_dest) > 1000000:
                binary_found = True
                print(f"[OFFLINE] Got binary from Velociraptor container", flush=True)

        if not binary_found:
            shutil.rmtree(bundle_dir, ignore_errors=True)
            return {"success": False, "error": f"Velociraptor binary not found for {os_type}. Expected at: {velo_src}"}

        print(f"[OFFLINE] Copied Velociraptor binary: {velo_dest} ({os.path.getsize(velo_dest)} bytes)", flush=True)

        if os_type == "windows":
            # Create pure batch file with progress indication and logging
            script_name = "Collect.bat"
            script_path = os.path.join(bundle_dir, script_name)

            # Safe name for files
            safe_blueprint = config_name.replace(" ", "_").replace("[", "").replace("]", "").replace("/", "-")

            # Build skipped artifacts note
            skipped_note = ""
            if skipped_artifacts:
                skipped_note = f'''
echo.
echo [!] NOTE: {len(skipped_artifacts)} artifacts skipped (require internet):
'''
                for sk in skipped_artifacts:
                    skipped_note += f'echo     - {sk}\n'
                skipped_note += 'echo.\n'

            # Build artifact collection commands - simplified for reliability
            total_artifacts = len(artifacts)
            artifact_commands = []
            for idx, artifact in enumerate(artifacts, 1):
                artifact_commands.append(f'echo.')
                artifact_commands.append(f'echo [{idx}/{total_artifacts}] {artifact}')
                artifact_commands.append(f'velociraptor_client.exe --nobanner artifacts collect "{artifact}" --output "%ZIP_FILE%" --format jsonl --cpu_limit {parameters.get("CpuLimit", 80)} --timeout {parameters.get("MaxExecutionTimeInSeconds", 300)}')

            artifact_section = '\n'.join(artifact_commands)

            script_content = f'''@echo off
title {config_name} - Velociraptor Collector
cd /d "%~dp0"
echo.
echo ============================================
echo   {config_name}
echo   Velociraptor Offline Collector
echo ============================================
echo   Working directory: %CD%
echo ============================================
echo.
if not exist velociraptor_client.exe (
    echo ERROR: velociraptor_client.exe not found!
    echo Make sure you extracted ALL files from the ZIP.
    echo.
    dir
    goto :end
)
echo [+] Found Velociraptor binary
{skipped_note}
set "ZIP_FILE=%~dp0Collection-%COMPUTERNAME%-{safe_blueprint}.zip"
echo.
echo [*] Output: %ZIP_FILE%
echo [*] Artifacts: {total_artifacts}
echo.
{artifact_section}

echo.
echo ============================================
if exist "%ZIP_FILE%" (
    echo   COLLECTION COMPLETE
    echo   Output: %ZIP_FILE%
) else (
    echo   Collection may have failed.
)
echo ============================================
:end
echo.
pause
'''
            # Use CRLF line endings for Windows BAT files
            with open(script_path, 'w', newline='\r\n') as f:
                f.write(script_content)

        else:
            # Create shell script for Linux/Mac (binary is bundled)
            script_path = os.path.join(bundle_dir, script_name)
            artifacts_str = ' '.join(f'"{a}"' for a in artifacts)

            script_content = f'''#!/bin/bash
# ============================================
# {config_name}
# Velociraptor Offline Collection
# ============================================
#
# Generated: {datetime.now().isoformat()}
# Artifacts: {len(artifacts)}
#
# Extract this archive and run this script as root.
# The velociraptor binary is included - no download needed.
#
# Usage: sudo ./collect.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VELO_PATH="$SCRIPT_DIR/velociraptor_client"
OUTPUT_DIR="$SCRIPT_DIR/Collection_$(date +%Y%m%d_%H%M%S)"

echo ""
echo "============================================"
echo "  {config_name}"
echo "  Velociraptor Offline Collector"
echo "============================================"
echo ""

# Check for velociraptor_client binary
if [ ! -f "$VELO_PATH" ]; then
    echo "[-] ERROR: velociraptor_client binary not found!"
    echo "    Expected at: $VELO_PATH"
    echo ""
    echo "Make sure you extracted the entire archive."
    exit 1
fi

chmod +x "$VELO_PATH"
echo "[+] Found Velociraptor: $VELO_PATH"

# Create output directory
echo "[*] Creating output directory..."
mkdir -p "$OUTPUT_DIR"

echo ""
echo "[*] Configuration:"
echo "    Artifacts: {len(artifacts)}"
echo "    CPU Limit: {parameters.get('CpuLimit', 50)}%"
echo "    Timeout: {parameters.get('MaxExecutionTimeInSeconds', 3600)} seconds"
echo ""

# Artifacts to collect
ARTIFACTS=({artifacts_str})

echo "[*] Artifacts to collect:"
for artifact in "${{ARTIFACTS[@]}}"; do
    echo "    - $artifact"
done
echo ""

# Output file
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ZIP_FILE="$OUTPUT_DIR/Collection-$HOSTNAME-$TIMESTAMP.zip"

echo "[*] Starting collection..."
echo "    Output: $ZIP_FILE"
echo ""

# Run collection
"$VELO_PATH" artifacts collect "${{ARTIFACTS[@]}}" --output "$ZIP_FILE" --format jsonl --cpu_limit {parameters.get('CpuLimit', 50)} --timeout {parameters.get('MaxExecutionTimeInSeconds', 3600)} || true

# Check result
echo ""
if [ -f "$ZIP_FILE" ]; then
    SIZE=$(du -h "$ZIP_FILE" | cut -f1)
    echo "============================================"
    echo "  COLLECTION COMPLETE"
    echo "============================================"
    echo ""
    echo "Output file: $ZIP_FILE"
    echo "Size: $SIZE"
    echo ""
    echo "Transfer this ZIP file back to your MSSP platform"
    echo "and use 'Import Results' to analyze the data."
else
    echo "[-] Collection may have failed. Check errors above."
fi
'''
            with open(script_path, 'w') as f:
                f.write(script_content)
            os.chmod(script_path, 0o755)

        # Create ZIP bundle with binary and script (use consistent name to overwrite previous)
        safe_name = config_name.replace(" ", "_").replace("/", "-").replace("[", "").replace("]", "").replace("(", "").replace(")", "")
        zip_filename = f"OfflineCollector_{safe_name}_{os_type}.zip"
        zip_path = os.path.join(COLLECTOR_OUTPUT_DIR, zip_filename)

        # Remove existing file if present
        if os.path.exists(zip_path):
            os.remove(zip_path)

        print(f"[OFFLINE] Creating ZIP bundle: {zip_path}", flush=True)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add Velociraptor binary
            zf.write(velo_dest, velo_binary_name)
            # Add collection script
            zf.write(script_path, script_name)

        # Clean up temp bundle directory
        shutil.rmtree(bundle_dir, ignore_errors=True)

        # CRITICAL: Verify file exists and has content before returning
        if not os.path.exists(zip_path):
            print(f"[OFFLINE] ERROR: ZIP file not found after creation: {zip_path}", flush=True)
            return {"success": False, "error": "ZIP file not found after creation"}

        zip_size = os.path.getsize(zip_path)
        if zip_size == 0:
            print(f"[OFFLINE] ERROR: ZIP file is empty: {zip_path}", flush=True)
            return {"success": False, "error": "ZIP file is empty"}

        # Add small buffer to ensure filesystem sync
        time.sleep(0.5)

        print(f"[OFFLINE] Verified ZIP bundle ready: {zip_filename} ({zip_size} bytes)", flush=True)

        # Use consistent file_id based on config name and OS (for download URL)
        consistent_id = f"{safe_name}_{os_type}"

        # Build note with skipped artifact info
        note = f"ZIP bundle with velociraptor_client and {script_name} - extract and run as admin"
        if skipped_artifacts:
            note += f". Note: {len(skipped_artifacts)} artifacts skipped (require internet): {', '.join(skipped_artifacts)}"

        return {
            "success": True,
            "file_id": consistent_id,
            "file_name": zip_filename,
            "file_path": zip_path,
            "file_size": zip_size,
            "artifacts_count": len(artifacts),
            "skipped_count": len(skipped_artifacts),
            "skipped_artifacts": skipped_artifacts,
            "note": note
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"success": False, "error": f"Failed to create collector bundle: {str(e)}"}
