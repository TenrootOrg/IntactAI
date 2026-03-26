#!/usr/bin/env python3
"""
Velociraptor Initialization Service - Import artifacts and libraries on startup
"""

import json
import os
import time
import traceback
import sys
import zipfile
import tempfile
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection

# TenRoot custom artifacts zip (downloaded by tools_download_service)
TENROOT_ARTIFACTS_ZIP = "/app/data/tools/Velociraptor-Artifacts-main.zip"

# Local custom artifacts directory (for artifacts not in the TenRoot zip)
CUSTOM_ARTIFACTS_DIR = "/app/data/custom_artifacts"

# Server artifacts to run on startup (import artifacts)
# Step 1: Import ArtifactExchange - makes the DetectRaptor import artifact available
# Step 2: Import DetectRaptor hunting artifacts (requires ArtifactExchange first)
STARTUP_SERVER_ARTIFACTS = [
    "Server.Import.ArtifactExchange",
    "Server.Import.DetectRaptor",
    "Server.Import.Extras",
]

# Server EVENT artifacts to start monitoring (run continuously)
# These use add_server_monitoring() instead of collect_client()
STARTUP_SERVER_EVENT_ARTIFACTS = [
    "Custom.Elastic.Flows.Upload",  # Auto-upload flows to Elasticsearch
]

# Additional exchange artifacts that need manual import after startup:
# - Exchange.Windows.HardeningKitty: Windows security hardening checks (used by Agentic blueprints)
#   Import via Velociraptor UI: Server Artifacts > Server.Import.ArtifactExchange > Filter: HardeningKitty
MANUAL_IMPORT_ARTIFACTS = [
    "Exchange.Windows.HardeningKitty",
]


def run_server_artifact(artifact_name, parameters=None, logger_func=None):
    """Run a server artifact on Velociraptor

    Args:
        artifact_name: Name of the artifact to run
        parameters: Optional dict of parameters for the artifact
        logger_func: Optional logging function

    Returns:
        flow_id if successful, None otherwise
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    try:
        log(f"Running server artifact: {artifact_name}")

        channel = setup_velociraptor_connection()
        if not channel:
            log("Failed to connect to Velociraptor", "error")
            return None

        stub = api_pb2_grpc.APIStub(channel)

        # Build the VQL query
        if parameters:
            # Format parameters for VQL
            param_str = ", ".join(f"`{k}`='{v}'" for k, v in parameters.items())
            spec = f"dict(`{artifact_name}`=dict({param_str}))"
            query = f"SELECT collect_client(client_id='server', artifacts='{artifact_name}', spec={spec}) AS Flow FROM scope()"
        else:
            query = f"LET collection <= collect_client(client_id='server', artifacts='{artifact_name}') SELECT * FROM collection"

        log(f"VQL: {query}")

        request = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(
                Name=artifact_name,
                VQL=query
            )]
        )

        flow_id = None
        for response in stub.Query(request, timeout=60):
            if response.log:
                log(f"Server log: {response.log}")

            if response.Response:
                try:
                    data = json.loads(response.Response)
                    if isinstance(data, list) and len(data) > 0:
                        if "Flow" in data[0]:
                            flow_id = data[0]["Flow"].get("flow_id")
                        elif "flow_id" in data[0]:
                            flow_id = data[0].get("flow_id")
                        if flow_id:
                            log(f"Artifact started with flow_id: {flow_id}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    log(f"Could not parse response: {e}", "warning")

        channel.close()
        return flow_id

    except Exception as e:
        log(f"Error running artifact {artifact_name}: {e}", "error")
        traceback.print_exc()
        return None


def start_server_event_artifact(artifact_name, logger_func=None):
    """Start a server event artifact for continuous monitoring

    Args:
        artifact_name: Name of the SERVER_EVENT artifact to start
        logger_func: Optional logging function

    Returns:
        True if successful, False otherwise
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    try:
        log(f"Starting server event artifact: {artifact_name}")

        channel = setup_velociraptor_connection()
        if not channel:
            log("Failed to connect to Velociraptor", "error")
            return False

        stub = api_pb2_grpc.APIStub(channel)

        # Use add_server_monitoring() for SERVER_EVENT artifacts
        query = f"SELECT add_server_monitoring(artifact='{artifact_name}') AS Result FROM scope()"

        log(f"VQL: {query}")

        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            Query=[api_pb2.VQLRequest(
                Name=artifact_name,
                VQL=query
            )]
        )

        success = False
        for response in stub.Query(request, timeout=30):
            if response.log:
                log(f"Server log: {response.log}")

            if response.Response:
                try:
                    data = json.loads(response.Response)
                    if isinstance(data, list) and len(data) > 0:
                        log(f"Server event artifact started: {data}")
                        success = True
                except (json.JSONDecodeError, KeyError) as e:
                    log(f"Could not parse response: {e}", "warning")

        channel.close()
        return success

    except Exception as e:
        log(f"Error starting server event artifact {artifact_name}: {e}", "error")
        traceback.print_exc()
        return False


def initialize_velociraptor_artifacts(logger_func=None):
    """Initialize Velociraptor by running server artifacts in sequence

    This function is called on backend startup to ensure all required
    artifacts are available in Velociraptor:
    1. Server.Import.ArtifactExchange - imports exchange artifacts
    2. Server.Import.DetectRaptor - imports DetectRaptor artifacts
    3. Start server event artifacts (Custom.Elastic.Flows.Upload)

    Args:
        logger_func: Optional logging function

    Returns:
        dict with status of each import
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    log("=" * 60)
    log("Starting Velociraptor artifact initialization")
    log("=" * 60)

    results = {
        "success": [],
        "failed": [],
        "skipped": []
    }

    # Wait for Velociraptor to be ready
    log("Waiting for Velociraptor to be ready...")
    max_retries = 5
    for i in range(max_retries):
        channel = setup_velociraptor_connection()
        if channel:
            channel.close()
            log("Velociraptor is ready")
            break
        log(f"Velociraptor not ready, retrying... ({i+1}/{max_retries})")
        time.sleep(1)
    else:
        log("Velociraptor not available, skipping artifact initialization", "warning")
        return results

    # Run server artifacts (Server.Import.ArtifactExchange imports all exchange artifacts)
    log(f"Running {len(STARTUP_SERVER_ARTIFACTS)} server artifacts...")

    for idx, artifact in enumerate(STARTUP_SERVER_ARTIFACTS):
        try:
            flow_id = run_server_artifact(artifact, logger_func=logger_func)
            if flow_id:
                results["success"].append(artifact)
                log(f"Successfully started {artifact} with flow_id: {flow_id}")
            else:
                results["failed"].append(artifact)
                log(f"Failed to start {artifact}", "warning")

        except Exception as e:
            log(f"Failed to run {artifact}: {e}", "error")
            results["failed"].append(artifact)

        # Delay between artifacts (except after the last one)
        if idx < len(STARTUP_SERVER_ARTIFACTS) - 1:
            log("Waiting 10s before next artifact...")
            time.sleep(10)

    # Import TenRoot custom artifacts (if zip exists)
    log("")
    log("Importing TenRoot custom artifacts...")
    tenroot_results = import_tenroot_artifacts(logger_func)
    results["success"].extend(tenroot_results.get("success", []))
    results["failed"].extend(tenroot_results.get("failed", []))
    results["skipped"].extend(tenroot_results.get("skipped", []))

    # Import local custom artifacts (ELK integration, etc.)
    log("")
    log("Importing local custom artifacts...")
    local_results = import_local_custom_artifacts(logger_func)
    results["success"].extend(local_results.get("success", []))
    results["failed"].extend(local_results.get("failed", []))
    results["skipped"].extend(local_results.get("skipped", []))

    # Start server event artifacts (continuous monitoring)
    log("")
    log("Starting server event artifacts...")
    for artifact in STARTUP_SERVER_EVENT_ARTIFACTS:
        try:
            if start_server_event_artifact(artifact, logger_func):
                results["success"].append(f"{artifact} (monitoring)")
                log(f"Successfully started {artifact} for monitoring")
            else:
                results["failed"].append(f"{artifact} (monitoring)")
                log(f"Failed to start {artifact} for monitoring", "warning")
        except Exception as e:
            log(f"Failed to start {artifact}: {e}", "error")
            results["failed"].append(f"{artifact} (monitoring)")

    log("=" * 60)
    log("Velociraptor initialization complete")
    log(f"Successful: {len(results['success'])}")
    log(f"Failed: {len(results['failed'])}")
    log("=" * 60)

    return results


def check_artifact_exists(artifact_name, logger_func=None):
    """Check if an artifact already exists in Velociraptor

    Args:
        artifact_name: Name of the artifact to check
        logger_func: Optional logging function

    Returns:
        True if exists, False otherwise
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return False

        stub = api_pb2_grpc.APIStub(channel)

        query = f"SELECT * FROM artifact_definitions(names='{artifact_name}')"

        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(VQL=query)]
        )

        exists = False
        for response in stub.Query(request, timeout=10):
            if response.Response:
                data = json.loads(response.Response)
                if data and len(data) > 0:
                    exists = True
                    break

        channel.close()
        return exists

    except Exception as e:
        log(f"Error checking artifact {artifact_name}: {e}", "error")
        return False


def import_custom_artifact(yaml_content, logger_func=None):
    """Import a single custom artifact YAML into Velociraptor

    Args:
        yaml_content: The YAML content of the artifact
        logger_func: Optional logging function

    Returns:
        artifact_name if successful, None otherwise
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return None

        stub = api_pb2_grpc.APIStub(channel)

        # JSON encode the YAML content - this properly escapes all special chars
        # Then use unhex(base64decode()) to pass it safely to VQL
        import base64
        encoded_yaml = base64.b64encode(yaml_content.encode('utf-8')).decode('ascii')

        # Use artifact_set with base64 decoded content
        query = f"SELECT artifact_set(definition=base64decode(string='{encoded_yaml}')) AS Result FROM scope()"

        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            Query=[api_pb2.VQLRequest(VQL=query)]
        )

        artifact_name = None
        for response in stub.Query(request, timeout=30):
            if response.Response:
                try:
                    data = json.loads(response.Response)
                    if isinstance(data, list) and len(data) > 0:
                        result = data[0].get("Result", {})
                        if isinstance(result, dict):
                            artifact_name = result.get("name")
                except (json.JSONDecodeError, KeyError) as e:
                    pass

        channel.close()
        return artifact_name

    except Exception as e:
        log(f"Error importing artifact: {e}", "error")
        return None


def import_tenroot_artifacts(logger_func=None):
    """Import TenRoot custom artifacts from the downloaded zip file

    Extracts Velociraptor-Artifacts-main.zip and imports all .yaml files
    into Velociraptor using artifact_set().

    Args:
        logger_func: Optional logging function

    Returns:
        dict with success/failed lists
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    results = {
        "success": [],
        "failed": [],
        "skipped": []
    }

    # Check if zip exists
    if not os.path.exists(TENROOT_ARTIFACTS_ZIP):
        log(f"TenRoot artifacts zip not found: {TENROOT_ARTIFACTS_ZIP}", "warning")
        log("Run maintenance to download tools first", "warning")
        return results

    log("=" * 60)
    log("Importing TenRoot custom artifacts")
    log("=" * 60)

    try:
        # Extract to temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            log(f"Extracting {TENROOT_ARTIFACTS_ZIP}...")

            with zipfile.ZipFile(TENROOT_ARTIFACTS_ZIP, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # Find all .yaml files
            yaml_files = []
            for root, dirs, files in os.walk(temp_dir):
                for f in files:
                    if f.endswith('.yaml'):
                        yaml_files.append(os.path.join(root, f))

            log(f"Found {len(yaml_files)} artifact YAML files")

            # Import each artifact
            for idx, yaml_path in enumerate(yaml_files):
                filename = os.path.basename(yaml_path)

                try:
                    with open(yaml_path, 'r', encoding='utf-8') as f:
                        yaml_content = f.read()

                    # Skip empty or very small files
                    if len(yaml_content.strip()) < 50:
                        results["skipped"].append(filename)
                        continue

                    artifact_name = import_custom_artifact(yaml_content, logger_func)

                    if artifact_name:
                        results["success"].append(artifact_name)
                        log(f"  ✓ Imported: {artifact_name}")
                    else:
                        results["failed"].append(filename)
                        log(f"  ✗ Failed: {filename}", "warning")

                except Exception as e:
                    results["failed"].append(filename)
                    log(f"  ✗ Error with {filename}: {e}", "warning")

            log("=" * 60)
            log(f"TenRoot import complete: {len(results['success'])} succeeded, {len(results['failed'])} failed")
            log("=" * 60)

    except Exception as e:
        log(f"Error importing TenRoot artifacts: {e}", "error")
        traceback.print_exc()

    return results


def import_local_custom_artifacts(logger_func=None):
    """Import custom artifacts from the local custom_artifacts directory

    This imports artifacts that are not in the TenRoot zip, such as:
    - Custom.Elastic.Flows.Upload - Auto-forwards Velociraptor data to Elasticsearch

    Args:
        logger_func: Optional logging function

    Returns:
        dict with success/failed lists
    """
    def log(message, level="info"):
        print(f"[VELO-INIT] {message}", flush=True)
        if logger_func:
            try:
                logger_func(f"[VELO-INIT] {message}", level)
            except:
                pass

    results = {
        "success": [],
        "failed": [],
        "skipped": []
    }

    # Check if custom artifacts directory exists
    if not os.path.exists(CUSTOM_ARTIFACTS_DIR):
        log(f"Custom artifacts directory not found: {CUSTOM_ARTIFACTS_DIR}", "info")
        return results

    log("=" * 60)
    log("Importing local custom artifacts")
    log("=" * 60)

    try:
        # Find all .yaml files in the custom artifacts directory
        yaml_files = []
        for f in os.listdir(CUSTOM_ARTIFACTS_DIR):
            if f.endswith('.yaml'):
                yaml_files.append(os.path.join(CUSTOM_ARTIFACTS_DIR, f))

        if not yaml_files:
            log("No custom artifact YAML files found")
            return results

        log(f"Found {len(yaml_files)} custom artifact YAML files")

        # Import each artifact
        for yaml_path in yaml_files:
            filename = os.path.basename(yaml_path)

            try:
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()

                # Skip empty or very small files
                if len(yaml_content.strip()) < 50:
                    results["skipped"].append(filename)
                    continue

                artifact_name = import_custom_artifact(yaml_content, logger_func)

                if artifact_name:
                    results["success"].append(artifact_name)
                    log(f"  ✓ Imported: {artifact_name}")
                else:
                    results["failed"].append(filename)
                    log(f"  ✗ Failed: {filename}", "warning")

            except Exception as e:
                results["failed"].append(filename)
                log(f"  ✗ Error with {filename}: {e}", "warning")

        log("=" * 60)
        log(f"Local custom import complete: {len(results['success'])} succeeded, {len(results['failed'])} failed")
        log("=" * 60)

    except Exception as e:
        log(f"Error importing local custom artifacts: {e}", "error")
        traceback.print_exc()

    return results
