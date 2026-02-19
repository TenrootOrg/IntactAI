#!/usr/bin/env python3
"""
Velociraptor Initialization Service - Import artifacts and libraries on startup
"""

import json
import time
import traceback
import sys
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from services.velociraptor_service import setup_velociraptor_connection

# Server artifacts to run on startup (two-step import process)
# Step 1: Import ArtifactExchange - makes the DetectRaptor import artifact available
# Step 2: Import DetectRaptor hunting artifacts (requires ArtifactExchange first)
STARTUP_SERVER_ARTIFACTS = [
    "Server.Import.ArtifactExchange",
    "Server.Import.DetectRaptor",
    "Server.Import.Extras",
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


def initialize_velociraptor_artifacts(logger_func=None):
    """Initialize Velociraptor by running server artifacts in sequence

    This function is called on backend startup to ensure all required
    artifacts are available in Velociraptor:
    1. Server.Import.ArtifactExchange - imports exchange artifacts
    2. Server.Import.DetectRaptor - imports DetectRaptor artifacts

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
