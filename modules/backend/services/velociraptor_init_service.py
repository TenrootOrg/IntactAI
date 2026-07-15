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
# The upstream import artifacts. Velociraptor 0.77 renamed
# Server.Import.ArtifactExchange -> Server.Import.ArtifactBundle (old name
# kept as an alias). These are no longer RUN at runtime — the artifacts they
# import are baked into the image and loaded via --definitions — this list is
# now only the "skipped (baked)" record. scripts/regenerate_artifact_bundle.py
# is what actually runs them (and picks ArtifactBundle vs ArtifactExchange by
# what the running server defines) when refreshing the committed bundle.
STARTUP_SERVER_ARTIFACTS = [
    "Server.Import.ArtifactBundle",  # was Server.Import.ArtifactExchange (<0.77)
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

    channel = None
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

        return flow_id

    except Exception as e:
        log(f"Error running artifact {artifact_name}: {e}", "error")
        traceback.print_exc()
        return None
    finally:
        # Only closed on the success path before — any exception above leaked
        # the gRPC channel.
        if channel:
            channel.close()


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

    channel = None
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

        return success

    except Exception as e:
        # Transient "API not up yet" (UNAVAILABLE / connection refused) -> warning,
        # so a post-upgrade timing race never trips the run's auto-fail rule.
        log(f"Error starting server event artifact {artifact_name}: {e}",
            "warning" if _is_transient_grpc(e) else "error")
        traceback.print_exc()
        return False
    finally:
        if channel:
            channel.close()


def _is_transient_grpc(exc) -> bool:
    """True if the exception looks like the Velociraptor API not being up yet
    (gRPC UNAVAILABLE / connection refused) rather than a real artifact error.
    Used to log such hiccups at WARNING so a post-upgrade reimport race never
    trips the run's '>=2 error logs -> failed' rule."""
    s = str(exc)
    return ("UNAVAILABLE" in s
            or "Connection refused" in s
            or "failed to connect" in s
            or "Failed to connect" in s)


def _velociraptor_api_answers(timeout: int = 8) -> bool:
    """True iff the Velociraptor gRPC API actually ANSWERS a query — not merely
    that a channel object could be built. setup_velociraptor_connection() returns
    a LAZY grpc channel that 'succeeds' before the server accepts connections, so
    a trivial VQL probe is the only reliable readiness signal."""
    channel = setup_velociraptor_connection()
    if not channel:
        return False
    try:
        stub = api_pb2_grpc.APIStub(channel)
        for _ in stub.Query(
            api_pb2.VQLCollectorArgs(
                max_wait=1, max_row=1,
                Query=[api_pb2.VQLRequest(Name="ready_probe",
                                          VQL="SELECT 1 AS ok FROM scope()")]),
                timeout=timeout):
            return True          # got a streamed row -> serving
        return True              # stream completed cleanly -> serving
    except Exception:
        return False             # UNAVAILABLE / refused / TLS-not-ready
    finally:
        try:
            channel.close()
        except Exception:
            pass


def wait_for_velociraptor_ready(log=None, attempts: int = 45, delay: int = 2) -> bool:
    """Block until the Velociraptor API answers a VQL probe (or give up).

    ~attempts*delay seconds (default 90s) — generous because the gRPC API can
    take a while to start serving after a binary upgrade/restart. Replaces the
    old check that only verified a lazy channel could be constructed."""
    _log = log or (lambda m, l="info": None)
    for i in range(attempts):
        if _velociraptor_api_answers():
            return True
        if i == 0 or (i + 1) % 5 == 0:
            _log(f"  Velociraptor API not answering yet, waiting... ({(i + 1) * delay}s)", "info")
        time.sleep(delay)
    return False


def initialize_velociraptor_artifacts(logger_func=None, skip_exchange_imports=False):
    """Set up the runtime-only Velociraptor artifact state.

    The curated artifact bundle (ArtifactExchange / DetectRaptor / Sigma /
    Rapid7 / TenRoot — ~400 definitions) is BAKED into the velociraptor image
    and loaded on boot via --definitions, so it is no longer imported over
    the API here. What this function still does — the parts NOT covered by a
    static definition load — is:

      1. Import operator custom artifacts from data/custom_artifacts/
         (runtime additions that aren't part of the baked bundle).
      2. (Re)start the server EVENT artifacts (Custom.Elastic.Flows.Upload):
         --definitions loads the definition, but the continuous monitoring
         flow must be started via add_server_monitoring on every boot.

    Called on backend startup (app.py) and after a Velociraptor upgrade.

    Args:
        logger_func: Optional logging function
        skip_exchange_imports: Retained for call-site compatibility; now a
            no-op (the Server.Import.* artifacts are never API-imported here
            anymore — they load from the baked image).

    Returns:
        dict with status of each step
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

    # Wait for the Velociraptor API to actually ANSWER a query — not just for a
    # (lazy) gRPC channel to be constructible. setup_velociraptor_connection()
    # returns a channel before the server accepts connections, so the old check
    # passed prematurely and the imports below hit "Connection refused", logging
    # errors that flipped post-upgrade runs to 'failed'.
    log("Waiting for the Velociraptor API to answer...")
    if not wait_for_velociraptor_ready(log=log):
        log("Velociraptor API never became ready — skipping artifact initialization", "warning")
        return results
    log("Velociraptor API is ready")

    # The curated artifact bundle — Server.Import.* (ArtifactExchange /
    # DetectRaptor / Extras) AND the TenRoot custom pack — is now BAKED into
    # the velociraptor image and loaded on boot via --definitions (see
    # modules/velociraptor/{Dockerfile,entrypoint.sh,bundled_artifacts/}).
    # We no longer import them over the API here: that was the ~37-min step
    # on a fresh air-gap install, and it tied artifact versioning to a
    # runtime GitHub fetch instead of the repo. The ~400 definitions are
    # present the moment Velociraptor starts, the same way on a fresh
    # install, an online upgrade, and an offline package apply.
    # `skip_exchange_imports` is retained for call-site compatibility but is
    # now irrelevant — these are never API-imported here anymore.
    log(f"Curated bundle ({len(STARTUP_SERVER_ARTIFACTS)} Server.Import.* + "
        "TenRoot pack) loads from the image on boot (--definitions) — no API "
        "import needed.")
    for artifact in STARTUP_SERVER_ARTIFACTS:
        results["skipped"].append(artifact)

    # Import local (operator) custom artifacts from data/custom_artifacts/.
    # These are runtime operator additions that are NOT part of the baked
    # bundle, so they still need the API import.
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

    channel = None
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

        return exists

    except Exception as e:
        log(f"Error checking artifact {artifact_name}: {e}", "error")
        return False
    finally:
        if channel:
            channel.close()


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

    channel = None
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
        already_builtin = None
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
            # An artifact already loaded from the baked --definitions bundle is
            # read-only ("built in"), so artifact_set refuses to overwrite it.
            # That's NOT a failure — the definition is already present — so we
            # surface the name as a (no-op) success instead of a hard error.
            srv_log = getattr(response, 'log', '') or ''
            if 'Unable to override built in artifact' in srv_log:
                import re as _re
                m = _re.search(r'built in artifact\s+(\S+)', srv_log)
                if m:
                    already_builtin = m.group(1)

        return artifact_name or already_builtin

    except Exception as e:
        # Transient "API not up yet" -> warning (see _is_transient_grpc); real
        # parse/registry errors stay at error level.
        log(f"Error importing artifact: {e}",
            "warning" if _is_transient_grpc(e) else "error")
        return None
    finally:
        # Called in per-file import loops — a leaked channel per file adds up
        # fast across a bulk artifact import.
        if channel:
            channel.close()


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
                # ZIP-SLIP defense (Mythos finding #7, zip variant).
                # The TenRoot artifacts zip comes from a github tarball
                # pulled by `tools_download_service`, so it's not fully
                # untrusted — but tarball downloads CAN be tampered
                # with by an upstream supply-chain compromise, and the
                # extract here lands in a temp dir on the backend host.
                # Reject any name that's absolute or contains `..` so
                # a poisoned zip can't write to /etc/cron.d/ or
                # similar. Legit artifact-name YAMLs never look like
                # this.
                for name in zip_ref.namelist():
                    if not name:
                        continue
                    if name.startswith('/') or name.startswith('\\'):
                        raise RuntimeError(
                            f"zip contains absolute-path member ({name!r}) "
                            f"— refusing to extract"
                        )
                    parts = name.replace('\\', '/').split('/')
                    if '..' in parts:
                        raise RuntimeError(
                            f"zip contains path-traversal member ({name!r}) "
                            f"— refusing to extract"
                        )
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
