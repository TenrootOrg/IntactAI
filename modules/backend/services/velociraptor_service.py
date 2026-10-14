#!/usr/bin/env python3
"""
Velociraptor Service - gRPC connection, VQL queries, client operations
"""

import base64
import subprocess
import json
import shlex
import time
import yaml
import os
import grpc
import traceback
import sys
import threading
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

from config import VELOCIRAPTOR_CONTAINER, VELOCIRAPTOR_API_CONFIG_PATH, VELOCIRAPTOR_SNAPSHOT_PATH
from services.vql_safety import is_valid_client_id, is_valid_flow_id

# Parsed api.config.yaml, see load_velociraptor_api_config()
velociraptor_api_config = None
_api_config_lock = threading.Lock()
_API_CONFIG_KEYS = ("ca_certificate", "client_private_key", "client_cert", "api_connection_string")
_SHARED_CONFIG_COPY = "/tmp/api.config.yaml"
_CONNECT_CHECK_SECONDS = 5

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
    print(f"[CLIENT-LIST] Querying clients via VQL API (real-time, include_offline={include_offline})...", flush=True)
    # Outside the try: the fallback raises when the snapshot can't be decoded, and
    # the except below would read it a second time.
    channel = setup_velociraptor_connection()
    if not channel:
        print("[CLIENT-LIST] Failed to setup connection, falling back to snapshot file", flush=True)
        return get_clients_from_snapshot_file(include_offline)
    try:
        stub = api_pb2_grpc.APIStub(channel)

        # VQL query to get clients with their info. Online filter only
        # applied when include_offline=False — for existing-flow analysis
        # we want every enrolled client visible since the data was
        # collected previously.
        # last_seen_at is MICROseconds and now() seconds: compared raw, every enrolled
        # client passed, so the "online only" list was the whole fleet (10 of 10
        # on the lab box, with 1 really online).
        liveness_clause = "" if include_offline else "  AND last_seen_at / 1000000 > now() - 600"
        vql_query = f"""
        SELECT client_id,
               os_info.hostname AS hostname,
               os_info.system AS os,
               os_info.release AS os_version,
               labels AS labels,
               last_seen_at,
               last_ip,
               agent_information.name AS agent,
               agent_information.version AS version,
               last_interrogate_flow_id AS interrogated,
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
                                    "last_ip": item.get('last_ip', ''),
                                    "imported": _is_import(item),
                                })
                except json.JSONDecodeError as e:
                    print(f"[CLIENT-LIST] Error parsing VQL response: {e}", flush=True)
                    continue

        print(f"[CLIENT-LIST] ✓ Found {len(clients)} clients via VQL API", flush=True)
        return clients

    except Exception as e:
        print(f"[CLIENT-LIST] Error querying via API: {e}", flush=True)
        traceback.print_exc()
        # Fallback to snapshot file method
        return get_clients_from_snapshot_file(include_offline)
    finally:
        # Previously only closed on the success path — any exception above
        # (or the pre-existing early return via the `if not channel` branch,
        # where channel is falsy anyway) leaked the gRPC channel.
        if channel:
            channel.close()


def _is_import(row):
    """An offline-collection import, not an agent: Velociraptor keeps a client record
    for it (no agent name, never interrogated, no version). It showed in every picker
    and the dashboard count as a client nothing could ever be sent to. Same
    predicate as Settings → Velociraptor (velociraptor_clients.classify), reused so
    the two can't disagree. Callers that only map host -> OS keep these rows."""
    from services.velociraptor_clients import classify
    return classify([row], None)["counts"]["imported"] == 1


# actions_proto.ClientInfo field numbers -- what each snapshot record's `info` blob
# is. Read from the protobuf descriptor embedded in the v0.77.1 server binary
# (2026-10-14), not guessed: wire-format numbers are stable across versions.
_CLIENT_INFO_FIELDS = {1: "client_id", 3: "hostname", 5: "os", 6: "os_version", 10: "last_ip",
                       12: "version", 13: "agent", 15: "labels", 16: "interrogated"}


def _client_info_strings(blob):
    """The string fields of a serialized ClientInfo (protobuf wire format)."""
    out, i = {"labels": []}, 0

    def varint():
        nonlocal i
        n = shift = 0
        while True:
            b = blob[i]
            i += 1
            n |= (b & 0x7f) << shift
            shift += 7
            if b < 0x80:
                return n
    while i < len(blob):
        key = varint()
        num, wire = key >> 3, key & 7
        if wire == 0:
            varint()
        elif wire == 1:
            i += 8
        elif wire == 5:
            i += 4
        elif wire == 2:
            n = varint()
            val, i = blob[i:i + n], i + n
            if i > len(blob):
                raise ValueError("truncated record")
            name = _CLIENT_INFO_FIELDS.get(num)
            if name == "labels":
                out["labels"].append(val.decode("utf-8", "replace"))
            elif name:
                out[name] = val.decode("utf-8", "replace")
        else:
            raise ValueError(f"wire type {wire}")
    return out


def _decode_client_info(info, client_id):
    """A snapshot record's `info` -> its ClientInfo strings. Hex is what this code
    has always read; base64 is how Go's encoder writes []byte, so both are tried.
    The decoded client_id must match the record's, so a wrong guess can't pass."""
    for decode in (bytes.fromhex, base64.b64decode):
        try:
            got = _client_info_strings(decode(info))
        except (ValueError, IndexError):        # binascii.Error is a ValueError
            continue
        if got.get("client_id") == client_id:
            return got
    raise ValueError(f"{client_id}: info is not a ClientInfo record")


def get_clients_from_snapshot_file(include_offline=True):
    """Read clients from Velociraptor snapshot file (fallback method only).

    This used to stamp every client "seen now", so with the API down the whole fleet
    showed online and the pickers pre-selected all of it. The record's ping is only
    as fresh as the last snapshot flush, and with the API down nothing can be sent
    anyway: clients are listed as not seen (last_seen_at 0), and an online-only
    request gets none.

    Hostnames used to be guessed by searching the raw bytes for "DESKTOP-", so every
    other host became "Unknown" -- at 1,000 hosts, 1,000 indistinguishable rows. Each
    record is now decoded as the ClientInfo protobuf it is. If the snapshot has
    records and none decode, this raises instead of listing a fleet of "Unknown"."""
    if not include_offline:
        print("[CLIENT-LIST] Snapshot fallback cannot tell who is online -- returning none", flush=True)
        return []
    try:
        print("[CLIENT-LIST] Using fallback snapshot file method...", flush=True)
        result = subprocess.run([
            "docker", "exec", VELOCIRAPTOR_CONTAINER,
            "cat", VELOCIRAPTOR_SNAPSHOT_PATH
        ], capture_output=True, text=True, timeout=10)
    except Exception as e:
        print(f"[CLIENT-LIST] Error reading snapshot: {e}", flush=True)
        return []
    if result.returncode != 0:
        return []
    clients, undecodable = [], 0
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            client_id = data.get('client_id') or ''
            # Skip server and non-client entries
            if not client_id.startswith('C.'):
                continue
            info = _decode_client_info(data.get('info') or '', client_id)
        except Exception as e:
            undecodable += 1
            if undecodable <= 3:
                print(f"[CLIENT-LIST] Error parsing client record: {e}", flush=True)
            continue
        agent = {k: info.get(k, '') for k in ('agent', 'version', 'interrogated', 'last_ip')}
        clients.append({
            "client_id": client_id,
            "hostname": info.get("hostname", ""),
            "os": info.get("os", ""),
            "os_version": info.get("os_version", ""),
            "labels": [l for l in info["labels"] if l],
            "last_seen_at": 0,      # unknown -- never claim "online"
            "last_ip": info.get("last_ip", ""),
            "imported": _is_import(agent),
        })
    if undecodable:
        print(f"[CLIENT-LIST] {undecodable} snapshot record(s) could not be decoded", flush=True)
        if not clients:
            raise RuntimeError("The Velociraptor API is unreachable and its client snapshot "
                               "could not be decoded; the client list is unavailable until "
                               "the API answers again")
    print(f"[CLIENT-LIST] Found {len(clients)} clients from snapshot file", flush=True)
    return clients

def load_velociraptor_api_config(stale=None):
    """The parsed API config (api.config.yaml), read from the Velociraptor container
    once and then served from memory.

    It used to be re-read on EVERY gRPC call: a `docker exec cat` whose output was
    written to a shared /tmp/api.config.yaml and read back. Concurrent threads (one
    per client at fleet scale) read it while another had just truncated it,
    yaml.safe_load returned None, and that host's start or status check was reported
    as failed. Now nothing reads a file: stdout is parsed directly, under a lock.

    Pass `stale` = the config a connection just failed with: it is re-read then (a
    changed hostname must not break every later call), unless another thread has
    already replaced it, so a burst of failures costs one re-read, not one each.
    Returns None when the config cannot be read."""
    global velociraptor_api_config
    with _api_config_lock:
        if velociraptor_api_config is not None and velociraptor_api_config is not stale:
            return velociraptor_api_config
        try:
            print("[CONFIG] Loading Velociraptor API configuration from container...", flush=True)
            result = subprocess.run([
                "docker", "exec", VELOCIRAPTOR_CONTAINER,
                "cat", VELOCIRAPTOR_API_CONFIG_PATH
            ], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                print(f"[CONFIG] ✗ Failed to load API config: {result.stderr}", flush=True)
                return None
            config = yaml.safe_load(result.stdout)
            if not isinstance(config, dict) or not all(config.get(k) for k in _API_CONFIG_KEYS):
                print("[CONFIG] ✗ API config is incomplete", flush=True)
                return None
            velociraptor_api_config = config
            _refresh_shared_config_copy(result.stdout)
            return config
        except Exception as e:
            print(f"[CONFIG] ✗ Exception loading API config: {e}", flush=True)
            return None


def _refresh_shared_config_copy(text):
    """tools_download_service and msi_generator_service still read their own copy
    of /tmp/api.config.yaml (written by them only when missing), so keep it current
    -- replaced atomically, never truncated in place, so a reader can't see it half
    written. ponytail: drop once both use setup_velociraptor_connection()."""
    try:
        tmp = _SHARED_CONFIG_COPY + ".new"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, _SHARED_CONFIG_COPY)
    except OSError as e:
        print(f"[CONFIG] Could not refresh {_SHARED_CONFIG_COPY}: {e}", flush=True)


def _secure_channel(config):
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
    return grpc.secure_channel(config["api_connection_string"], creds, options)


def setup_velociraptor_connection():
    """Setup gRPC connection to Velociraptor API"""
    try:
        config = load_velociraptor_api_config()
        if not config:
            return None
        channel = _secure_channel(config)
        # The config is cached, so a stale one (an out-of-date hostname after an IP
        # or domain change) would break every later call. grpc channels are lazy, so
        # connect now: if that fails, re-read the config and build the channel from
        # it. A server that is simply down fails the same way the caller's own RPC
        # always did; it only costs this wait and one re-read.
        ready = grpc.channel_ready_future(channel)
        try:
            ready.result(timeout=_CONNECT_CHECK_SECONDS)
        except Exception:
            ready.cancel()
            fresh = load_velociraptor_api_config(stale=config)
            if fresh and fresh != config:
                print("[GRPC] API config changed -- reconnecting with the new one", flush=True)
                channel.close()
                config, channel = fresh, _secure_channel(fresh)
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
    channel = None
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
    finally:
        # Never closed before — every call (this is polled) leaked a channel.
        if channel:
            channel.close()


def is_hunt_registered(hunt_id):
    """Return True once Velociraptor actually has this hunt.

    The workflow's deliverable is CREATING the hunt. Once Velociraptor holds
    it, the hunt collects over its own expire window on its own schedule —
    that is Velociraptor's job, not the run's, and the operator watches it in
    the Velociraptor UI.

    This used to wait for collection to finish:

        return scheduled > 0 and finished >= scheduled

    which never became true when no client was online at dispatch, because
    Velociraptor only schedules a client when it checks in. Observed on
    H.D9K786G1CQ8Q4: all 9 clients last seen 44.7 hours earlier, so
    total_clients_scheduled stayed 0 and `scheduled > 0` pinned the run at
    'running' forever — not merely until the 120-minute window expired, but
    permanently, since the guard could never pass. The hunt itself was fine.

    Confirmed against Velociraptor rather than trusting the create call: the
    run should only close on evidence the hunt exists where it matters.
    Returns False on any lookup failure so a gRPC blip leaves the run's
    status untouched instead of falsely completing it."""
    if not hunt_id:
        return False
    channel = None
    try:
        channel = setup_velociraptor_connection()
        if not channel:
            return False
        stub = api_pb2_grpc.APIStub(channel)
        vql = ("SELECT hunt_id FROM hunts() "
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
                # A row means Velociraptor knows the hunt. Its state is
                # deliberately NOT checked: RUNNING/PAUSED/STOPPED are all
                # states of a hunt that exists, and the run's job was to put
                # it there.
                if isinstance(rows, list) and rows and rows[0].get("hunt_id"):
                    return True
        return False
    except Exception as e:
        print(f"[GRPC] is_hunt_registered({hunt_id}) failed: {e}", flush=True)
        return False
    finally:
        # This is polled by _reconcile_velociraptor_hunt on every dashboard
        # fetch — never closing before leaked one channel per poll.
        if channel:
            channel.close()


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

    channel = None
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
    finally:
        # Both except branches previously returned without closing —
        # any gRPC error while creating a hunt leaked the channel.
        if channel:
            channel.close()


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




def get_artifact_definitions():
    """Get all artifact definitions from Velociraptor.

    Returns a list of artifact names that are available in the server.
    This is used to dynamically populate blueprint artifact selectors.
    """
    channel = None
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

        print(f"[ARTIFACTS] ✓ Found {len(artifacts)} artifacts", flush=True)
        return artifacts

    except Exception as e:
        print(f"[ARTIFACTS] Error querying artifacts: {e}", flush=True)
        traceback.print_exc()
        return None
    finally:
        if channel:
            channel.close()




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

    # Defense-in-depth: these values are interpolated directly into a VQL
    # string literal below with no escaping. Callers should already only
    # pass server-generated IDs, but reject anything else here too.
    if not is_valid_client_id(client_id) or not is_valid_flow_id(flow_id):
        log(f"Rejecting invalid client_id/flow_id: {client_id!r}/{flow_id!r}", "error")
        return False

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

    # Defense-in-depth: client_id/flow_id are interpolated directly into a
    # VQL string literal below with no escaping.
    if not is_valid_client_id(client_id) or not is_valid_flow_id(flow_id):
        log(f"Rejecting invalid client_id/flow_id: {client_id!r}/{flow_id!r}", "warning")
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

    def _count(vql, timeout):
        """Rows the query produced (each one a deletion), counted as they stream.
        This used to keep every row in a list only to take len() of it -- millions
        of dicts on a fleet -- and max_row=2,000,000 let one response carry them all
        as a single JSON string. max_row is a batch size, not a cap."""
        stub = api_pb2_grpc.APIStub(channel)
        req = api_pb2.VQLCollectorArgs(
            max_wait=10, max_row=10000,
            Query=[api_pb2.VQLRequest(VQL=vql)],
        )
        n = 0
        for resp in stub.Query(req, timeout=timeout):
            if resp.Response:
                try:
                    r = json.loads(resp.Response)
                    if isinstance(r, list):
                        n += len(r)
                except json.JSONDecodeError:
                    pass
        return n

    try:
        # 1. Live hunts — hunt_delete also removes their per-client collected
        #    files (when the hunt metadata still exists).
        if delete_hunts:
            try:
                log("Deleting hunts…")
                n = _count(
                    "SELECT hunt_id, "
                    "hunt_delete(hunt_id=hunt_id, really_do_it=true) AS deleted "
                    "FROM hunts()",
                    timeout=600,
                )
                out["hunts"] = n
                log(f"Deleted {out['hunts']} hunt(s)", "success")
            except Exception as e:
                log(f"Hunt deletion error: {e}", "warning")
                out["errors"].append(f"hunts: {e}")

        # 2. Live flows — flow_delete removes the collection metadata + files.
        if delete_flows:
            try:
                log("Deleting tracked flows…")
                n = _count(
                    "SELECT client_id, session_id, "
                    "flow_delete(client_id=client_id, flow_id=session_id, really_do_it=true) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT client_id, session_id FROM flows(client_id=client_id) }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["flows"] = n
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
                n = _count(
                    "SELECT OSPath, file_store_delete(path=OSPath) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT OSPath FROM glob("
                    "globs=['/artifacts/**', '/collections/**', '/uploads/**', '/tmp/**'], "
                    "accessor='fs', root='/clients/' + client_id) WHERE NOT IsDir }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["data_files"] = n
                log(f"Removed {out['data_files']} residual result file(s)", "success")
            except Exception as e:
                log(f"Residual sweep error: {e}", "warning")
                out["errors"].append(f"residual: {e}")

        # 4. Client monitoring (event) data.
        if delete_monitoring:
            try:
                log("Deleting client monitoring data…")
                n = _count(
                    "SELECT OSPath, file_store_delete(path=OSPath) AS deleted "
                    "FROM foreach("
                    "row={ SELECT client_id FROM clients() WHERE client_id != 'server' }, "
                    "query={ SELECT OSPath FROM glob("
                    "globs=['/monitoring/**', '/monitoring_logs/**'], "
                    "accessor='fs', root='/clients/' + client_id) WHERE NOT IsDir }, "
                    "workers=10)",
                    timeout=1800,
                )
                out["monitoring"] = n
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
