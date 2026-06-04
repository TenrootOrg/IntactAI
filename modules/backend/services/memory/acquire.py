"""Velociraptor memory acquisition + fs-accessor extract.

Port of ``volweb-poc/acquire.sh`` to Python.  Three steps:

  1. Dispatch ``Windows.Memory.Acquisition`` via VQL ``collect_client()``
     with the load-bearing kwargs ``max_bytes=64GiB`` and
     ``Compression='None'`` (see :mod:`services.memory.defaults` for
     the multi-paragraph explanation of why those values are not
     negotiable).
  2. Poll the resulting flow until it reaches ``FINISHED`` (or fail).
  3. Run VQL ``copy(accessor='fs')`` inside the Velociraptor container
     to extract the raw memory from the filestore (auto-unwraps the
     at-rest zlib wrap), then ``docker cp`` the file out to the host
     at ``DUMPS_DIR/<hostname>-<flow_id>.raw``.

Reuses the existing gRPC plumbing in
:mod:`services.velociraptor_service` (channel setup, cancel_flow,
cleanup_flow_export) and the flow-monitor loop in
:mod:`services.kape_service` so this module owns only the
acquisition-specific VQL.

The pipeline orchestrator passes ``run_id`` and a cancel-event so the
Stop button kills both the in-flight Velociraptor flow AND the local
poll loop promptly. On any failure path we cancel + DeleteFlow on the
Velociraptor side to release ~5 GB of filestore the moment things go
wrong; on success we leave the flow for the post-success cleanup hook
which also handles the host .raw + VolWeb media copy.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable

from config import VELOCIRAPTOR_CONTAINER
from services.kape_service import monitor_flow_completion
from services.velociraptor_service import cancel_flow

from .defaults import ACQUISITION_DEFAULTS


# Host-side directory where extracted .raw files land. Falls back to
# the PoC location so the in-tree port can run alongside the existing
# pipeline without colliding.
DUMPS_DIR_DEFAULT = "/data/memory_dumps"


class AcquisitionError(RuntimeError):
    """Raised on any acquisition failure the pipeline can't recover from."""


# ---------------------------------------------------------------------------
# Velociraptor VQL helpers
# ---------------------------------------------------------------------------


def _velo_query(vql: str, timeout: int = 30) -> list[dict]:
    """Run a one-off VQL query inside the Velociraptor container.

    Uses ``docker exec`` rather than the gRPC channel because the
    queries in this module are short, one-shot, and operator-readable
    in the workflow logs. Returns the parsed JSONL rows.

    Long-running calls (``collect_client``, ``copy``) timeout-protect
    via subprocess timeout — Velociraptor's CLI returns promptly for
    these even on slow servers.
    """
    # Use --api_config (not --config) so we hit the running server's
    # API instead of trying to spin up a parallel server inside the
    # already-running container. The PoC's acquire.sh established
    # this — `--config server.config.yaml` returns empty clients()
    # results because it operates on a separate, empty datastore view.
    cmd = [
        "docker", "exec", VELOCIRAPTOR_CONTAINER,
        "/velociraptor/velociraptor",
        "--api_config", "/velociraptor/api.config.yaml",
        "--nobanner",
        "query", "--format", "jsonl", vql,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise AcquisitionError(f"VQL query timed out after {timeout}s: {vql[:120]}") from e
    if result.returncode != 0:
        raise AcquisitionError(
            f"VQL query failed (rc={result.returncode}): {result.stderr.strip()[:300]}"
        )
    rows: list[dict] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _client_hostname(client_id: str) -> str:
    rows = _velo_query(
        f"SELECT os_info.hostname AS hostname FROM clients(client_id='{client_id}')"
    )
    if not rows:
        raise AcquisitionError(f"client {client_id} not found in Velociraptor")
    host = rows[0].get("hostname") or "unknown"
    # Sanitize for filesystem use — same scheme as acquire.sh's tr.
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(host))


def _dispatch_acquisition(
    client_id: str,
    *,
    max_bytes: int,
    cpu_limit: int,
    compression: str,
    flow_timeout: int,
    urgent: bool,
) -> str:
    """Issue ``collect_client(Windows.Memory.Acquisition, ...)``.

    Returns the new ``flow_id``. Raises :class:`AcquisitionError` if
    dispatch fails OR the resulting flow's ``request.max_upload_bytes``
    doesn't reflect the cap we asked for (which would mean the kwarg
    didn't stick — Vol3 would then refuse to parse the truncated
    dump).
    """
    spec_dict = f"dict(`Windows.Memory.Acquisition`=dict(Compression='{compression}'))"
    urgent_lit = "true" if urgent else "false"
    vql = (
        "SELECT collect_client("
        f"client_id='{client_id}',"
        "artifacts=['Windows.Memory.Acquisition'],"
        f"spec={spec_dict},"
        f"timeout={flow_timeout},"
        f"cpu_limit={cpu_limit},"
        f"max_bytes={max_bytes},"
        "max_rows=10000000,"
        f"urgent={urgent_lit}"
        ").flow_id AS flow_id FROM scope()"
    )
    rows = _velo_query(vql)
    if not rows or not rows[0].get("flow_id"):
        raise AcquisitionError(f"collect_client returned no flow_id: {rows}")
    flow_id = rows[0]["flow_id"]

    # Sanity: confirm max_upload_bytes actually landed on the request.
    # A typo on the kwarg name (e.g. max_upload_bytes vs max_bytes) is
    # silently accepted by VQL and the cap stays at the server default.
    confirm = _velo_query(
        "SELECT request.max_upload_bytes AS m FROM flows("
        f"client_id='{client_id}') WHERE session_id='{flow_id}'"
    )
    got = int((confirm[0] if confirm else {}).get("m", 0))
    if got < 2 * 1024 * 1024 * 1024:
        raise AcquisitionError(
            f"max_bytes did not stick: request.max_upload_bytes={got}"
        )
    return flow_id


def _extract_raw_via_fs_accessor(client_id: str, flow_id: str) -> tuple[str, int]:
    """Extract the captured PhysicalMemory.dd using the ``fs:`` accessor
    so the at-rest zlib wrap is stripped on read.

    Returns ``(container_path, size_bytes)``. The caller is responsible
    for ``docker cp``-ing the file out and deleting the container-side
    copy.
    """
    srv_vfs = f"/clients/{client_id}/collections/{flow_id}/uploads/auto/PhysicalMemory.dd"
    srv_tmp = f"/tmp/{flow_id}.raw"
    vql = (
        "SELECT copy("
        f"filename='{srv_vfs}',dest='{srv_tmp}',accessor='fs'"
        ") AS r FROM scope()"
    )
    _velo_query(vql, timeout=900)  # copy() blocks until done; 15-min cap

    stat = subprocess.run(
        ["docker", "exec", VELOCIRAPTOR_CONTAINER, "stat", "-c", "%s", srv_tmp],
        capture_output=True, text=True, timeout=15,
    )
    try:
        size = int((stat.stdout or "0").strip())
    except ValueError:
        size = 0
    if size < 1000:
        raise AcquisitionError(
            f"fs-accessor copy produced empty/tiny file: {size} bytes"
        )
    return srv_tmp, size


def _docker_cp_out(srv_path: str, host_dst: str) -> None:
    """Pull the container-side temp file to the host with ``docker cp``.

    Same path the alpine→docker-exec ZIP-export fix uses elsewhere in
    the codebase. After success the container-side temp is removed —
    keeping it would needlessly retain a multi-GB duplicate inside
    Velociraptor's volume.
    """
    cp = subprocess.run(
        ["docker", "cp", f"{VELOCIRAPTOR_CONTAINER}:{srv_path}", host_dst],
        capture_output=True, text=True, timeout=900,
    )
    if cp.returncode != 0:
        raise AcquisitionError(
            f"docker cp failed: {cp.stderr.strip()[:300]}"
        )
    subprocess.run(
        ["docker", "exec", VELOCIRAPTOR_CONTAINER, "rm", "-f", srv_path],
        capture_output=True, timeout=30,
    )


# ---------------------------------------------------------------------------
# Magic-byte sanity check — guard against a regression where the fs
# accessor stops stripping the at-rest wrap. Vol3 would otherwise stall
# on a malformed image.
# ---------------------------------------------------------------------------

_BAD_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"\x78\x01", "zlib (level=1)"),
    (b"\x78\x09", "zlib (level=2)"),
    (b"\x78\x9c", "zlib (default)"),
    (b"\x78\xda", "zlib (max)"),
    (b"\x1f\x8b", "gzip"),
    (b"\xff\x06\x00\x00", "Snappy framing"),
)


def _assert_raw_memory(path: str) -> None:
    with open(path, "rb") as f:
        head = f.read(4)
    for magic, name in _BAD_MAGICS:
        if head.startswith(magic):
            raise AcquisitionError(
                f"dump at {path} starts with {name} magic — fs accessor likely failed to unwrap"
            )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def acquire_memory_dump(
    client_id: str,
    *,
    dumps_dir: str = DUMPS_DIR_DEFAULT,
    flow_timeout: int = 3600,
    poll_interval_s: int = 30,
    poll_max_min: int = 90,
    logger: Callable[[str, str], None] | None = None,
    run_id: str | None = None,
    cancel_check: Callable[[], bool] | None = None,
    **overrides,
) -> dict:
    """Capture a memory dump from a Velociraptor client.

    Returns a dict::

        {
          "flow_id": str,
          "client_id": str,
          "hostname": str,
          "host_path": str,        # /data/memory_dumps/<host>-<flow>.raw
          "size_bytes": int,
          "duration_s": float,
        }

    Args:
      client_id: Velociraptor client ID (e.g. ``"C.3653059e5f15efc6"``).
      dumps_dir: Host directory where the .raw lands. Created if missing.
      flow_timeout: Per-flow timeout in seconds (Velociraptor side).
      poll_interval_s: How often to poll flow state.
      poll_max_min: Hard wall-clock cap on the acquisition step.
      logger: Optional ``(msg, level)`` callback for workflow logging.
      run_id: Workflow run id; threaded into the flow-monitor so the
        Stop button kills the in-flight flow via the existing cleanup
        callback infrastructure.
      cancel_check: Optional ``() -> bool`` polled between phases.
      overrides: Keyword overrides for any value in ACQUISITION_DEFAULTS
        (``max_bytes``, ``cpu_limit``, ``compression``, ``urgent``).
    """
    log = logger or (lambda msg, level="info": None)

    cfg = {**ACQUISITION_DEFAULTS, **overrides}
    Path(dumps_dir).mkdir(parents=True, exist_ok=True)

    started = time.time()
    log(f"acquire: target client {client_id}", "info")

    hostname = _client_hostname(client_id)
    log(f"acquire: client hostname={hostname}", "info")

    if cancel_check and cancel_check():
        raise AcquisitionError("cancelled before dispatch")

    log(
        f"acquire: dispatching Windows.Memory.Acquisition "
        f"(max_bytes={cfg['max_bytes']:,} compression={cfg['compression']} "
        f"cpu_limit={cfg['cpu_limit']})",
        "info",
    )
    flow_id = _dispatch_acquisition(
        client_id,
        max_bytes=cfg["max_bytes"],
        cpu_limit=cfg["cpu_limit"],
        compression=cfg["compression"],
        flow_timeout=flow_timeout,
        urgent=cfg["urgent"],
    )
    log(f"acquire: flow_id={flow_id}", "info")

    try:
        # Reuse the validated KAPE poll loop — it already handles the
        # cancel-event + register_cleanup(cancel_flow) wiring + state
        # interpretation (FINISHED/ERROR/CANCELLED) and prints rich
        # log lines for the workflow timeline.
        state = monitor_flow_completion(
            client_id,
            flow_id,
            timeout_seconds=poll_max_min * 60,
            logger=lambda m, level="info": log(f"acquire: {m}", level),
            run_id=run_id,
        )
        if state == "CANCELLED":
            raise AcquisitionError("acquisition cancelled by operator")
        if state != "FINISHED":
            raise AcquisitionError(f"acquisition did not complete (state={state})")
    except Exception:
        # Best-effort: cancel the flow on Velociraptor so we don't
        # leave orphaned in-progress state behind. DeleteFlow handles
        # uploads + metadata atomically.
        try:
            cancel_flow(client_id, flow_id, logger=lambda m, level="info": log(f"acquire: {m}", level))
        except Exception:
            pass
        try:
            _velo_query(
                "SELECT count() AS n FROM Artifact.Server.Utils.DeleteFlow("
                f"ClientId='{client_id}',FlowId='{flow_id}',"
                "ReallyDoIt='Y',Sync='Y')",
                timeout=60,
            )
        except Exception:
            pass
        raise

    if cancel_check and cancel_check():
        raise AcquisitionError("cancelled before extract")

    log("acquire: extracting raw memory via fs accessor", "info")
    srv_tmp, size = _extract_raw_via_fs_accessor(client_id, flow_id)
    log(f"acquire: raw memory ~{size // 1024 // 1024} MB", "info")

    host_dst = str(Path(dumps_dir) / f"{hostname}-{flow_id}.raw")
    log(f"acquire: copying out to {host_dst}", "info")
    _docker_cp_out(srv_tmp, host_dst)

    _assert_raw_memory(host_dst)

    duration = time.time() - started
    log(f"acquire: complete in {duration:.0f}s — {host_dst}", "success")
    return {
        "flow_id": flow_id,
        "client_id": client_id,
        "hostname": hostname,
        "host_path": host_dst,
        "size_bytes": size,
        "duration_s": duration,
    }


def cleanup_velociraptor_flow(
    client_id: str,
    flow_id: str,
    *,
    logger: Callable[[str, str], None] | None = None,
) -> None:
    """Delete a flow's uploads + metadata on the Velociraptor side.

    Used by the pipeline's post-success cleanup hook (and the
    acquisition error path above) to release the ~5 GB filestore
    duplicate Velociraptor keeps after every memory capture.
    Best-effort — never raises.
    """
    log = logger or (lambda msg, level="info": None)
    try:
        rows = _velo_query(
            "SELECT count() AS n FROM Artifact.Server.Utils.DeleteFlow("
            f"ClientId='{client_id}',FlowId='{flow_id}',"
            "ReallyDoIt='Y',Sync='Y')",
            timeout=60,
        )
        log(f"acquire-cleanup: DeleteFlow → {rows[0].get('n') if rows else '?'}", "info")
    except Exception as e:
        log(f"acquire-cleanup: DeleteFlow failed (non-fatal): {e}", "warning")


__all__ = ["acquire_memory_dump", "cleanup_velociraptor_flow", "AcquisitionError"]
