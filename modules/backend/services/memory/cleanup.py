"""Post-run cleanup of memory-dump residue.

The PoC's :file:`pipeline.sh` enumerated five places a multi-GB dump
landed and silently leaked when the workflow failed partway. This
module is the in-tree port of that ``trap cleanup EXIT`` hook —
called from :mod:`services.memory.pipeline` after success AND on
every failure path unless ``NO_CLEANUP=1`` is set for debugging.

Cleanup order matters: ``Server.Utils.DeleteFlow`` must run FIRST
because it needs to read the flow's ``uploads.json`` to enumerate
what to delete. A naive ``rm -rf`` first would leave the metadata
intact and the GUI would show an empty zombie flow.

Each step is best-effort and never raises — a flaky cleanup must not
mask the actual workflow result. Failures get logged at ``warning``
level so an operator can spot stale artefacts in the timeline.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable

from config import VELOCIRAPTOR_CONTAINER

from .acquire import cleanup_velociraptor_flow
from .volweb_client import VolWebClient, VolWebError, _config_value


def _backend_container_name() -> str:
    return _config_value("backend_container", default="intact_volweb_backend")


def _remove_host_dump(host_path: str, log: Callable[[str, str], None]) -> None:
    try:
        p = Path(host_path)
        if p.is_file():
            p.unlink()
            log(f"cleanup: removed host dump {host_path}", "info")
    except Exception as e:
        log(f"cleanup: host dump remove failed (non-fatal): {e}", "warning")


def _remove_volweb_media_raw(
    evidence_filename: str, log: Callable[[str, str], None]
) -> None:
    """Belt-and-suspenders ``rm`` of the .raw inside VolWeb's media
    volume. Django's ``DELETE /api/evidences/<id>/`` does not always
    cascade the on-disk file (observed orphan 5 GB ``.raw`` files in
    the PoC after the row went away).

    Tries both candidate locations: ``evidences/`` (legacy HTTP-upload
    path) and ``staging/`` (shared-volume fast-path). Whichever exists
    gets removed; the other rm is silently no-op.
    """
    if not evidence_filename:
        return
    container = _backend_container_name()
    cmd = [
        "docker", "exec", container, "sh", "-c",
        f"rm -f /home/app/web/media/evidences/{evidence_filename} "
        f"/home/app/web/media/staging/{evidence_filename}",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            log(
                f"cleanup: volweb media rm non-zero ({r.returncode}): "
                f"{r.stderr.strip()[:200]}",
                "warning",
            )
        else:
            log(f"cleanup: removed VolWeb media {evidence_filename} (evidences/ + staging/)", "info")
    except FileNotFoundError:
        log("cleanup: docker CLI not available — skipped media rm", "warning")
    except subprocess.TimeoutExpired:
        log("cleanup: volweb media rm timed out — continuing", "warning")


def _remove_volweb_media_dir(
    evidence_id: int, log: Callable[[str, str], None]
) -> None:
    """Tidy the per-evidence dir (yarascan jsonl, rendered rules)."""
    container = _backend_container_name()
    cmd = [
        "docker", "exec", container,
        "rm", "-rf", f"/home/app/web/media/{int(evidence_id)}",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        log(f"cleanup: per-evidence dir rm failed (non-fatal): {e}", "warning")


def cleanup_after_run(
    *,
    client_id: str | None,
    flow_id: str | None,
    host_path: str | None,
    evidence_id: int | None,
    evidence_filename: str | None,
    volweb_client: VolWebClient | None,
    delete_evidence_row: bool = False,
    preserve_evidence_dir: bool = False,
    logger: Callable[[str, str], None] | None = None,
) -> None:
    """Sweep every place memory data lands.

    Args:
      client_id, flow_id: identify the Velociraptor flow to
        ``DeleteFlow`` (removes the server-side .raw + flow metadata).
      host_path: ``/data/memory_dumps/<host>-<flow>.raw`` to ``unlink``.
      evidence_id, evidence_filename: VolWeb evidence to clean up.
        If ``delete_evidence_row=True`` the row is deleted too (which
        cascades plugin + yarascan rows). Otherwise only on-disk files
        are removed; the DB rows + LLM report stay (the default — the
        operator wants the analysis to survive auto-purge).
      volweb_client: optional client for the DB-row delete. Passed in
        rather than constructed so the same auth state is reused.

    Never raises. Failures are logged at ``warning`` level.

    The ``NO_CLEANUP=1`` env var short-circuits the entire function,
    matching the PoC's debug knob. Useful when iterating on the
    analyze step against a known dump.
    """
    log = logger or (lambda msg, level="info": None)

    if os.environ.get("NO_CLEANUP") == "1":
        log("cleanup: skipped (NO_CLEANUP=1)", "info")
        return

    # 1. Velociraptor server-side (must come first — needs uploads.json).
    if client_id and flow_id:
        cleanup_velociraptor_flow(client_id, flow_id, logger=log)

    # 2. Host-side .raw from the local extract step.
    if host_path:
        _remove_host_dump(host_path, log)

    # 3. VolWeb-side residue.
    if evidence_id:
        # Belt-and-suspenders: even if we don't delete the row, the
        # media .raw is the multi-GB hog. Remove it. Plugin + yarascan
        # results stay in the DB.
        #
        # The .raw staging file is safe to remove even while a yarascan
        # is still reading it: the worker holds an open fd, so Linux
        # keeps the inode alive until the scan finishes (unlink only
        # drops the name). Freeing the path matters on disk-tight hosts.
        if evidence_filename:
            _remove_volweb_media_raw(evidence_filename, log)
        # The per-evidence dir (media/<id>/) holds the yarascan
        # results jsonl the worker streams into. If the scan is STILL
        # running (the yarascan wait timed out rather than completing),
        # removing this dir destroys the in-flight matches — exactly
        # what cost 84 real hits on 2026-06-17. Preserve it in that
        # case; a later run's cleanup or the operator can reclaim it.
        if preserve_evidence_dir:
            log(
                f"cleanup: PRESERVING media/{evidence_id}/ — yarascan still "
                f"running; removing it now would destroy in-flight matches. "
                f"The dir + results survive for this evidence.",
                "warning",
            )
        elif delete_evidence_row:
            # Full purge requested ('Delete scan') — drop the analysis dir too.
            _remove_volweb_media_dir(evidence_id, log)
        else:
            # DEFAULT: KEEP the per-evidence dir. It holds the yarascan RESULTS
            # jsonl (small) — the analysis OUTPUT, not the multi-GB .raw (already
            # reclaimed above). Deleting it 404'd BOTH VolWeb's YARA Scan tab and
            # the Case-fusion lazy fetch, for zero real space saving.
            log(
                f"cleanup: keeping media/{evidence_id}/ — yarascan results stay "
                f"browsable in VolWeb and readable by Case fusion (only the .raw "
                f"is reclaimed)",
                "info",
            )

        if delete_evidence_row and volweb_client is not None:
            try:
                volweb_client.delete_evidence(evidence_id)
                log(f"cleanup: VolWeb evidence_id={evidence_id} deleted", "info")
            except VolWebError as e:
                log(f"cleanup: evidence delete failed (non-fatal): {e}", "warning")


__all__ = ["cleanup_after_run"]
