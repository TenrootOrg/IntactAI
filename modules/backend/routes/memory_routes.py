"""Memory-forensics module — Flask routes.

Collection only: dispatch a Volatility/YARA extraction, poll it, stop it. No
per-run LLM/report/chat — all reporting lives at the case level.

Endpoint inventory (all under ``/api/memory/``):
    POST   /run                      → start extraction, returns run_id
    POST   /upload                   → analyze an uploaded memory dump
    GET    /run/<run_id>/status      → poll status + progress + last logs
    POST   /run/<run_id>/stop        → cancel
    GET/POST/PUT/DELETE /blueprints  → memory blueprint CRUD
"""

from __future__ import annotations

import json
import threading
from typing import Any

from flask import Blueprint, jsonify, request

from services.file_storage_service import get_workflow as file_get_workflow
from services.memory import pipeline as memory_pipeline
from services.memory.upload_extract import (
    UploadExtractError,
    extract_memory_from_upload,
)
from services.storage.blueprint_store import (
    delete_blueprint,
    get_blueprint,
    list_blueprints,
    save_blueprint,
)
from services.storage.config_store import load_frontend_config
from services.workflow_service import (
    add_log_to_run,
    create_automation_run,
    request_stop,
    update_run_status,
)


memory_bp = Blueprint("memory", __name__)

_BLUEPRINT_TYPE = "memory"
_VALID_MODES = {"yara", "plugin", "layered"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_module_enabled() -> bool:
    """Memory module gates on ``config.yaml: modules.volweb.enabled``.

    History: 2026-06-10 the operator-facing module key was merged —
    `memory:` was removed from config.yaml because the platform's
    "Memory" feature is just an operator-facing label for VolWeb (the
    memory-forensics stack). So a single `volweb.enabled` toggle now
    controls both memory acquisition + memory analysis. Defaults to
    True if absent (ships enabled out of the box).
    """
    try:
        from config import load_main_config
        cfg = load_main_config() or {}
        modules = cfg.get("modules") or {}
        node = modules.get("volweb")
        if isinstance(node, dict):
            return bool(node.get("enabled", True))
        return True
    except Exception:
        return True


def _get_run(run_id: str) -> dict | None:
    return file_get_workflow(run_id)


_DUMPS_DIR = "/data/memory_dumps"
# Anything smaller than this is not a memory image — it is a stray file, a
# half-written download or a .part. Same floor register_existing_file uses
# before it will insert a VolWeb row.
_MIN_DUMP_BYTES = 1024 * 1024


def _resolve_dump_path(raw: str) -> tuple[bool, str]:
    """Resolve an operator-supplied dump path, or say why not.

    The path arrives from the browser and ends up being read by the pipeline
    and interpolated into a `docker exec` inside the VolWeb container, so it
    is contained to the dumps volume the same way the case purge contains its
    deletes: resolve symlinks FIRST, then require the real path to sit under
    /data/memory_dumps. `..` and a symlink pointing out of the volume both
    fail that check; a prefix test on the raw string would pass both.
    """
    import os
    if not raw:
        return False, "dump_path is required"
    real = os.path.realpath(raw)
    root = os.path.realpath(_DUMPS_DIR)
    if real != root and not real.startswith(root + os.sep):
        return False, f"dump_path must be a file inside {_DUMPS_DIR}"
    if not os.path.isfile(real):
        return False, f"no such dump: {raw}"
    if os.path.getsize(real) < _MIN_DUMP_BYTES:
        return False, f"{raw} is too small to be a memory image"
    return True, real


def _resolve_keep_dump(requested: Any, blueprint: dict | None) -> bool:
    """Should the memory image survive this run?

    Precedence mirrors the timeout overrides: an explicit value in the request
    wins, then ``blueprint.settings.keep_dump``, then off. ``None`` means "not
    specified" — an explicit ``false`` must be able to override a blueprint
    that says true, which is why this is not a plain ``or`` chain.
    """
    if requested is not None:
        return bool(requested)
    return bool(((blueprint or {}).get("settings") or {}).get("keep_dump"))


def _run_visible_in_active_workspace(run: dict) -> bool:
    """Mirror dashboard_routes.py's / azure_routes.py's own workspace check:
    run_id is a predictable ``{automation_type}_{millis}`` string, so without
    this an operator in one case could read the status/logs of, or stop,
    another case's memory-forensics run just by guessing/reusing a run_id.
    No active case_id means no filtering (admin/no-workspace-concept
    context)."""
    from flask import g
    case_id = getattr(g, "case_id", None)
    if not case_id:
        return True
    return run.get("case_id") == case_id


def _llm_config() -> dict:
    """Reuse the agentic LLM config block (the chat module reads from
    ``cfg['agentic']`` already)."""
    cfg = load_frontend_config() or {}
    return cfg


def _spawn_pipeline(run_id: str, **kwargs: Any) -> None:
    """Start the pipeline on a daemon thread so the route returns
    immediately with the run_id."""
    threading.Thread(
        target=memory_pipeline.run_memory_pipeline,
        kwargs={"run_id": run_id, **kwargs},
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/run", methods=["POST"])
def start_memory_run():
    """Kick off a memory pipeline against one client, or against a dump the
    appliance already holds.

    Request body::

      {
        "client_id": "C.3653059e5f15efc6",         // acquire from this endpoint
        "client_name": "DESKTOP-566AT85",          // optional, log nicety
        "blueprint_id": "memory_layered_default",  // optional
        "mode": "layered",                         // optional override
        "case_name": "Cust X — June 2026",         // optional VolWeb case
        "keep_dump": false                         // optional, keep the image
      }

    or, INSTEAD of ``client_id``::

      { "dump_path": "/data/memory_dumps/HOST-F.123.raw" }

    which re-analyses an image already on the shared volume — no endpoint, no
    acquisition, no second copy of the file anywhere.
    """
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400

    data = request.get_json(silent=True) or {}

    client_id = (data.get("client_id") or "").strip()
    dump_path = (data.get("dump_path") or "").strip()

    if dump_path:
        # Re-analysing a dump we already hold: no endpoint is involved, so the
        # Velociraptor guard below must not apply (it would block the one path
        # that works when Velociraptor is down).
        if client_id:
            return jsonify({
                "error": "send either client_id (acquire) or dump_path "
                         "(re-analyse an image already on the appliance), not both"
            }), 400
        ok, resolved_or_err = _resolve_dump_path(dump_path)
        if not ok:
            return jsonify({"error": resolved_or_err}), 400
        dump_path = resolved_or_err
    else:
        # Pre-flight: dispatching Windows.Memory.Acquisition requires the
        # Velociraptor server to be reachable. The /upload and dump_path
        # routes do NOT share this guard because those flows consume a dump
        # file directly — no endpoint-side acquisition involved.
        from services.container_status import require_velociraptor
        err, vstatus = require_velociraptor('memory')
        if err:
            return jsonify(err), vstatus

        if not client_id:
            return jsonify({"error": "client_id is required"}), 400

        # SHAPE VALIDATION (Mythos #2 extended): `client_id` is downstream-
        # interpolated into VQL strings via the memory acquisition path.
        # Same Velociraptor `C.<hex>` shape constraint as everywhere else.
        from services.vql_safety import is_valid_client_id
        if not is_valid_client_id(client_id):
            return jsonify({"error": "client_id must match C.<hex>"}), 400

    client_name = (data.get("client_name") or "").strip() or None
    case_name = (data.get("case_name") or "").strip() or "Volatile Memory"

    # Resolve blueprint (optional) — settings precedence:
    # explicit ``mode`` in request > blueprint.settings.mode > "layered"
    blueprint = None
    bp_id = (data.get("blueprint_id") or "").strip()
    if bp_id:
        blueprint = get_blueprint(_BLUEPRINT_TYPE, bp_id)
        if not blueprint:
            return jsonify({"error": f"blueprint {bp_id!r} not found"}), 404

    mode = (data.get("mode") or "").strip().lower()
    if not mode and blueprint:
        mode = ((blueprint.get("settings") or {}).get("mode") or "").lower()
    if not mode:
        mode = "layered"   # default per the plan
    if mode not in _VALID_MODES:
        return jsonify({"error": f"invalid mode: {mode!r}"}), 400

    # Memory is extraction-only — Volatility plugins + YARA. The LLM/reporting lives
    # at the case level (fusion), so per-run analysis is never requested here.

    # Optional per-run timeout overrides (seconds). Each is honored in
    # the pipeline if provided; otherwise blueprint.settings → defaults.
    # Front-end UI lets the operator bump these for huge dumps or
    # slow hardware without touching defaults.
    # Keep the memory image after the run? Same precedence idiom as the
    # timeouts below: explicit request > blueprint.settings > default (off).
    keep_dump = _resolve_keep_dump(data.get("keep_dump"), blueprint)
    if dump_path:
        # Re-analysing an image the operator deliberately kept. Reclaiming it
        # at the end of this run would consume the thing they saved — and the
        # obvious next step, "try again with YARA too", would need a fresh
        # acquisition. Keeping is not optional on this path.
        keep_dump = True

    timeouts = {}
    for k in ("acquire_flow_timeout_s", "plugin_timeout_s", "yarascan_timeout_s"):
        v = data.get(k)
        if v is not None:
            try:
                timeouts[k] = int(v)
            except (TypeError, ValueError):
                return jsonify({"error": f"{k} must be an integer (seconds)"}), 400

    import os as _os
    if dump_path:
        label = client_name or _os.path.basename(dump_path)
        name = f"Memory ({mode}) — reuse: {label}"
    else:
        label = client_name or client_id
        name = f"Memory ({mode}) — {label}"
    details = {
        "trigger": "reuse" if dump_path else "manual",
        "mode": mode,
        "client_id": client_id,
        "client_name": client_name,
        "case_name": case_name,
        "blueprint_id": bp_id or None,
        "blueprint": (blueprint or {}).get("name") if blueprint else None,
        "timeouts": timeouts or None,
        "keep_dump": keep_dump,
    }

    run_id = create_automation_run(automation_type="memory", name=name, details=details)
    add_log_to_run(
        run_id,
        (f"memory: queued dump={dump_path} mode={mode}" if dump_path
         else f"memory: queued client={client_id} mode={mode}")
        + (f" timeouts={timeouts}" if timeouts else "")
        + (" keep_dump=yes" if keep_dump else ""),
        "info",
    )
    if dump_path:
        add_log_to_run(
            run_id,
            "memory: re-analysing an image already on the appliance — no "
            "acquisition, and the image is kept when this run ends",
            "info",
        )
    update_run_status(run_id, "running", progress=1)

    _spawn_pipeline(
        run_id,
        client_id=client_id,
        client_name=client_name,
        mode=mode,
        case_name=case_name,
        blueprint=blueprint,
        timeouts=timeouts or None,
        keep_dump=keep_dump,
        from_upload_path=dump_path or None,
    )

    return jsonify({
        "run_id": run_id,
        "status": "running",
        "mode": mode,
        "message": f"Memory pipeline started for {label}",
    }), 202


# ---------------------------------------------------------------------------
# Offline upload — operator-supplied memory dump
# ---------------------------------------------------------------------------
#
# Use-case: operator already has the memory image (Velociraptor
# Prepare-Download ZIP, offline-collector output, third-party capture).
# This endpoint accepts the file, extracts a usable raw image, then
# fires the same pipeline as ``/run`` but with the acquire phase
# skipped — pipeline jumps straight to upload-to-VolWeb.
#
# Multipart form fields:
#   * ``file``            — required, the .raw / .bin / .mem / .zip
#   * ``mode``            — optional, default 'layered'
#   * ``case_name``       — optional, default 'Memory <date>'
#   * ``client_name``     — optional, just a label for the workflow row

_UPLOAD_STAGING_DIR = "/data/memory_dumps/_uploads"
# Hard cap on per-upload size. Velociraptor's max_bytes default is
# 64 GiB; this matches. Reject anything bigger at the request edge
# rather than buffering 100 GB to disk and failing later.
_UPLOAD_MAX_BYTES = 68_719_476_736


@memory_bp.route("/api/memory/upload", methods=["POST"])
def upload_memory_dump():
    """Kick off a memory pipeline against an operator-supplied dump."""
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400

    if "file" not in request.files:
        return jsonify({"error": "multipart field 'file' is required"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "uploaded file is empty"}), 400

    mode = (request.form.get("mode") or "layered").strip().lower()
    if mode not in _VALID_MODES:
        return jsonify({"error": f"invalid mode: {mode!r}"}), 400

    case_name = (request.form.get("case_name") or "").strip() or None
    client_name = (request.form.get("client_name") or "").strip() or None
    # Multipart carries everything as text — "false"/"0"/"" all mean off.
    _keep_raw = (request.form.get("keep_dump") or "").strip().lower()
    keep_dump = _keep_raw in ("1", "true", "yes", "on")

    # Stream-save the upload to disk. Flask's `werkzeug.FileStorage`
    # already chunks at 16 KB — we never load the dump into memory.
    import os
    os.makedirs(_UPLOAD_STAGING_DIR, exist_ok=True)
    # Sanitise filename — strip directory components, keep extension.
    safe_name = os.path.basename(f.filename).replace("\x00", "")
    if not safe_name:
        safe_name = "upload.raw"
    # Per-run subdir so concurrent uploads don't clobber each other.
    import uuid
    upload_id = uuid.uuid4().hex[:12]
    upload_dir = os.path.join(_UPLOAD_STAGING_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)
    upload_path = os.path.join(upload_dir, safe_name)

    # Save with a streaming-size guard so an oversized client doesn't
    # fill the disk silently.
    bytes_written = 0
    chunk_size = 16 * 1024 * 1024
    try:
        with open(upload_path, "wb") as out:
            while True:
                chunk = f.stream.read(chunk_size)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > _UPLOAD_MAX_BYTES:
                    raise ValueError(
                        f"upload exceeds {_UPLOAD_MAX_BYTES} bytes — "
                        "split or re-acquire with a smaller max_bytes"
                    )
                out.write(chunk)
    except ValueError as ve:
        # Best-effort cleanup so failed uploads don't leave residue.
        try:
            os.remove(upload_path)
            os.rmdir(upload_dir)
        except OSError:
            pass
        return jsonify({"error": str(ve)}), 413
    except Exception as e:
        try:
            os.remove(upload_path)
            os.rmdir(upload_dir)
        except OSError:
            pass
        return jsonify({"error": f"write failed: {e}"}), 500

    label = client_name or safe_name
    # Sensible default case: ISO date so repeated uploads on the same
    # day group together. Mirrors the frontend default.
    if not case_name:
        from datetime import datetime
        case_name = f"Memory {datetime.now().strftime('%Y-%m-%d')}"

    name = f"Memory ({mode}) — upload: {label}"
    details = {
        "trigger": "upload",
        "mode": mode,
        "client_name": client_name,
        "upload_filename": safe_name,
        "upload_bytes": bytes_written,
        "case_name": case_name,
        "keep_dump": keep_dump,
        # The per-upload staging dir is this run's to clean; record it so the
        # case purge can reclaim it (store.py looks for exactly this key and
        # never found it before).
        "upload_dir": upload_dir,
    }
    run_id = create_automation_run(automation_type="memory", name=name, details=details)
    add_log_to_run(
        run_id,
        f"memory: upload received — {bytes_written // 1024 // 1024} MB ({safe_name})",
        "info",
    )
    update_run_status(run_id, "running", progress=1)

    # Resolve the raw image (ZIP-extract if needed) in a worker thread
    # so a 5 GB ZIP-decompress doesn't block the route. The pipeline
    # is then spawned from the same thread.
    def _resolve_and_run():
        try:
            raw_path = extract_memory_from_upload(
                upload_path,
                staging_dir=upload_dir,
                logger=lambda m, level="info": add_log_to_run(run_id, m, level),
            )
            # If the helper extracted a NEW file from a ZIP, drop the
            # original ZIP — we don't need both on disk.
            if raw_path != upload_path:
                try:
                    os.remove(upload_path)
                except OSError:
                    pass
            add_log_to_run(run_id, f"upload: pipeline will use {raw_path}", "info")
            memory_pipeline.run_memory_pipeline(
                run_id=run_id,
                client_id="",          # no Velociraptor client for offline uploads
                client_name=client_name,
                mode=mode,
                case_name=case_name,
                from_upload_path=raw_path,
                keep_dump=keep_dump,
            )
        except UploadExtractError as ue:
            add_log_to_run(run_id, f"upload: extract failed — {ue}", "error")
            update_run_status(run_id, "failed", error=str(ue))
        except Exception as e:
            add_log_to_run(run_id, f"upload: pipeline failed — {e}", "error")
            update_run_status(run_id, "failed", error=str(e))

    threading.Thread(target=_resolve_and_run, daemon=True).start()
    return jsonify({
        "run_id": run_id,
        "status": "running",
        "mode": mode,
        "message": f"Memory pipeline started for upload ({bytes_written // 1024 // 1024} MB)",
    }), 202


# ---------------------------------------------------------------------------
# Pull another case's memory findings in by workflow id
# ---------------------------------------------------------------------------
#
# Velociraptor's "Add by ID" does this by re-reading the rows from a server
# that still holds them, copying nothing (velociraptor_routes._adopt_from_workflow).
# Memory cannot: VolWeb's per-evidence dir holds the yarascan results and
# cleanup reclaims it with the image, so a live re-fetch at fuse time loses
# every hit. What we copy instead is the snapshot the pipeline writes BEFORE
# cleanup — memory_payload.json, the plugin rows + yara hits, which is exactly
# what the model reads and nothing else. Never the image, never the evidence.

# Fields worth carrying to the new run. Everything else is deliberately left
# behind — see _adopt_details().
_ADOPT_CARRY = ("client_id", "client_name", "case_name", "mode",
                "blueprint", "blueprint_id")


def _payload_path(run_id: str) -> str | None:
    """The run's fusion snapshot, under whichever downloads root exists."""
    import os
    for base in (f"/app/data/downloads/{run_id}", f"/data/downloads/{run_id}"):
        p = os.path.join(base, "memory_payload.json")
        if os.path.exists(p):
            return p
    return None


def _adopt_details(source_details: dict, source_run_id: str) -> dict:
    """What the copied run remembers about the run it came from.

    The omissions are the point. `host_path`, `upload_dir`, `_cleanup_state`,
    `evidence_id` and `evidence_filename` all name storage the SOURCE case
    owns: the case purge deletes `host_path` outright, so carrying it over
    would mean deleting this case destroys the other case's memory image and
    its VolWeb evidence. A copy of the findings owns none of that.
    """
    out = {k: source_details.get(k) for k in _ADOPT_CARRY if source_details.get(k) is not None}
    out["trigger"] = "adopt"
    out["adopted_from"] = source_run_id
    return out


@memory_bp.route("/api/memory/adopt", methods=["POST"])
def adopt_memory_run():
    """Copy another case's memory findings into the active case.

    Body: ``{"run_id": "memory_1790012609712"}`` — a workflow id as the
    Workflows page shows it.
    """
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400

    import json
    import os
    import shutil

    from services.workflow_service import _resolve_case_id
    from routes.velociraptor_routes import _is_workflow_run_id

    data = request.get_json(silent=True) or {}
    source_run_id = (data.get("run_id") or data.get("id") or "").strip()

    # Shape first — the id is used to build filesystem paths below, and the
    # same rule the Velociraptor adopt applies keeps ../.. out of them.
    if not _is_workflow_run_id(source_run_id):
        return jsonify({"error": f"{source_run_id!r} is not a workflow id. Copy one "
                                 f"from the Workflows page, e.g. memory_1790012609712."}), 400

    case_id = _resolve_case_id("memory", None)
    if not case_id:
        return jsonify({"error": "No active case to pull into."}), 400

    source = _get_run(source_run_id)
    if not source:
        return jsonify({"error": f"No workflow with id {source_run_id}. "
                                 f"Copy it from the Workflows page."}), 404
    if source.get("automation_type") != "memory":
        return jsonify({"error": f"{source_run_id} is a "
                                 f"{source.get('automation_type') or 'non-memory'} run. "
                                 f"Velociraptor collections are pulled from the "
                                 f"Velociraptor tab's Add by ID."}), 400
    if source.get("case_id") == case_id:
        return jsonify({"error": f"{source_run_id} is already part of this case.",
                        "duplicate": True, "run_id": source_run_id}), 409

    # Already pulled here? Scoped to the case, like the Velociraptor check: the
    # same run legitimately feeds two cases, this only stops it feeding one
    # case twice. A failed copy does not count — it left nothing behind.
    from services.workflow_service import get_automation_runs_by_case
    for run in (get_automation_runs_by_case(case_id) or []):
        if (run.get("status") or "").lower() in ("failed", "cancelled", "error", "stopped"):
            continue
        if (run.get("details") or {}).get("adopted_from") == source_run_id:
            return jsonify({"error": f"{source_run_id} has already been pulled into this "
                                     f"case as {run.get('run_id')}.",
                            "duplicate": True, "run_id": run.get("run_id")}), 409

    src_payload = _payload_path(source_run_id)
    if not src_payload:
        return jsonify({"error": f"{source_run_id} has no extracted findings to pull "
                                 f"(status {source.get('status') or 'unknown'}). A run that "
                                 f"failed before extraction, or one from before the "
                                 f"findings snapshot existed, holds nothing to copy."}), 400

    src_details = source.get("details") or {}
    host = src_details.get("client_name") or src_details.get("client_id") or source_run_id
    run_id = create_automation_run(
        automation_type="memory",
        name=f"Memory (adopted) — {host}",
        details=_adopt_details(src_details, source_run_id),
        case_id=case_id,
    )

    # Copy the snapshot into the NEW run's own download dir. A fresh id, never
    # the source's: reusing it would let this case's purge delete the other
    # case's payload (services/fusion/case_bundle.py says why at length).
    dest_dir = os.path.join(os.path.dirname(os.path.dirname(src_payload)), run_id)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src_payload, os.path.join(dest_dir, "memory_payload.json"))
    except OSError as e:
        update_run_status(run_id, "failed", error=f"could not copy the findings: {e}")
        return jsonify({"error": f"could not copy the findings: {e}"}), 500

    try:
        with open(os.path.join(dest_dir, "memory_payload.json")) as fh:
            snap = json.load(fh)
        n_plugins = sum(len(v) for v in (snap.get("plugins") or {}).values()
                        if hasattr(v, "__len__"))
        n_yara = len(snap.get("yara") or [])
    except Exception:                        # noqa: BLE001 — a count, not the copy
        n_plugins = n_yara = 0

    add_log_to_run(
        run_id,
        f"memory: pulled the findings of {source_run_id} into this case — "
        f"{n_plugins} plugin rows, {n_yara} YARA hits. The memory image and the "
        f"VolWeb evidence stay with the original run; this case holds a copy of "
        f"the findings only.",
        "info",
    )
    # Terminal status arms the debounced auto-fuse (workflow_service), which is
    # what makes the findings show up in Case Analysis.
    update_run_status(run_id, "completed", progress=100)

    return jsonify({
        "run_id": run_id,
        "from_run": source_run_id,
        "plugin_rows": n_plugins,
        "yara_hits": n_yara,
        "message": f"Pulled {host}'s memory findings into the case",
    }), 202


# ---------------------------------------------------------------------------
# Dumps the appliance already holds
# ---------------------------------------------------------------------------
#
# The dumps volume is shared, not per-case: an image one case kept is readable
# by every case, so "re-use a dump" and "import a dump from another case" are
# the same listing. It says where each file came from so the operator can tell
# them apart.


def _dump_origins() -> dict:
    """Map dump path → the run that produced it, for the listing's labels."""
    origins = {}
    try:
        from services.storage.workflow_store import load_workflows
        for w in load_workflows() or []:
            if w.get("automation_type") != "memory":
                continue
            det = w.get("details") or {}
            path = det.get("host_path") or (det.get("_cleanup_state") or {}).get("host_path")
            if not path:
                continue
            # Newest wins: the same path can be re-analysed many times, and the
            # operator cares which run put the file there, not who read it.
            prev = origins.get(path)
            if prev and prev.get("created_at", "") > (w.get("created_at") or ""):
                continue
            origins[path] = {
                "run_id": w.get("run_id"),
                "client_name": det.get("client_name"),
                "case_id": w.get("case_id"),
                "created_at": w.get("created_at"),
                "status": w.get("status"),
            }
    except Exception:                       # noqa: BLE001 — labels are a nicety
        pass
    return origins


@memory_bp.route("/api/memory/dumps", methods=["GET"])
def list_memory_dumps():
    """Memory images currently on the appliance, newest first."""
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400

    import os
    origins = _dump_origins()
    out = []
    # One level of recursion: uploads land in _uploads/<id>/<file>, everything
    # else sits at the top. Deeper than that is not ours.
    for root, _dirs, files in os.walk(_DUMPS_DIR):
        depth = root[len(_DUMPS_DIR):].strip(os.sep).count(os.sep)
        if depth > 1:
            continue
        for fn in files:
            p = os.path.join(root, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or st.st_size < _MIN_DUMP_BYTES:
                continue
            out.append({
                "path": p,
                "name": os.path.relpath(p, _DUMPS_DIR),
                "size_bytes": st.st_size,
                "mtime": st.st_mtime,
                "origin": origins.get(p),
            })
    out.sort(key=lambda d: d["mtime"], reverse=True)
    total = sum(d["size_bytes"] for d in out)
    return jsonify({"dumps": out, "count": len(out), "total_bytes": total})


# ---------------------------------------------------------------------------
# Status + download
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/run/<run_id>/status", methods=["GET"])
def get_memory_status(run_id):
    run = _get_run(run_id)
    if not run or not _run_visible_in_active_workspace(run):
        return jsonify({"error": "Run not found"}), 404
    # Trim logs to last 200 to keep the polling payload reasonable —
    # the workflows table modal pulls full logs via the dashboard
    # endpoint when expanded.
    logs = run.get("logs") or []
    if isinstance(logs, str):
        try:
            logs = json.loads(logs)
        except Exception:
            logs = []
    return jsonify({
        "run_id": run_id,
        "status": run.get("status"),
        "progress": run.get("progress", 0),
        "name": run.get("name"),
        "error_count": run.get("error_count", 0),
        "details": run.get("details") or {},
        "logs_tail": (logs or [])[-200:],
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
    })


@memory_bp.route("/api/memory/run/<run_id>/stop", methods=["POST"])
def stop_memory_run(run_id):
    run = _get_run(run_id)
    if not run or not _run_visible_in_active_workspace(run):
        return jsonify({"error": "Run not found"}), 404
    request_stop(run_id)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Blueprint CRUD
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/blueprints", methods=["GET"])
def list_memory_blueprints():
    return jsonify({"blueprints": list_blueprints(_BLUEPRINT_TYPE) or []})


@memory_bp.route("/api/memory/blueprints", methods=["POST"])
def create_memory_blueprint():
    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return jsonify({"error": "name is required"}), 400
    # Every write must have a real id — without this, save_blueprint()
    # inserts (id=NULL, ...), the follow-up get-by-id lookup finds nothing,
    # and the route returns {"blueprint": null} with a 201 while silently
    # clobbering the same NULL-id row on every subsequent create. Mirrors
    # the id-generation already done by the sibling /api/blueprints/memory
    # route (routes/blueprint_routes.py), which writes the SAME table.
    if not data.get("id"):
        import time
        data["id"] = f"custom_{int(time.time() * 1000)}"
    bp = save_blueprint(_BLUEPRINT_TYPE, data)
    # A failed save must not report 201. save_blueprint swallows storage errors
    # and returns falsy (it logs "[STORAGE] Error saving ..."), so this returned
    # {"blueprint": null} with 201 Created — the operator's blueprint silently
    # did not exist, and the UI had nothing to show but no error to report.
    # Observed live when the backend's SQLite connection went stale and every
    # write raised "disk I/O error" while the route kept answering 201.
    # The sibling /api/blueprints/memory route already 500s on the same
    # condition; this makes the two agree.
    if not bp:
        return jsonify({"error": "Failed to save blueprint"}), 500
    return jsonify({"blueprint": bp}), 201


@memory_bp.route("/api/memory/blueprints/<bp_id>", methods=["PUT"])
def update_memory_blueprint(bp_id):
    existing = get_blueprint(_BLUEPRINT_TYPE, bp_id)
    if not existing:
        return jsonify({"error": "blueprint not found"}), 404
    data = request.get_json(silent=True) or {}
    data["id"] = bp_id
    bp = save_blueprint(_BLUEPRINT_TYPE, data)
    return jsonify({"blueprint": bp})


@memory_bp.route("/api/memory/blueprints/<bp_id>", methods=["DELETE"])
def delete_memory_blueprint(bp_id):
    ok = delete_blueprint(_BLUEPRINT_TYPE, bp_id)
    if not ok:
        return jsonify({"error": "blueprint not found"}), 404
    return jsonify({"ok": True})


@memory_bp.route("/api/memory/available_plugins", methods=["GET"])
def list_available_memory_plugins():
    """Return the catalog of Volatility 3 Windows plugins surfaced to
    the Blueprints memory editor. Used to render the checkbox grid so
    operators don't have to type dotted class paths. Grouped by purpose
    for the UI's section headers.
    """
    from services.memory.defaults import KNOWN_VOL3_PLUGINS
    # Group preserving insertion order — Python dicts since 3.7 keep
    # insertion order, which gives the UI a stable section layout.
    groups: dict[str, list[str]] = {}
    for group_label, class_path in KNOWN_VOL3_PLUGINS:
        groups.setdefault(group_label, []).append(class_path)
    return jsonify({
        "groups": [
            {"label": label, "plugins": plugins}
            for label, plugins in groups.items()
        ],
    })


__all__ = ["memory_bp"]
