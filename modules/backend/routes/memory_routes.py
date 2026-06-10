"""Memory-forensics module — Flask routes.

End-to-end pipeline dispatch + workflow polling + report download +
interactive chat + rerun. Mirrors :mod:`routes.agentic_routes` so the
frontend's existing chat + workflow patterns drop in unchanged.

Endpoint inventory (all under ``/api/memory/``):

  Dispatch + lifecycle:
    POST   /run                      → start pipeline, returns run_id
    GET    /run/<run_id>/status      → poll status + progress + last logs
    GET    /run/<run_id>/download    → raw markdown report
    POST   /run/<run_id>/stop        → cancel
    POST   /run/<run_id>/rerun       → re-analyze with optional master prompt

  Interactive validation (chat):
    GET    /run/<run_id>/chat                → transcript + state
    POST   /run/<run_id>/chat                → user turn
    DELETE /run/<run_id>/chat                → clear
    POST   /run/<run_id>/chat/synthesize     → compress → master prompt
    PUT    /run/<run_id>/master-prompt       → operator override

  Blueprints (memory blueprint type, same store as agentic/velo):
    GET    /blueprints                       → list
    POST   /blueprints                       → create
    PUT    /blueprints/<id>                  → update
    DELETE /blueprints/<id>                  → delete

All chat endpoints delegate to ``services.agentic.chat`` — the chat
infrastructure is LLM-agnostic and already operates on
``workflow.details.chat_messages``. No memory-specific chat code.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from flask import Blueprint, Response, jsonify, request

from services.agentic import chat as agentic_chat
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
    """Kick off a memory pipeline against one client.

    Request body::

      {
        "client_id": "C.3653059e5f15efc6",
        "client_name": "DESKTOP-566AT85",          // optional, log nicety
        "blueprint_id": "memory_layered_default",  // optional
        "mode": "layered",                         // optional override
        "case_name": "Cust X — June 2026"          // optional VolWeb case
      }
    """
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400
    data = request.get_json(silent=True) or {}

    client_id = (data.get("client_id") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400

    # SHAPE VALIDATION (Mythos #2 extended): `client_id` is downstream-
    # interpolated into VQL strings via the memory acquisition path.
    # Same Velociraptor `C.<hex>` shape constraint as everywhere else.
    from services.vql_safety import is_valid_client_id
    if not is_valid_client_id(client_id):
        return jsonify({"error": "client_id must match C.<hex>"}), 400

    client_name = (data.get("client_name") or "").strip() or None
    case_name = (data.get("case_name") or "").strip() or "Memory"

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

    # use_llm: operator-toggleable in the UI. Default True (keeps the
    # existing behavior — full LLM analysis runs). False = skip Phase 5,
    # emit an extraction-only markdown report.
    use_llm = data.get("use_llm")
    if use_llm is None:
        use_llm = True
    use_llm = bool(use_llm)

    # Optional per-run timeout overrides (seconds). Each is honored in
    # the pipeline if provided; otherwise blueprint.settings → defaults.
    # Front-end UI lets the operator bump these for huge dumps or
    # slow hardware without touching defaults.
    timeouts = {}
    for k in ("acquire_flow_timeout_s", "plugin_timeout_s", "yarascan_timeout_s"):
        v = data.get(k)
        if v is not None:
            try:
                timeouts[k] = int(v)
            except (TypeError, ValueError):
                return jsonify({"error": f"{k} must be an integer (seconds)"}), 400

    label = client_name or client_id
    name = f"Memory ({mode}) — {label}"
    details = {
        "trigger": "manual",
        "mode": mode,
        "client_id": client_id,
        "client_name": client_name,
        "case_name": case_name,
        "blueprint_id": bp_id or None,
        "blueprint": (blueprint or {}).get("name") if blueprint else None,
        "use_llm": use_llm,
        "timeouts": timeouts or None,
    }

    run_id = create_automation_run(automation_type="memory", name=name, details=details)
    add_log_to_run(
        run_id,
        f"memory: queued client={client_id} mode={mode} use_llm={use_llm}"
        + (f" timeouts={timeouts}" if timeouts else ""),
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
        use_llm=use_llm,
        timeouts=timeouts or None,
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
    # use_llm is sent as a string from FormData — coerce to bool.
    use_llm_raw = (request.form.get("use_llm") or "true").strip().lower()
    use_llm = use_llm_raw not in ("false", "0", "no", "off")

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
        "use_llm": use_llm,
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
                use_llm=use_llm,
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
# Status + download
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/run/<run_id>/status", methods=["GET"])
def get_memory_status(run_id):
    run = _get_run(run_id)
    if not run:
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


@memory_bp.route("/api/memory/run/<run_id>/download", methods=["GET"])
def download_memory_report(run_id):
    """Serve the markdown report stored in workflow.details.report_md."""
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    details = run.get("details") or {}
    md = details.get("report_md") or ""
    if not md:
        return jsonify({"error": "Report not yet available"}), 404
    fname = f"memory-{run_id}.md"
    return Response(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@memory_bp.route("/api/memory/run/<run_id>/stop", methods=["POST"])
def stop_memory_run(run_id):
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    request_stop(run_id)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Rerun (with optional master_prompt)
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/run/<run_id>/rerun", methods=["POST"])
def rerun_memory(run_id):
    """Re-analyze an existing run.

    Skips the expensive phases (acquire/upload/extract) and feeds the
    operator's master prompt rider through the LLM analyzer against
    the already-uploaded evidence. Mirrors agentic's
    "reports-only rerun" path so the operator pays one LLM call's
    worth of tokens for an iteration after the chat-validation step.
    """
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404

    details = run.get("details") or {}
    evidence_id = details.get("evidence_id")
    if not evidence_id:
        return jsonify({"error": "Original run has no evidence_id to rerun against"}), 400

    body = request.get_json(silent=True) or {}
    # Caller can override the mode (e.g. cheap-rerun in yara-only) or
    # inherit from the original.
    mode = (body.get("mode") or details.get("mode") or "layered").lower()
    if mode not in _VALID_MODES:
        return jsonify({"error": f"invalid mode: {mode!r}"}), 400

    # Pull the master_prompt from the chat module's state if present.
    chat_state = agentic_chat.get_chat_state(run_id) or {}
    master_prompt = chat_state.get("master_prompt") or details.get("master_prompt")

    # Create a NEW workflow row for the rerun so the operator sees both
    # the original AND the rerun in the workflows table.
    base_name = (run.get("name") or f"Memory rerun of {run_id}").split(" [v")[0]
    rerun_version = int(details.get("report_version") or 1) + 1
    new_name = f"{base_name} [v{rerun_version}]"
    new_details = {
        "trigger": "rerun",
        "mode": mode,
        "client_id": details.get("client_id"),
        "client_name": details.get("client_name"),
        "case_name": details.get("case_name"),
        "blueprint_id": details.get("blueprint_id"),
        "rerun_from": run_id,
        "rerun_from_evidence": evidence_id,
        "report_version": rerun_version,
        "master_prompt": master_prompt,
    }
    new_run_id = create_automation_run(
        automation_type="memory", name=new_name, details=new_details,
    )
    add_log_to_run(
        new_run_id,
        f"memory: rerun from {run_id} evidence={evidence_id} mode={mode}",
        "info",
    )
    update_run_status(new_run_id, "running", progress=1)

    _spawn_pipeline(
        new_run_id,
        client_id=details.get("client_id") or "",
        client_name=details.get("client_name"),
        mode=mode,
        case_name=details.get("case_name") or "Memory",
        master_prompt=master_prompt,
        rerun_from_evidence=int(evidence_id),
    )

    return jsonify({
        "run_id": new_run_id,
        "rerun_from": run_id,
        "mode": mode,
        "message": "Memory pipeline rerun started",
    }), 202


# ---------------------------------------------------------------------------
# Interactive chat (delegate to services.agentic.chat)
# ---------------------------------------------------------------------------


@memory_bp.route("/api/memory/run/<run_id>/chat", methods=["GET"])
def get_memory_chat(run_id):
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(agentic_chat.get_chat_state(run_id))


@memory_bp.route("/api/memory/run/<run_id>/chat", methods=["POST"])
def post_memory_chat(run_id):
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    data = request.get_json(silent=True) or {}
    try:
        reply = agentic_chat.send_chat_message(run_id, data.get("message", ""), _llm_config())
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except RuntimeError as re_:
        return jsonify({"error": str(re_)}), 502
    return jsonify({"assistant": reply})


@memory_bp.route("/api/memory/run/<run_id>/chat", methods=["DELETE"])
def clear_memory_chat(run_id):
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    agentic_chat.clear_chat(run_id)
    return jsonify({"ok": True})


@memory_bp.route("/api/memory/run/<run_id>/chat/synthesize", methods=["POST"])
def synthesize_memory_chat(run_id):
    if not _is_module_enabled():
        return jsonify({"error": "Memory module is not enabled."}), 400
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    try:
        master = agentic_chat.synthesize_master_prompt(run_id, _llm_config())
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except RuntimeError as re_:
        return jsonify({"error": str(re_)}), 502
    return jsonify({"master_prompt": master})


@memory_bp.route("/api/memory/run/<run_id>/master-prompt", methods=["PUT"])
def update_memory_master_prompt(run_id):
    run = _get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    data = request.get_json(silent=True) or {}
    agentic_chat.set_master_prompt(run_id, data.get("master_prompt"))
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
    bp = save_blueprint(_BLUEPRINT_TYPE, data)
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
