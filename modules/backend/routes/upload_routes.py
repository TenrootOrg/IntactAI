#!/usr/bin/env python3
"""
Upload Routes - Handle tus upload webhooks for resumable file uploads

All upload progress is tracked in the Workflows tab via workflow runs.
"""

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
import json
import threading
import traceback
import base64

from services.workflow_service import create_automation_run, add_log_to_run, update_run_status

upload_bp = Blueprint('uploads', __name__)

# Store mapping of upload_id -> run_id for workflow tracking. This is an
# in-memory cache only — if the backend restarts between an upload's pre-create
# and post-finish the mapping is lost, so _resolve_upload_run() falls back to
# durable storage (the run carries its upload_id in details). Without that
# recovery the upload run orphans at RUNNING and processing spawns a SECOND run
# instead of continuing the same workflow.
_upload_runs = {}


def _resolve_upload_run(upload_id, *, pop=False):
    """Return the run_id for this upload — from the in-memory map, or recovered
    from storage by matching details.upload_id. Keeps upload + processing as ONE
    workflow even if the backend restarted mid-upload."""
    if not upload_id:
        return None
    run_id = _upload_runs.pop(upload_id, None) if pop else _upload_runs.get(upload_id)
    if run_id:
        return run_id
    try:
        from services.workflow_service import get_all_automation_runs
        for r in get_all_automation_runs():
            d = r.get("details") or {}
            if d.get("upload_id") == upload_id:
                rid = r.get("id") or r.get("run_id")
                if rid:
                    print(f"[TUS HOOK] recovered upload run {rid} for {upload_id} "
                          f"(in-memory map was empty — backend likely restarted)", flush=True)
                    return rid
    except Exception as e:
        print(f"[TUS HOOK] upload-run recovery failed: {e}", flush=True)
    return None


def decode_tus_metadata(metadata_str):
    """Decode tus metadata from base64-encoded key-value pairs

    Format: "key1 base64value1,key2 base64value2"
    """
    if not metadata_str:
        return {}

    result = {}
    pairs = metadata_str.split(',')
    for pair in pairs:
        parts = pair.strip().split(' ', 1)
        if len(parts) == 2:
            key = parts[0]
            try:
                # Decode base64 value
                value = base64.b64decode(parts[1]).decode('utf-8')
                result[key] = value
            except Exception:
                result[key] = parts[1]
        elif len(parts) == 1 and parts[0]:
            result[parts[0]] = ''

    return result


def _fuse_offline_import(import_result, upload_run_id):
    """After an offline-collector ZIP is imported into Velociraptor, fuse the
    imported data into the Case — as a final step of the SAME upload run (one
    workflow row). There is NO agent and NO LLM here: this only reads the
    imported rows back from Velociraptor and persists them so the fusion graph
    can pick them up (velociraptor_upload is a fusion member — see
    workflow_service.AGENTIC_TYPES + the fusion-store dispatch). Any LLM analysis
    is a separate, explicit Case-level action the operator chooses to run later.

    A collector ZIP may import as a HUNT (multi-host export — the real per-client
    data lives under the hunt, not the server import flow) or as a single client
    FLOW. Prefer the hunt; fall back to the flow."""
    if not (isinstance(import_result, dict) and import_result.get("success")
            and upload_run_id):
        return
    hunt_id = import_result.get("hunt_id")
    flow_id = import_result.get("flow_id")
    if not (hunt_id or flow_id):
        # Say so. This used to return silently, so an import that produced
        # neither id looked to the operator like fusion had simply never been
        # attempted — no log line anywhere explained the missing case data.
        try:
            from services.workflow_service import add_log_to_run
            add_log_to_run(upload_run_id,
                           "[Import] No hunt_id or flow_id came back from the "
                           "import — nothing to fuse into the case.", "warning")
        except Exception:
            pass
        return
    try:
        from services.workflow_service import (
            get_automation_run, add_log_to_run, update_run_status)
        from services.file_storage_service import save_workflow
        from services.agentic.collectors import get_existing_collection_results, persist_pipeline_artifacts

        add_log_to_run(upload_run_id, "[Import] Reading imported data into the case…")
        if hunt_id:
            # Hunt: enumerate every imported client's flow and pull their rows.
            all_results, artifacts, client_info = get_existing_collection_results(
                upload_run_id, flow_id=None, hunt_id=hunt_id, client_ids=None)
        else:
            client_id = import_result.get("client_id")
            all_results, artifacts, client_info = get_existing_collection_results(
                upload_run_id, flow_id=flow_id, hunt_id=None,
                client_ids=[client_id] if client_id else None)

        total_rows = sum(len(rows) for rows in (all_results or {}).values())
        if total_rows == 0:
            add_log_to_run(upload_run_id,
                           "[Import] Import had no rows to fuse into the case.", "warning")
            return

        # Seed the run's hostnames map (client_id -> hostname) so the Case host
        # cards show friendly names. client_info comes back as cid -> {hostname,…};
        # the mapper also falls back to each row's own hostname column.
        run = get_automation_run(upload_run_id) or {}
        det = run.get("details") or {}
        hn = dict(det.get("hostnames") or {})
        for cid, info in (client_info or {}).items():
            name = (info or {}).get("hostname") if isinstance(info, dict) else None
            if cid and name:
                hn[str(cid)] = name
        if hn:
            det["hostnames"] = hn
        det["offline_hunt_id" if hunt_id else "offline_flow_id"] = hunt_id or flow_id
        # Capture the imported hunt's description ('[Agentic] …' for agentic
        # collectors). It's the only agentic-provenance signal that survives the
        # offline-collector ZIP round-trip — fusion reads it to classify this
        # upload as an agentic run (see fusion.store._is_agentic_run).
        if hunt_id:
            try:
                from services.velociraptor_service import get_hunt_description
                hd = get_hunt_description(hunt_id)
                if hd:
                    det["hunt_description"] = hd
                    add_log_to_run(upload_run_id, f"[Import] Imported hunt: {hd}")
            except Exception:
                hd = ""
        else:
            hd = ""
        # Tag the import agentic-or-general from the imported hunt description
        # ('[Agentic] …' for agentic collectors). The import ALWAYS fuses; this
        # flag only decides whether it counts toward 'Velociraptor (Agentic)' vs
        # only 'Velociraptor (All)' in the Case Analysis modules picker.
        det["is_agentic"] = "agentic" in (hd or "").lower()
        # The offline-collector ZIP round-trip loses the '[Agentic]' description (a
        # collection ZIP is named 'Collection-<host>-<ts>.zip', not the collector), so a
        # collection generated from an agentic blueprint (e.g. "Velociraptor Agentic:
        # Quick Wins") gets mis-classified non-agentic and silently excluded from the
        # 'Velociraptor (Agentic)' fusion module. Fall back to CONTENT: if the imported
        # artifacts are mostly an agentic blueprint's set, tag it agentic. Best-effort.
        if not det["is_agentic"]:
            try:
                from services.storage.blueprint_store import load_agentic_blueprints
                imported = {str(a).split("/")[-1].strip().lower() for a in (artifacts or []) if a}
                best = None
                for bp in (load_agentic_blueprints() or []):
                    bparts = {str(x).split("/")[-1].strip().lower() for x in (bp.get("artifacts") or []) if x}
                    ov = len(imported & bparts)
                    # majority of what was collected belongs to this agentic blueprint
                    if imported and ov >= 2 and ov >= (len(imported) + 1) // 2:
                        if not best or ov > best[1]:
                            best = (bp.get("name") or "agentic blueprint", ov)
                if best:
                    det["is_agentic"] = True
                    add_log_to_run(upload_run_id,
                                   f"[Import] Classified agentic by artifact match: {best[0]} "
                                   f"({best[1]}/{len(imported)} imported artifacts)")
            except Exception:
                pass
        run["details"] = det
        try:
            save_workflow(run)
        except Exception:
            pass

        # Persist rows where the fusion graph reads them (/data/downloads/<rid>).
        persist_pipeline_artifacts(upload_run_id, all_results)
        add_log_to_run(
            upload_run_id,
            f"[Import] Added {total_rows} rows across {len(artifacts)} artifact(s) "
            f"from {len(client_info or {})} host(s) to the workspace.", "success")
        update_run_status(upload_run_id, "completed", progress=100)

        # Do NOT auto-fuse. The imported data is now a member of the workspace;
        # FUSION (building the case graph — a heavy correlation pass) is an
        # explicit operator action in Case Analysis (the Fusion button), so it
        # only runs when the analyst asks for it. Same rule as every other module:
        # runs are tagged to the workspace on completion; fusion is on demand.
        add_log_to_run(
            upload_run_id,
            "[Import] Data added to the workspace. Open Case Analysis and click "
            "Fusion to build the case graph.", "info")
    except Exception as e:
        print(f"[OFFLINE IMPORT] fuse of imported data failed: {e}", flush=True)
        import traceback
        traceback.print_exc()


@upload_bp.route('/api/uploads/hook', methods=['POST'])
def handle_tus_hook():
    """Handle tusd webhook events (pre-create, post-finish)

    tusd sends HTTP hooks with JSON body format:
    {
        "Type": "pre-create" | "post-finish" | ...,
        "Event": {
            "Upload": { "ID": "...", "Size": N, "MetaData": {...} },
            "HTTPRequest": { ... }
        }
    }
    """
    try:
        data = request.get_json(force=True) or {}

        # tusd sends event type in body, not header
        event_type = data.get('Type', '')

        # Upload info is nested under Event.Upload
        event_data = data.get('Event', {})
        upload_info = event_data.get('Upload', {})

        # Metadata is already decoded by tusd
        metadata = upload_info.get('MetaData', {})

        print(f"[TUS HOOK] Event: {event_type}", flush=True)
        print(f"[TUS HOOK] Upload ID: {upload_info.get('ID', 'unknown')}", flush=True)
        print(f"[TUS HOOK] Size: {upload_info.get('Size', 0)}", flush=True)
        # Redact any decryption password before logging the metadata.
        _meta_log = {k: ('***' if k == 'password' else v) for k, v in (metadata or {}).items()}
        print(f"[TUS HOOK] Metadata: {_meta_log}", flush=True)

        if event_type == 'pre-create':
            # Validate upload before it starts (no ID assigned yet)
            purpose = metadata.get('purpose', '')
            filename = metadata.get('filename', '')

            if purpose not in ['velociraptor', 'timesketch', 'upgrade_package', 'agentic_external']:
                print(f"[TUS HOOK] Rejected: Invalid purpose '{purpose}'", flush=True)
                return jsonify({
                    "RejectUpload": True,
                    "HTTPResponse": {
                        "StatusCode": 400,
                        "Body": json.dumps({"error": "Invalid upload purpose. Must be 'velociraptor', 'timesketch', 'upgrade_package', or 'agentic_external'"})
                    }
                }), 200  # Return 200 but with RejectUpload flag

            # Validate file extension based on purpose
            if purpose == 'upgrade_package':
                # '.tar' is accepted alongside the compressed forms. A wrapper
                # package carries the release's per-module assets unchanged, and
                # those are already-gzipped docker layers: re-gzipping the
                # wrapper measured 0.55% smaller (31 MB on 5.44 GB) for a full
                # single-threaded deflate pass over 5.4 GB, so prepare may hand
                # the operator a plain .tar. Rejecting it here would refuse the
                # upload before any of the readers downstream ever saw it.
                if not (filename.lower().endswith('.tar.gz')
                        or filename.lower().endswith('.tgz')
                        or filename.lower().endswith('.tar')):
                    print(f"[TUS HOOK] Rejected: Not a tar file '{filename}'", flush=True)
                    return jsonify({
                        "RejectUpload": True,
                        "HTTPResponse": {
                            "StatusCode": 400,
                            "Body": json.dumps({"error": "Upgrade packages must be .tar.gz, .tgz or .tar files"})
                        }
                    }), 200
            elif purpose == 'agentic_external':
                # Accept text-based log files for external log data
                allowed_extensions = ['.csv', '.json', '.jsonl', '.log', '.txt', '.xml', '.tsv', '.evtx', '.syslog']
                filename_lower = filename.lower()
                if not any(filename_lower.endswith(ext) for ext in allowed_extensions):
                    print(f"[TUS HOOK] Rejected: Not a supported log file '{filename}'", flush=True)
                    return jsonify({
                        "RejectUpload": True,
                        "HTTPResponse": {
                            "StatusCode": 400,
                            "Body": json.dumps({"error": f"Supported formats: {', '.join(allowed_extensions)}"})
                        }
                    }), 200
            elif not filename.lower().endswith('.zip'):
                print(f"[TUS HOOK] Rejected: Not a ZIP file '{filename}'", flush=True)
                return jsonify({
                    "RejectUpload": True,
                    "HTTPResponse": {
                        "StatusCode": 400,
                        "Body": json.dumps({"error": "Only ZIP files are accepted"})
                    }
                }), 200

            print(f"[TUS HOOK] Validated upload: {filename} for {purpose}", flush=True)
            return jsonify({"ok": True})

        elif event_type == 'post-create':
            # Upload created - ID is now assigned, create workflow
            upload_id = upload_info.get('ID', '')
            purpose = metadata.get('purpose', '')
            filename = metadata.get('filename', '')
            upload_size = upload_info.get('Size', 0)
            size_mb = upload_size / (1024 * 1024) if upload_size else 0

            workflow_type = f"{purpose}_upload"
            workflow_name = f"Upload: {filename}"

            # If the browser PRE-CREATED the workflow row (so the operator sees
            # it the instant they click Apply, before this hook fires — the run
            # otherwise only appears once tusd assigns an ID and calls us), reuse
            # that run instead of opening a second one. Its id rides in the
            # upload metadata as `upload_run_id`. This keeps ONE row for the
            # whole import and makes it appear immediately.
            provided_run = (metadata.get('upload_run_id') or '').strip()
            if provided_run:
                try:
                    from services.file_storage_service import get_workflow as _get_wf
                    if _get_wf(provided_run):
                        _upload_runs[upload_id] = provided_run
                        # Write the id into the RUN as well, not just the
                        # in-memory map. The map is popped at post-finish and
                        # lost on restart, and details.upload_id is the only
                        # durable join anyone else has: _resolve_upload_run's
                        # storage fallback, _close_orphan_upload_run, and
                        # sweep_applied_upload_packages' 4 GiB reclaim all key
                        # off it. A pre-created row never had it, so all three
                        # matched nothing and silently did nothing — the reason
                        # an upload row sat at running/10% for 40+ minutes on
                        # 2026-08-05 while a second run did the apply.
                        try:
                            from services.workflow_service import mutate_run_details
                            mutate_run_details(
                                provided_run,
                                lambda d, _u=upload_id: d.__setitem__("upload_id", _u))
                        except Exception as _be:
                            print(f"[TUS HOOK] could not record upload_id on run "
                                  f"{provided_run}: {_be}", flush=True)
                        add_log_to_run(provided_run, f"Upload started: {filename} ({size_mb:.1f} MB)")
                        add_log_to_run(provided_run, f"Upload ID: {upload_id}")
                        update_run_status(provided_run, "running", progress=0)
                        print(f"[TUS HOOK] Reusing pre-created run {provided_run} "
                              f"for upload {upload_id}", flush=True)
                        return jsonify({"ok": True})
                except Exception as _e:
                    print(f"[TUS HOOK] pre-created run reuse failed ({_e}); "
                          "creating a fresh run", flush=True)

            # tusd webhooks are server-to-server and don't carry the browser's
            # X-Case-Id header, so the active workspace rides in the upload
            # metadata (set by js/upload.js). Pass it through explicitly so the
            # run is tagged to the workspace the operator uploaded from.
            case_id = (metadata.get('case_id') or '').strip() or None

            run_id = create_automation_run(
                workflow_type,
                workflow_name,
                {
                    "filename": filename,
                    "purpose": purpose,
                    "upload_id": upload_id,
                    "size_bytes": upload_size,
                    "size_mb": round(size_mb, 2),
                    "sketch_name": metadata.get('sketch_name', ''),
                    "plaso_parser": metadata.get('plaso_parser', ''),
                },
                case_id=case_id,
            )

            # Store mapping for post-finish
            _upload_runs[upload_id] = run_id

            add_log_to_run(run_id, f"Upload started: {filename} ({size_mb:.1f} MB)")
            add_log_to_run(run_id, f"Purpose: {purpose}")
            add_log_to_run(run_id, f"Upload ID: {upload_id}")
            update_run_status(run_id, "running", progress=0)

            print(f"[TUS HOOK] Created workflow for upload: {upload_id} -> run_id: {run_id}", flush=True)
            return jsonify({"ok": True})

        elif event_type == 'post-receive':
            # Upload progress - called after each chunk is received
            upload_id = upload_info.get('ID', '')
            offset = upload_info.get('Offset', 0)
            total_size = upload_info.get('Size', 0)

            # Get workflow run_id (don't pop, just get)
            run_id = _resolve_upload_run(upload_id)

            if run_id and total_size > 0:
                percentage = (offset / total_size) * 100
                offset_mb = offset / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)

                # Log progress at 10% intervals to avoid spam
                # Use a simple check: log when percentage crosses a 10% boundary
                prev_percentage = ((offset - 5 * 1024 * 1024) / total_size) * 100 if offset > 5 * 1024 * 1024 else 0

                # Log at 10%, 20%, 30%, etc. or every 50MB for large files
                should_log = (
                    int(percentage / 10) > int(prev_percentage / 10) or  # Crossed 10% boundary
                    (offset_mb > 50 and int(offset_mb / 50) > int((offset_mb - 5) / 50))  # Every 50MB
                )

                if should_log or percentage >= 99:
                    add_log_to_run(run_id, f"Uploading: {percentage:.0f}% ({offset_mb:.1f} / {total_mb:.1f} MB)")
                    # Update progress (upload is 0-10% of total workflow)
                    workflow_progress = int(percentage / 10)  # 0-10%
                    update_run_status(run_id, "running", progress=workflow_progress)

                print(f"[TUS HOOK] Progress: {upload_id} - {percentage:.1f}%", flush=True)

            return jsonify({"ok": True})

        elif event_type == 'post-finish':
            # Upload complete - trigger processing
            upload_id = upload_info.get('ID', '')
            file_path = f"/data/uploads/{upload_id}"
            purpose = metadata.get('purpose', '')
            # secure_filename() strips path-traversal sequences and unsafe
            # characters — this value is client-supplied (TUS upload
            # metadata) and flows into host filesystem paths downstream
            # (e.g. process_kape_upload -> plaso_service derives
            # PLASO_OUTPUT_DIR/<name>_Artifacts.plaso from it), unlike the
            # sibling upload routes (aws/azure/velociraptor_offline) which
            # already sanitize their uploaded filenames.
            original_filename = secure_filename(metadata.get('filename', '')) or 'upload.zip'
            # Optional decryption password for an encrypted offline collection
            # (password scheme, or the recovered session password for X509/PGP).
            import_password = metadata.get('password') or None

            # Extract db_overwrite for upgrade packages (JSON string -> dict)
            db_overwrite_str = metadata.get('db_overwrite', '{}')
            try:
                db_overwrite = json.loads(db_overwrite_str) if db_overwrite_str else {}
            except (json.JSONDecodeError, TypeError):
                db_overwrite = {}

            # Get workflow run_id from pre-create (recover from storage if the
            # in-memory map was lost to a restart — keeps this ONE workflow).
            run_id = _resolve_upload_run(upload_id, pop=True)

            print(f"[TUS HOOK] Upload complete: {original_filename}", flush=True)
            print(f"[TUS HOOK] File path: {file_path}", flush=True)
            print(f"[TUS HOOK] Purpose: {purpose}, run_id: {run_id}", flush=True)

            # Verify file exists
            if not os.path.exists(file_path):
                print(f"[TUS HOOK] ERROR: File not found at {file_path}", flush=True)
                if run_id:
                    add_log_to_run(run_id, "ERROR: Uploaded file not found on server", "error")
                    update_run_status(run_id, "failed", error="File not found after upload")
                return jsonify({"error": "Uploaded file not found"}), 500

            file_size = os.path.getsize(file_path)
            size_mb = file_size / (1024 * 1024)
            print(f"[TUS HOOK] File size: {size_mb:.2f} MB", flush=True)

            if run_id:
                add_log_to_run(run_id, f"Upload complete: {size_mb:.1f} MB received")
                update_run_status(run_id, "running", progress=10)

            if purpose == 'velociraptor':
                # Trigger Velociraptor import in background thread
                print(f"[TUS HOOK] Starting Velociraptor import...", flush=True)
                if run_id:
                    add_log_to_run(run_id, "Starting Velociraptor offline collector import...")

                def run_velociraptor_import():
                    try:
                        from services.offline_collector.importer import import_results
                        result = import_results(file_path, original_filename, run_id=run_id, password=import_password)
                        print(f"[TUS HOOK] Velociraptor import result: {result}", flush=True)
                        # Fuse the imported flow into the Case as a final step of THIS
                        # upload run — read the rows back and persist them for the
                        # fusion graph. No agent, no LLM (see _fuse_offline_import).
                        _fuse_offline_import(result, run_id)
                    except Exception as e:
                        print(f"[TUS HOOK] Velociraptor import error: {e}", flush=True)
                        traceback.print_exc()
                        if run_id:
                            add_log_to_run(run_id, f"Import error: {str(e)}", "error")
                            update_run_status(run_id, "failed", error=str(e))

                thread = threading.Thread(target=run_velociraptor_import, daemon=True)
                thread.start()

            elif purpose == 'timesketch':
                # Trigger Timesketch KAPE processing in background thread
                print(f"[TUS HOOK] Starting Timesketch KAPE processing...", flush=True)
                if run_id:
                    add_log_to_run(run_id, "Starting KAPE file processing...")

                settings = {
                    'sketch_name': metadata.get('sketch_name', 'Investigation'),
                    'plaso_parser': metadata.get('plaso_parser', 'win7'),
                    'plaso_workers': int(metadata.get('plaso_workers', '2')),
                    'plaso_hasher': metadata.get('plaso_hasher', ''),
                    'plaso_hasher_size': int(metadata.get('plaso_hasher_size', '100')),
                    # 3-day cap on the Timesketch indexing wait; big collections
                    # routinely exceed the old 10000s default.
                    'timesketch_processing_timeout': int(metadata.get('timesketch_processing_timeout', '259200')),
                }

                print(f"[TUS HOOK] Settings: {settings}", flush=True)

                def run_timesketch_processing():
                    try:
                        from services.kape_upload_service import process_kape_upload
                        result = process_kape_upload(file_path, original_filename, settings, run_id=run_id)
                        print(f"[TUS HOOK] Timesketch processing result: {result}", flush=True)
                    except Exception as e:
                        print(f"[TUS HOOK] Timesketch processing error: {e}", flush=True)
                        traceback.print_exc()
                        if run_id:
                            add_log_to_run(run_id, f"Processing error: {str(e)}", "error")
                            update_run_status(run_id, "failed", error=str(e))

                thread = threading.Thread(target=run_timesketch_processing, daemon=True)
                thread.start()

            elif purpose == 'agentic_external':
                # External log file for agentic collection - no processing needed
                # File is stored and will be picked up by the agentic pipeline
                print(f"[TUS HOOK] External log uploaded: {original_filename}", flush=True)
                if run_id:
                    add_log_to_run(run_id, f"External log file ready: {original_filename}", "success")
                    update_run_status(run_id, "completed", progress=100)

            elif purpose == 'upgrade_package':
                # Upload only — DOES NOT auto-apply. The operator reviews the
                # manifest, picks modules, then applies. To keep that apply in
                # THE SAME workflow/log as this upload (one row, not two), we
                # persist THIS run_id in a sidecar next to the package;
                # /api/upgrade/offline reads it and CONTINUES this run instead
                # of opening a second workflow. (Prepare-built packages have no
                # sidecar, so they still get their own run.)
                print(f"[TUS HOOK] Upgrade package uploaded (deferred apply): "
                      f"{original_filename}", flush=True)
                if run_id:
                    try:
                        with open(f"{file_path}.run", "w") as _rf:
                            _rf.write(run_id)
                    except Exception as _e:
                        print(f"[TUS HOOK] could not write upload run sidecar: {_e}", flush=True)
                    add_log_to_run(run_id, f"Upload complete: {original_filename}", "success")
                    add_log_to_run(run_id, f"Package path: {file_path}", "info")
                    add_log_to_run(run_id, "Ready to apply — applying this package continues the same workflow.", "info")
                    # Keep the run OPEN (running), NOT completed: the apply
                    # immediately continues THIS run via the .run sidecar. Marking
                    # it completed made the row read as "done" at the upload stage
                    # (and an older frontend then stopped following it), even
                    # though the apply re-opens it. An upload that's never applied
                    # is reaped by cleanup_orphan_workflows after its idle window.
                    update_run_status(run_id, "running", progress=10)

            return jsonify({"ok": True})

        elif event_type == 'post-terminate':
            # Upload was cancelled/terminated
            upload_id = upload_info.get('ID', '')
            run_id = _resolve_upload_run(upload_id, pop=True)
            print(f"[TUS HOOK] Upload terminated: {upload_id}", flush=True)

            # Update workflow status
            if run_id:
                add_log_to_run(run_id, "Upload cancelled by user", "warning")
                update_run_status(run_id, "failed", error="Upload cancelled")

            # Clean up partial upload file and .info metadata
            file_path = f"/data/uploads/{upload_id}"
            info_path = f"/data/uploads/{upload_id}.info"
            for path in [file_path, info_path]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        print(f"[TUS HOOK] Cleaned up: {path}", flush=True)
                    except Exception as e:
                        print(f"[TUS HOOK] Cleanup error: {e}", flush=True)

            return jsonify({"ok": True})

        else:
            # Unknown event type - just acknowledge
            print(f"[TUS HOOK] Unhandled event type: {event_type}", flush=True)
            return jsonify({"ok": True})

    except Exception as e:
        print(f"[TUS HOOK] Error handling webhook: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@upload_bp.route('/api/uploads/status/<upload_id>', methods=['GET'])
def get_upload_status(upload_id):
    """Check if an upload file exists and get its size"""
    # Defense-in-depth: Flask's default converter blocks literal '/' in this
    # segment, but a bare ".." would still resolve to the parent dir — pin to
    # just the basename so this can never escape /data/uploads.
    file_path = os.path.join("/data/uploads", os.path.basename(upload_id))

    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        return jsonify({
            "exists": True,
            "size": size,
            "size_mb": size / (1024 * 1024)
        })
    else:
        return jsonify({"exists": False})
