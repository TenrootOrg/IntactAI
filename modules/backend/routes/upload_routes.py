#!/usr/bin/env python3
"""
Upload Routes - Handle tus upload webhooks for resumable file uploads

All upload progress is tracked in the Workflows tab via workflow runs.
"""

from flask import Blueprint, request, jsonify
import os
import json
import threading
import traceback
import base64

from services.workflow_service import create_automation_run, add_log_to_run, update_run_status

upload_bp = Blueprint('uploads', __name__)

# Store mapping of upload_id -> run_id for workflow tracking
_upload_runs = {}


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
    imported flow into the Case — as a final step of the SAME upload run (one
    workflow row). There is NO agent and NO LLM here: this only reads the flow's
    rows back from Velociraptor and persists them so the fusion graph can pick
    them up (velociraptor_upload is a fusion member — see
    workflow_service.AGENTIC_TYPES + the fusion-store dispatch). Any LLM analysis
    is a separate, explicit Case-level action the operator chooses to run later."""
    if not (isinstance(import_result, dict) and import_result.get("success")
            and import_result.get("flow_id") and upload_run_id):
        return
    try:
        from services.workflow_service import (
            get_automation_run, add_log_to_run, update_run_status)
        from services.file_storage_service import save_workflow
        from services.agentic.collectors import get_existing_collection_results
        from services.agentic.reports import persist_pipeline_artifacts
        flow_id = import_result["flow_id"]
        client_id = import_result.get("client_id")
        hostname = import_result.get("hostname")

        # Seed the run's hostnames map so the Case host card shows a friendly
        # name (the mapper also falls back to each row's own hostname column).
        run = get_automation_run(upload_run_id) or {}
        det = run.get("details") or {}
        if client_id and hostname:
            hn = dict(det.get("hostnames") or {})
            hn[str(client_id)] = hostname
            det["hostnames"] = hn
            det["offline_flow_id"] = flow_id
            run["details"] = det
            try:
                save_workflow(run)
            except Exception:
                pass

        add_log_to_run(upload_run_id, "[Fusion] Reading imported flow into the case…")
        all_results, artifacts, _client_info = get_existing_collection_results(
            upload_run_id, flow_id=flow_id, hunt_id=None,
            client_ids=[client_id] if client_id else None)
        total_rows = sum(len(rows) for rows in (all_results or {}).values())
        if total_rows == 0:
            add_log_to_run(upload_run_id,
                           "[Fusion] Import had no rows to fuse into the case.", "warning")
            return
        # Persist rows where the fusion graph reads them (/data/downloads/<rid>).
        persist_pipeline_artifacts(upload_run_id, {}, all_results)
        add_log_to_run(
            upload_run_id,
            f"[Fusion] Added {total_rows} rows across {len(artifacts)} artifact(s) "
            f"to the case.", "success")
        update_run_status(upload_run_id, "completed", progress=100)
    except Exception as e:
        print(f"[OFFLINE IMPORT] fuse of imported flow failed: {e}", flush=True)
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
        print(f"[TUS HOOK] Metadata: {metadata}", flush=True)

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
                if not (filename.lower().endswith('.tar.gz') or filename.lower().endswith('.tgz')):
                    print(f"[TUS HOOK] Rejected: Not a tar.gz file '{filename}'", flush=True)
                    return jsonify({
                        "RejectUpload": True,
                        "HTTPResponse": {
                            "StatusCode": 400,
                            "Body": json.dumps({"error": "Upgrade packages must be .tar.gz or .tgz files"})
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
            run_id = _upload_runs.get(upload_id)

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
            original_filename = metadata.get('filename', 'upload.zip')

            # Extract db_overwrite for upgrade packages (JSON string -> dict)
            db_overwrite_str = metadata.get('db_overwrite', '{}')
            try:
                db_overwrite = json.loads(db_overwrite_str) if db_overwrite_str else {}
            except (json.JSONDecodeError, TypeError):
                db_overwrite = {}

            # Get workflow run_id from pre-create
            run_id = _upload_runs.pop(upload_id, None)

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
                        result = import_results(file_path, original_filename, run_id=run_id)
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
                # External log file for agentic analysis - no processing needed
                # File is stored and will be picked up by the agentic pipeline
                print(f"[TUS HOOK] External log uploaded: {original_filename}", flush=True)
                if run_id:
                    add_log_to_run(run_id, f"External log file ready: {original_filename}", "success")
                    update_run_status(run_id, "completed", progress=100)

            elif purpose == 'upgrade_package':
                # Upload only — DOES NOT auto-apply. The operator
                # triggers run_offline_upgrade_workflow themselves once
                # they're ready; until then the package just sits at
                # file_path. The "where to go next" hint that used to
                # live here was removed 2026-06-14 — it pointed at a
                # specific UI card name that turned out to be noise in
                # the workflow log (operator already knows where the
                # apply control is; the path + completed status is
                # what matters).
                print(f"[TUS HOOK] Upgrade package uploaded (deferred apply): "
                      f"{original_filename}", flush=True)
                if run_id:
                    add_log_to_run(run_id, f"Upload complete: {original_filename}", "success")
                    add_log_to_run(run_id, f"Package path: {file_path}", "info")
                    update_run_status(run_id, "completed", progress=100)

            return jsonify({"ok": True})

        elif event_type == 'post-terminate':
            # Upload was cancelled/terminated
            upload_id = upload_info.get('ID', '')
            run_id = _upload_runs.pop(upload_id, None)
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
    file_path = f"/data/uploads/{upload_id}"

    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        return jsonify({
            "exists": True,
            "size": size,
            "size_mb": size / (1024 * 1024)
        })
    else:
        return jsonify({"exists": False})
