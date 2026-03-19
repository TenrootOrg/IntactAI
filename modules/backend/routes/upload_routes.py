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

            if purpose not in ['velociraptor', 'timesketch', 'upgrade_package']:
                print(f"[TUS HOOK] Rejected: Invalid purpose '{purpose}'", flush=True)
                return jsonify({
                    "RejectUpload": True,
                    "HTTPResponse": {
                        "StatusCode": 400,
                        "Body": json.dumps({"error": "Invalid upload purpose. Must be 'velociraptor', 'timesketch', or 'upgrade_package'"})
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
                }
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

            elif purpose == 'upgrade_package':
                # Upgrade package uploaded - keep workflow running for upgrade to continue
                # The actual upgrade will use this same run_id
                print(f"[TUS HOOK] Upgrade package uploaded: {original_filename}", flush=True)
                if run_id:
                    add_log_to_run(run_id, f"Upload complete: {original_filename}", "success")
                    add_log_to_run(run_id, f"Package path: {file_path}", "info")
                    add_log_to_run(run_id, "Starting offline upgrade...", "info")
                    update_run_status(run_id, "running", progress=15)

                    # Auto-start the offline upgrade using the same workflow
                    def run_offline_upgrade():
                        try:
                            from services.upgrade import run_offline_upgrade_workflow

                            # Track progress based on module completion
                            completed_modules = [0]

                            def logger(msg, level="info"):
                                add_log_to_run(run_id, msg, level)
                                # Track progress based on module completion messages
                                if level == "success" and " upgrade completed" in msg:
                                    first_word = msg.split()[0] if msg else ""
                                    if first_word.isupper() and first_word in ["ELK", "TIMESKETCH", "PLASO", "IRIS", "VELOCIRAPTOR", "RISX"]:
                                        completed_modules[0] += 1
                                        # Progress from 15% (upload done) to 95%
                                        progress = 15 + min(completed_modules[0] * 13, 80)
                                        update_run_status(run_id, "running", progress=progress)

                            result = run_offline_upgrade_workflow(file_path, run_id=run_id, logger=logger)

                            # Handle result
                            if result.get('phase') == 'awaiting_restart':
                                add_log_to_run(run_id, "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.", "info")
                                update_run_status(run_id, "running", progress=50)
                            elif result.get('success'):
                                add_log_to_run(run_id, f"Offline upgrade completed: {result.get('completed', 0)}/{result.get('total', 0)} modules", "success")
                                update_run_status(run_id, "completed", progress=100)
                            else:
                                failed = [m for m, r in result.get('results', {}).items() if not r.get('success')]
                                if failed:
                                    add_log_to_run(run_id, f"Offline upgrade completed with failures: {', '.join(failed)}", "warning")
                                update_run_status(run_id, "completed", progress=100)

                        except Exception as e:
                            print(f"[TUS HOOK] Offline upgrade error: {e}", flush=True)
                            traceback.print_exc()
                            add_log_to_run(run_id, f"Upgrade error: {str(e)}", "error")
                            update_run_status(run_id, "failed", error=str(e))

                    thread = threading.Thread(target=run_offline_upgrade, daemon=True)
                    thread.start()

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

            # Clean up partial upload file
            file_path = f"/data/uploads/{upload_id}"
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"[TUS HOOK] Cleaned up: {file_path}", flush=True)
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
