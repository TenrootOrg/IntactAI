#!/usr/bin/env python3
"""
Velociraptor Offline Collector Routes - Offline collector configuration and generation
"""

from flask import Blueprint, jsonify, request, send_file
import os
import threading
import traceback

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)
from services.offline_collector import (
    get_all_configs,
    get_config,
    save_config,
    delete_config,
    generate_collector,
    get_collector_file,
    import_results
)
from services.file_storage_service import get_agentic_blueprint, get_velociraptor_blueprint
from services.storage.blueprint_store import get_timesketch_blueprint

velociraptor_offline_bp = Blueprint('velociraptor_offline', __name__)


@velociraptor_offline_bp.route('/api/velociraptor/offline/configs', methods=['GET'])
def list_offline_configs():
    """Get all offline collector configurations"""
    try:
        configs = get_all_configs()
        return jsonify({"configs": configs})
    except Exception as e:
        print(f"[OFFLINE] Error listing configs: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/configs', methods=['POST'])
def create_offline_config():
    """Create a new offline collector configuration"""
    try:
        data = request.get_json()

        if not data.get('config_name'):
            return jsonify({"error": "config_name is required"}), 400
        if not data.get('artifacts'):
            return jsonify({"error": "artifacts list is required"}), 400

        result = save_config(data)

        if result.get('success'):
            return jsonify(result), 201
        else:
            return jsonify(result), 500
    except Exception as e:
        print(f"[OFFLINE] Error creating config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['GET'])
def get_offline_config(config_id):
    """Get a specific configuration"""
    try:
        config = get_config(config_id)
        if config:
            return jsonify(config)
        return jsonify({"error": "Configuration not found"}), 404
    except Exception as e:
        print(f"[OFFLINE] Error getting config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['PUT'])
def update_offline_config(config_id):
    """Update an existing configuration"""
    try:
        data = request.get_json()

        # Check if config exists
        existing = get_config(config_id)
        if not existing:
            return jsonify({"error": "Configuration not found"}), 404

        # Merge existing with new data
        existing.update(data)
        result = save_config(existing, config_id)

        if result.get('success'):
            return jsonify(result)
        else:
            return jsonify(result), 500
    except Exception as e:
        print(f"[OFFLINE] Error updating config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/configs/<config_id>', methods=['DELETE'])
def delete_offline_config(config_id):
    """Delete a configuration"""
    try:
        # Don't allow deleting templates
        config = get_config(config_id)
        if config and config.get('is_template'):
            return jsonify({"error": "Cannot delete default templates"}), 400

        result = delete_config(config_id)
        return jsonify(result)
    except Exception as e:
        print(f"[OFFLINE] Error deleting config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/generate', methods=['POST'])
def generate_offline_collector():
    """Generate an offline collector binary with workflow logging"""
    try:
        data = request.get_json()
        config_id = data.get('config_id')
        os_type = data.get('os', 'windows')
        # Binary variant — three mutually-exclusive modes:
        #   legacy=True   → swap in legacy v0.7.x build (Server 2008 R2 / Win 7)
        #   musl=True     → swap in MODERN musl-static linux build (any-glibc Linux)
        #   neither       → default standard build
        # legacy + musl together is rejected as inconsistent.
        legacy = bool(data.get('legacy'))
        musl   = bool(data.get('musl'))
        legacy_source = (data.get('legacy_source') or 'offline').lower()
        legacy_version = data.get('legacy_version') or None

        if not config_id:
            return jsonify({"error": "config_id is required"}), 400

        if os_type not in ['windows', 'linux', 'darwin']:
            return jsonify({"error": "os must be windows, linux, or darwin"}), 400

        if legacy and legacy_source not in ('offline', 'online'):
            return jsonify({"error": "legacy_source must be 'offline' or 'online'"}), 400

        if legacy and musl:
            return jsonify({"error": "legacy and musl are mutually exclusive — pick one"}), 400
        if musl and os_type != 'linux':
            return jsonify({"error": "musl variant is Linux-only"}), 400
        # Velociraptor publishes no legacy darwin asset (the 0.7.x release
        # series stopped before darwin shipping took off). Reject upfront
        # so the run doesn't connect to gRPC, allocate state, and only
        # then fail at the file-swap step with a cryptic ENOENT.
        if legacy and os_type == 'darwin':
            return jsonify({"error": "legacy variant is not available for macOS (no upstream darwin asset for v0.7.x)"}), 400

        # Get config name for workflow
        config = get_config(config_id)
        config_name = config.get('config_name', config_id) if config else config_id

        # Look up blueprint display name from blueprints tables. Timesketch
        # blueprints (KAPE triage) now also flow through the offline collector
        # generator — check that store too so the workflow row shows the
        # human-readable blueprint name in the dashboard.
        blueprint = (
            get_agentic_blueprint(config_id)
            or get_velociraptor_blueprint(config_id)
            or get_timesketch_blueprint(config_id)
        )
        blueprint_display_name = blueprint.get('name', config_name) if blueprint else config_name

        # Create workflow run for tracking
        if legacy:
            suffix = " [legacy]"
        elif musl:
            suffix = " [musl]"
        else:
            suffix = ""
        run_id = create_automation_run(
            automation_type="velociraptor_offline_collector",
            name=f"Generate Collector: {blueprint_display_name} ({os_type}){suffix}",
            details={"config_id": config_id, "os": os_type, "config_name": config_name,
                     "blueprint": blueprint_display_name, "blueprint_id": config_id,
                     "legacy": legacy, "musl": musl,
                     "legacy_source": legacy_source,
                     "legacy_version": legacy_version},
        )

        add_log_to_run(run_id, f"Starting offline collector generation", "info")
        add_log_to_run(run_id, f"Configuration: {config_name}", "info")
        add_log_to_run(run_id, f"Target OS: {os_type}", "info")
        if legacy:
            add_log_to_run(run_id, f"Legacy mode: binary={legacy_version or 'default'} source={legacy_source}", "info")
        elif musl:
            add_log_to_run(run_id, "Musl-static mode: swap in modern musl Linux binary (zero glibc deps)", "info")
        update_run_status(run_id, "running", progress=10)

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event = register_cancel_event(run_id)

        print(f"[OFFLINE] Generate request: config={config_id}, os={os_type}, run_id={run_id}", flush=True)

        # Run generation in background thread
        def do_generate():
            try:
                add_log_to_run(run_id, "Connecting to Velociraptor...", "info")
                update_run_status(run_id, "running", progress=20)

                result = generate_collector(
                    config_id, os_type,
                    legacy=legacy,
                    legacy_version=legacy_version,
                    legacy_source=legacy_source,
                    musl=musl,
                )

                if result.get('success'):
                    file_size = result.get('file_size', 0)
                    file_name = result.get('file_name', 'collector')
                    file_id = result.get('file_id', '')

                    add_log_to_run(run_id, f"Collector generated successfully", "success")
                    add_log_to_run(run_id, f"File: {file_name}", "info")
                    add_log_to_run(run_id, f"Size: {file_size / (1024*1024):.2f} MB", "info")
                    add_log_to_run(run_id, f"Download URL: /api/velociraptor/offline/download/{file_id}", "info")

                    if result.get('note'):
                        add_log_to_run(run_id, result['note'], "info")

                    # Store file_id in details for download button
                    update_run_status(run_id, "completed", progress=100, details={"file_id": file_id})
                else:
                    error = result.get('error', 'Unknown error')
                    add_log_to_run(run_id, f"Generation failed: {error}", "error")
                    update_run_status(run_id, "failed", progress=0, error=error)

            except Exception as e:
                error_msg = str(e)
                print(f"[OFFLINE] Background generation error: {error_msg}", flush=True)
                traceback.print_exc()
                add_log_to_run(run_id, f"Generation failed: {error_msg}", "error")
                update_run_status(run_id, "failed", progress=0, error=error_msg)
            finally:
                unregister_cancel(run_id)

        thread = threading.Thread(target=do_generate, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Generation started for {config_name} ({os_type})"
        })

    except Exception as e:
        print(f"[OFFLINE] Error generating collector: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/download/<file_id>', methods=['GET'])
def download_offline_collector(file_id):
    """Download a generated collector file"""
    try:
        file_path = get_collector_file(file_id)

        if not file_path or not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        filename = os.path.basename(file_path)

        # Determine mimetype
        if filename.endswith('.exe'):
            mimetype = 'application/x-msdownload'
        elif filename.endswith('.ps1'):
            mimetype = 'text/plain'
        elif filename.endswith('.sh'):
            mimetype = 'text/x-sh'
        else:
            mimetype = 'application/octet-stream'

        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"[OFFLINE] Error downloading file: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@velociraptor_offline_bp.route('/api/velociraptor/offline/import', methods=['POST'])
def import_offline_results():
    """Import offline collection results from ZIP file"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.endswith('.zip'):
            return jsonify({"error": "File must be a ZIP archive"}), 400

        # Check file size (limit to 500MB)
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)

        if file_size > 500 * 1024 * 1024:
            return jsonify({"error": "File too large (max 500MB)"}), 413

        # Save uploaded file temporarily
        import tempfile
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)

        print(f"[OFFLINE] Importing: {file.filename} ({file_size} bytes)", flush=True)

        result = import_results(temp_path, file.filename)

        return jsonify(result)
    except Exception as e:
        print(f"[OFFLINE] Error importing results: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
