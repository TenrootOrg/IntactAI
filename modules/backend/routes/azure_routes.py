"""
Azure Automation API Routes

Provides endpoints for Azure security automation:
- Online mode: Live collection from Azure tenant
- Offline mode: Upload and analyze existing logs
"""

import os
import json
import uuid
import traceback
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app, Response
from werkzeug.utils import secure_filename

from services.azure.pipeline import (
    run_azure_pipeline,
    run_azure_on_existing,
    get_azure_blueprints,
    get_available_sources,
)
from services.azure.collectors import parse_uploaded_logs
from services.azure.sigma_runner import (
    validate_rules_directory,
    get_available_rules_count,
    list_custom_rules,
    save_custom_rule,
    delete_custom_rule,
)
from services.workflow_logger import add_log_to_run
from routes.config_routes import _load_cloud_config
from config import is_module_enabled
from services.workflow_service import update_run_status, get_automation_run
import threading

azure_bp = Blueprint('azure', __name__)

# In-memory storage for run results (would use database in production)
_azure_runs = {}

# Upload configuration
UPLOAD_FOLDER = '/tmp/azure_uploads'
ALLOWED_EXTENSIONS = {'json', 'jsonl', 'csv', 'zip'}
PARSEABLE_EXTENSIONS = {'json', 'jsonl', 'csv'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _parseable(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in PARSEABLE_EXTENSIONS


# =============================================================================
# Status & Configuration Endpoints
# =============================================================================

@azure_bp.route('/api/azure/status', methods=['GET'])
def get_azure_status():
    """Get Azure automation service status."""
    try:
        # Check SIGMA rules
        rules_valid, rules_msg = validate_rules_directory()

        # Check Azure config
        cloud_config = _load_cloud_config()
        azure_config = cloud_config.get('azure', {})
        has_credentials = bool(
            azure_config.get('tenant_id') and
            azure_config.get('client_id') and
            azure_config.get('client_secret')
        )

        return jsonify({
            'status': 'ready' if rules_valid else 'partial',
            'sigma_rules': {
                'available': rules_valid,
                'message': rules_msg
            },
            'azure_credentials': {
                'configured': has_credentials,
                'tenant_id': azure_config.get('tenant_id', '')[:8] + '...' if azure_config.get('tenant_id') else None
            },
            'capabilities': {
                'online_mode': has_credentials,
                'offline_mode': True  # Always available
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@azure_bp.route('/api/azure/blueprints', methods=['GET'])
def get_blueprints():
    """Get available Azure blueprints."""
    try:
        blueprints = get_azure_blueprints()
        return jsonify({'blueprints': blueprints})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/sources', methods=['GET'])
def get_sources():
    """Get available Azure log sources."""
    try:
        sources = get_available_sources()
        return jsonify({'sources': sources})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/rules', methods=['GET'])
def get_rules_info():
    """Get information about available SIGMA rules."""
    try:
        rules_valid, rules_msg = validate_rules_directory()
        custom_count = len(list_custom_rules('azure'))
        if rules_valid:
            counts = get_available_rules_count()
            return jsonify({
                'available': True,
                'message': rules_msg,
                'counts': counts,
                'custom_rules_count': custom_count,
            })
        else:
            return jsonify({
                'available': False,
                'message': rules_msg,
                'custom_rules_count': custom_count,
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/rules/custom', methods=['GET'])
def list_custom_azure_rules():
    """List operator-added custom SIGMA rules for Azure."""
    try:
        return jsonify({'rules': list_custom_rules('azure')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/rules/custom', methods=['POST'])
def upload_custom_azure_rule():
    """Upload a custom SIGMA rule for Azure. Accepts either a multipart file
    upload (field 'file') or a JSON body {"filename": ..., "content": ...}."""
    try:
        if 'file' in request.files:
            f = request.files['file']
            filename = f.filename or 'custom_rule.yml'
            content = f.read().decode('utf-8', errors='replace')
        else:
            data = request.get_json(silent=True) or {}
            filename = data.get('filename') or 'custom_rule.yml'
            content = data.get('content') or ''
        if not content.strip():
            return jsonify({'error': 'No rule content provided'}), 400
        success, msg = save_custom_rule('azure', filename, content)
        if not success:
            return jsonify({'error': msg}), 400
        return jsonify({'success': True, 'filename': msg})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/rules/custom/<filename>', methods=['DELETE'])
def delete_custom_azure_rule(filename):
    """Delete an operator-added custom SIGMA rule for Azure."""
    try:
        success, msg = delete_custom_rule('azure', filename)
        if not success:
            return jsonify({'error': msg}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Online Mode Endpoints
# =============================================================================

@azure_bp.route('/api/azure/scan', methods=['POST'])
def start_scan():
    """
    Start an online Azure security scan.

    Request body:
    {
        "blueprint": "azure_quick_scan" | "azure_full_investigation" | {...custom...},
        "time_filter": {"enabled": true, "mode": "relative", "relative_range": "7d"} | {"enabled": true, "mode": "between", "start_datetime": "...", "end_datetime": "..."}
    }
    """
    # Always create workflow first so everything is visible in logs
    from services.workflow_service import create_automation_run, update_run_status

    data = request.json or {}
    blueprint_id = data.get('blueprint', 'azure_quick_triage')

    # Build a clean display name (blueprint can be a string ID or a custom dict)
    if isinstance(blueprint_id, dict):
        blueprint_display = blueprint_id.get('name') or blueprint_id.get('id') or 'Custom'
    else:
        blueprint_display = str(blueprint_id)

    # scope_mode: "targeted" (default) requires target_users or target_ips, runs
    # the fast server-side-filtered UAL path. "tenant_wide" pulls every event in
    # the window — for periodic baselines or unknown-attacker hunts.
    target_users = data.get('target_users', []) or []
    target_ips = data.get('target_ips', []) or []
    scope_mode = (data.get('scope_mode') or "targeted").lower()
    if scope_mode not in ("targeted", "tenant_wide"):
        return jsonify({"error": f"Invalid scope_mode: {scope_mode!r}. Use 'targeted' or 'tenant_wide'."}), 400
    if scope_mode == "targeted" and not (target_users or target_ips):
        return jsonify({
            "error": "scope_mode='targeted' requires at least one target_user or target_ip. "
                     "Pass scope_mode='tenant_wide' to hunt across the whole tenant."
        }), 400

    # ual_mode: "full" (default — every UAL record type) or "light" (curated
    # high-signal record types only — recommended for large tenants where
    # full collection is slow and most events are PowerBI/Yammer/Sway noise).
    # Ignored when target_users / target_ips is set: those identity filters
    # take precedence (they're more targeted than any RecordTypes filter).
    ual_mode = (data.get('ual_mode') or "full").lower()
    if ual_mode not in ("full", "light"):
        return jsonify({"error": f"Invalid ual_mode: {ual_mode!r}. Use 'full' or 'light'."}), 400

    run_id = create_automation_run(
        automation_type="azure_scan",
        name=f"Azure Scan: {blueprint_display}",
        details={
            "trigger": "manual",
            "blueprint": blueprint_id,
            "mode": "online",
            "scope_mode": scope_mode,
            "target_users": target_users,
            "target_ips": target_ips,
            "ual_mode": ual_mode,
            # Persisted so /rerun can re-apply the same scope on the
            # cached findings instead of regenerating reports over
            # informational/low + out-of-window noise.
            "min_severity": data.get('min_severity', 'medium'),
            "time_filter": data.get('time_filter'),
        }
    )
    update_run_status(run_id, "running", progress=5)

    # Register cancel event for stop support
    from services.workflow_service import register_cancel_event, unregister_cancel, is_cancelled
    cancel_event = register_cancel_event(run_id)

    # Run everything in background thread - all errors go to workflow log
    import threading
    def run_scan():
        try:
            from services.connectivity import require_internet
            if not require_internet(run_id, "Azure scan"):
                return

            # Validate module
            if not is_module_enabled('o365rc'):
                add_log_to_run(run_id, "Azure module is not enabled. Enable it in config.yaml and rebuild.", "error")
                update_run_status(run_id, "failed", error="Azure module not enabled")
                return

            # Get Azure credentials
            cloud_config = _load_cloud_config()
            azure_config = cloud_config.get('azure', {})

            if not azure_config.get('tenant_id') or not azure_config.get('client_id'):
                add_log_to_run(run_id, "Azure credentials not configured. Please configure in Settings.", "error")
                update_run_status(run_id, "failed", error="Azure credentials not configured")
                return

            # Get or create blueprint config
            if isinstance(blueprint_id, str):
                blueprints = get_azure_blueprints()
                blueprint = next((b for b in blueprints if b['id'] == blueprint_id), None)
                if not blueprint:
                    add_log_to_run(run_id, f"Blueprint not found: {blueprint_id}", "error")
                    update_run_status(run_id, "failed", error=f"Blueprint not found: {blueprint_id}")
                    return
            else:
                blueprint = blueprint_id

            # Update workflow name with resolved blueprint
            add_log_to_run(run_id, f"[AZURE] Starting scan with blueprint: {blueprint.get('name', 'Custom')}", "info")

            # Build options with identity filters
            options = {
                'time_filter': data.get('time_filter'),
                'min_severity': data.get('min_severity', 'medium'),
                'scope_mode': scope_mode,
                'target_users': target_users,
                'target_ips': target_ips,
                'pivot_mode': data.get('pivot_mode', False),
                'ual_mode': ual_mode,
            }
            add_log_to_run(
                run_id,
                f"[AZURE] Scope: {scope_mode}"
                + (f" (users={','.join(target_users)})" if target_users else "")
                + (f" (ips={','.join(target_ips)})" if target_ips else ""),
                "info",
            )
            # Log the UAL collection mode separately so it's obvious in the
            # workflow log when an operator picked "light" and why some
            # record types are missing from the result set.
            if not target_users and not target_ips:
                add_log_to_run(
                    run_id,
                    f"[AZURE] UAL collection mode: {ual_mode}"
                    + (" (curated high-signal record types only)" if ual_mode == "light" else " (every record type)"),
                    "info",
                )

            result = run_azure_pipeline(
                run_id=run_id,
                azure_config=azure_config,
                blueprint=blueprint,
                options=options
            )

            if is_cancelled(run_id):
                return

            _azure_runs[run_id] = result

            # Persist raw data to disk so it survives backend restart
            try:
                persist_dir = "/app/data/azure_runs"
                os.makedirs(persist_dir, exist_ok=True)
                with open(f"{persist_dir}/{run_id}.json", 'w') as f:
                    json.dump(result, f, default=str)
            except Exception as persist_err:
                print(f"[AZURE] Warning: Could not persist raw data: {persist_err}", flush=True)

            if result.get('status') == 'failed':
                update_run_status(run_id, "failed", error=result.get('error', 'Unknown error'))
            else:
                if not is_cancelled(run_id):
                    update_run_status(run_id, "completed", progress=100)

        except Exception as e:
            if is_cancelled(run_id):
                return
            add_log_to_run(run_id, f"[AZURE] Scan failed: {str(e)}", "error")
            update_run_status(run_id, "failed", error=str(e))
            traceback.print_exc()
        finally:
            unregister_cancel(run_id)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({
        'run_id': run_id,
        'status': 'running',
        'message': 'Azure scan started'
    })


# =============================================================================
# Offline Mode Endpoints
# =============================================================================

@azure_bp.route('/api/azure/upload', methods=['POST'])
def upload_logs():
    """
    Upload log files for offline analysis.

    Accepts multipart form data with files.
    Returns run_id for subsequent analysis.
    """
    if not is_module_enabled('o365rc'):
        return jsonify({"error": "Azure module is not enabled. Enable it in config.yaml and rebuild the backend."}), 400
    try:
        if 'files' not in request.files and 'file' not in request.files:
            return jsonify({'error': 'No files provided'}), 400

        # Create upload directory
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # Create run ID
        run_id = f"azure_offline_{uuid.uuid4().hex[:12]}"
        run_dir = os.path.join(UPLOAD_FOLDER, run_id)
        os.makedirs(run_dir, exist_ok=True)

        # Get files (support both 'file' and 'files' field names)
        files = request.files.getlist('files') or request.files.getlist('file')

        uploaded_files = []
        parsed_data = {}

        def _ingest(parsed_path, hint):
            """Parse one log file and merge it into parsed_data, preserving
            existing records when the same source_prefix shows up twice
            (e.g. multi-day UAL split across files)."""
            data, parse_status = parse_uploaded_logs(parsed_path, filename_hint=hint)
            for src_prefix, records in data.items():
                if src_prefix in parsed_data:
                    parsed_data[src_prefix].extend(records)
                else:
                    parsed_data[src_prefix] = records
            return parse_status

        for file in files:
            if not (file and file.filename and allowed_file(file.filename)):
                continue
            filename = secure_filename(file.filename)
            file_path = os.path.join(run_dir, filename)
            file.save(file_path)

            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

            if ext == 'zip':
                # Extract every parseable JSON/JSONL/CSV inside; use each
                # member's basename as the filename hint so files named
                # `Azure.<source>.json` are tagged correctly.
                import zipfile as _zf
                from services.archive_guard import guard_zip, ArchiveRejected
                extracted_dir = os.path.join(run_dir, 'extracted')
                os.makedirs(extracted_dir, exist_ok=True)
                # Judge the archive before touching it. Below, each member is
                # read with src.read() — the WHOLE member into RAM before it is
                # written — so an oversized entry exhausts backend memory, not
                # just disk. Nothing bounded that.
                try:
                    guard_zip(file_path, extracted_dir)
                except ArchiveRejected as e:
                    add_log_to_run(run_id, f"Archive rejected: {e}", "error")
                    return jsonify({"error": f"Archive rejected: {e}"}), 400
                try:
                    with _zf.ZipFile(file_path, 'r') as zf:
                        for member in zf.namelist():
                            base = os.path.basename(member)
                            if not base or member.endswith('/'):
                                continue
                            if not _parseable(base):
                                continue
                            # Skip findings/analysis sub-dirs — only the
                            # raw `collected/` records feed the offline
                            # pipeline. Anything else from the ZIP is
                            # derived data we'd recompute. Also skip
                            # `metadata.json` — that's a manifest, not data.
                            if member.startswith(('findings/', 'analysis/')):
                                continue
                            if base == 'metadata.json':
                                continue
                            target = os.path.join(extracted_dir, base)
                            with zf.open(member) as src, open(target, 'wb') as dst:
                                dst.write(src.read())
                            try:
                                ps = _ingest(target, base)
                                uploaded_files.append({
                                    'filename': f"{filename}:{base}",
                                    'records': ps.get('record_count', 0),
                                    'source_type': ps.get('detected_source'),
                                    'sigma_prefix': ps.get('sigma_prefix'),
                                })
                            except Exception as ex:
                                uploaded_files.append({
                                    'filename': f"{filename}:{base}",
                                    'error': str(ex),
                                })
                except _zf.BadZipFile as ex:
                    uploaded_files.append({
                        'filename': filename,
                        'error': f"Invalid ZIP file: {ex}",
                    })
                continue

            try:
                ps = _ingest(file_path, filename)
                uploaded_files.append({
                    'filename': filename,
                    'records': ps.get('record_count', 0),
                    'source_type': ps.get('detected_source'),
                    'sigma_prefix': ps.get('sigma_prefix'),
                })
            except Exception as e:
                uploaded_files.append({
                    'filename': filename,
                    'error': str(e),
                })

        # Store parsed data
        _azure_runs[run_id] = {
            'status': 'uploaded',
            'mode': 'offline',
            'uploaded_files': uploaded_files,
            'collected_data': parsed_data,
            'total_records': sum(len(v) for v in parsed_data.values()),
            'upload_time': datetime.utcnow().isoformat()
        }

        # Register the workflow row right at upload so the dashboard
        # tracks this run from the moment files arrive. We mint the row
        # ourselves (rather than via `create_automation_run`, which auto-
        # generates its own run_id) so the same `azure_offline_*` ID
        # carries through to `analyze-offline` — logs, phase timings,
        # findings all land on one row.
        try:
            from services.file_storage_service import save_workflow
            from services.workflow_service import update_run_status
            save_workflow({
                'run_id': run_id,
                'automation_type': 'azure_scan',
                'name': f"Azure Offline Analysis ({len(parsed_data)} sources, {sum(len(v) for v in parsed_data.values())} records)",
                'details': {
                    'trigger': 'upload',
                    'mode': 'offline',
                    'sources': list(parsed_data.keys()),
                    'uploaded_files': [f.get('filename') for f in uploaded_files],
                },
                'status': 'pending',
                'progress': 0,
                'logs': [],
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
            })
            update_run_status(run_id, "uploaded", progress=10)
            add_log_to_run(run_id, f"[AZURE] Uploaded {sum(len(v) for v in parsed_data.values())} records across {len(parsed_data)} sources", "info")
            for f in uploaded_files:
                if f.get('error'):
                    add_log_to_run(run_id, f"[AZURE] {f['filename']}: {f['error']}", "warning")
                else:
                    add_log_to_run(run_id, f"[AZURE] {f['filename']}: {f.get('records',0)} records -> {f.get('sigma_prefix','?')}", "success")
        except Exception as ex:
            print(f"[AZURE] workflow row create failed: {ex}", flush=True)

        return jsonify({
            'run_id': run_id,
            'status': 'uploaded',
            'files': uploaded_files,
            'total_records': sum(len(v) for v in parsed_data.values()),
            'message': 'Files uploaded successfully. Use /api/azure/analyze-offline to run analysis.'
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/analyze-offline', methods=['POST'])
def analyze_offline():
    """
    Run SIGMA detection on uploaded logs.

    Request body:
    {
        "run_id": "azure_offline_xxx",
        "time_filter": {...},
        "min_severity": "low"
    }
    """
    try:
        data = request.json or {}
        run_id = data.get('run_id')

        if not run_id or run_id not in _azure_runs:
            return jsonify({'error': 'Invalid or missing run_id'}), 400

        run_data = _azure_runs[run_id]
        if run_data.get('mode') != 'offline':
            return jsonify({'error': 'This endpoint is for offline mode only'}), 400

        uploaded_data = run_data.get('collected_data', {})
        if not uploaded_data:
            return jsonify({'error': 'No data found for this run_id'}), 400

        options = {
            'time_filter': data.get('time_filter'),
            'min_severity': data.get('min_severity', 'low'),
        }

        add_log_to_run(run_id, "[AZURE] Starting offline analysis", "info")

        from services.workflow_service import (
            update_run_status,
            register_cancel_event,
            unregister_cancel,
            is_cancelled,
        )
        register_cancel_event(run_id)
        update_run_status(run_id, "running", progress=15)

        import threading

        def run_analysis():
            try:
                result = run_azure_on_existing(
                    run_id=run_id,
                    uploaded_data=uploaded_data,
                    options=options,
                )
                _azure_runs[run_id].update(result)

                # Persist raw data to disk so it survives restart and the
                # dashboard's Data button can pull it back. Same shape as
                # the online pipeline writes — same downstream code reads it.
                try:
                    persist_dir = "/app/data/azure_runs"
                    os.makedirs(persist_dir, exist_ok=True)
                    with open(f"{persist_dir}/{run_id}.json", 'w') as f:
                        json.dump(result, f, default=str)
                except Exception as persist_err:
                    print(f"[AZURE] Warning: Could not persist raw data: {persist_err}", flush=True)

                if is_cancelled(run_id):
                    return
                if result.get('status') in ('failed', 'error'):
                    update_run_status(run_id, "failed", error=result.get('error', 'Unknown error'))
                else:
                    update_run_status(run_id, "completed", progress=100)
            except Exception as e:
                if not is_cancelled(run_id):
                    add_log_to_run(run_id, f"[AZURE] Offline analysis failed: {e}", "error")
                    update_run_status(run_id, "failed", error=str(e))
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        threading.Thread(target=run_analysis, daemon=True).start()

        return jsonify({
            'run_id': run_id,
            'status': 'running',
            'message': 'Offline analysis started — track progress on the dashboard.',
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Results Endpoints (Shared)
# =============================================================================

def _run_visible_in_active_workspace(run_id: str) -> bool:
    """Mirror dashboard_routes.py's _run_visible_in_active_workspace / list_runs()'s
    own workspace check: _azure_runs entries carry no case_id, so without this
    an operator in one case could read/download/delete another case's Azure
    run just by guessing/reusing a run_id. No active case_id means no
    filtering (admin/no-workspace-concept context)."""
    from flask import g
    case_id = getattr(g, "case_id", None)
    if not case_id:
        return True
    wf = get_automation_run(run_id)
    return bool(wf) and wf.get("case_id") == case_id


@azure_bp.route('/api/azure/status/<run_id>', methods=['GET'])
def get_run_status(run_id):
    """Get status of a specific run."""
    try:
        if run_id not in _azure_runs or not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Run not found'}), 404

        run_data = _azure_runs[run_id]

        # Pull observability fields from the persisted workflow row (the
        # in-memory _azure_runs dict tracks pipeline state, not these).
        phase_timings = None
        llm_metrics = None
        sigma_rule_tally = None
        try:
            from services import get_automation_run as _get_workflow
            wf = _get_workflow(run_id)
            if wf:
                phase_timings = wf.get('phase_timings')
                llm_metrics = wf.get('llm_metrics')
                sigma_rule_tally = wf.get('sigma_rule_tally')
        except Exception:
            pass

        return jsonify({
            'run_id': run_id,
            'status': run_data.get('status'),
            'mode': run_data.get('mode'),
            'phases': run_data.get('phases', {}),
            'start_time': run_data.get('start_time'),
            'end_time': run_data.get('end_time'),
            'error': run_data.get('error'),
            'phase_timings': phase_timings,
            'llm_metrics': llm_metrics,
            'sigma_rule_tally': sigma_rule_tally,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/results/<run_id>', methods=['GET'])
def get_run_results(run_id):
    """Get collected/uploaded data for a run."""
    try:
        if run_id not in _azure_runs or not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Run not found'}), 404

        run_data = _azure_runs[run_id]
        collected_data = run_data.get('collected_data', {})

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        source = request.args.get('source')

        # Filter by source if specified
        if source and source in collected_data:
            data_to_return = {source: collected_data[source]}
        else:
            data_to_return = collected_data

        # Calculate totals
        total_records = sum(len(v) for v in data_to_return.values())

        # Apply pagination (simple approach - paginate all records)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

        paginated = {}
        current_idx = 0
        for src, records in data_to_return.items():
            src_records = []
            for record in records:
                if current_idx >= start_idx and current_idx < end_idx:
                    src_records.append(record)
                current_idx += 1
                if current_idx >= end_idx:
                    break
            if src_records:
                paginated[src] = src_records
            if current_idx >= end_idx:
                break

        return jsonify({
            'run_id': run_id,
            'sources': list(collected_data.keys()),
            'total_records': total_records,
            'page': page,
            'per_page': per_page,
            'data': paginated
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/findings/<run_id>', methods=['GET'])
def get_run_findings(run_id):
    """Get SIGMA detection findings for a run."""
    try:
        if run_id not in _azure_runs or not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Run not found'}), 404

        run_data = _azure_runs[run_id]
        findings = run_data.get('findings', {})

        # Filter by severity if specified
        min_severity = request.args.get('min_severity', 'informational')
        severity_order = ['informational', 'low', 'medium', 'high', 'critical']
        min_idx = severity_order.index(min_severity.lower()) if min_severity.lower() in severity_order else 0

        filtered_findings = {}
        for source, source_findings in findings.items():
            filtered = [
                f for f in source_findings
                if severity_order.index(f.get('severity', 'medium').lower()) >= min_idx
            ]
            if filtered:
                filtered_findings[source] = filtered

        return jsonify({
            'run_id': run_id,
            'total_findings': sum(len(v) for v in filtered_findings.values()),
            'findings_by_source': {k: len(v) for k, v in filtered_findings.items()},
            'findings': filtered_findings
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/analysis/<run_id>', methods=['GET'])
def get_run_analysis(run_id):
    """Get LLM analysis results for a run."""
    try:
        if run_id not in _azure_runs or not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Run not found'}), 404

        run_data = _azure_runs[run_id]

        return jsonify({
            'run_id': run_id,
            'analysis': run_data.get('analysis', {}),
            'reports': run_data.get('reports', {})
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/runs', methods=['GET'])
def list_runs():
    """List all Azure runs (scoped to the active workspace via X-Case-Id)."""
    try:
        from flask import g
        from services.file_storage_service import get_workflow
        case_id = getattr(g, 'case_id', None)
        runs = []
        for run_id, run_data in _azure_runs.items():
            if case_id:                       # workspace isolation
                wf = get_workflow(run_id)
                if wf and wf.get('case_id') and wf.get('case_id') != case_id:
                    continue
            runs.append({
                'run_id': run_id,
                'status': run_data.get('status'),
                'mode': run_data.get('mode'),
                'start_time': run_data.get('start_time'),
                'end_time': run_data.get('end_time'),
                'findings_count': run_data.get('phases', {}).get('detection', {}).get('total_findings', 0)
            })

        # Sort by start time descending
        runs.sort(key=lambda x: x.get('start_time', ''), reverse=True)

        return jsonify({'runs': runs})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/data/<run_id>/download', methods=['GET'])
def download_azure_raw_data(run_id):
    """Download raw collected data, SIGMA findings, and LLM analysis as a ZIP file."""
    import zipfile
    import io

    try:
        if not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Raw data not found. Data is only available for scans run after this update.'}), 404
        # Try in-memory first, then persisted data
        run_data = _azure_runs.get(run_id)
        if not run_data:
            # Load from persisted file
            data_path = f"/app/data/azure_runs/{run_id}.json"
            if os.path.exists(data_path):
                with open(data_path, 'r') as f:
                    run_data = json.load(f)
            else:
                return jsonify({'error': 'Raw data not found. Data is only available for scans run after this update.'}), 404

        collected = run_data.get('collected_data', {})
        findings = run_data.get('findings', {})
        analysis = run_data.get('analysis', {})

        # Build ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Raw collected data per source
            for source, records in collected.items():
                # Strip internal fields for cleaner output
                clean_records = []
                for r in records:
                    clean = r.get('_original', r)
                    clean_records.append(clean)
                zf.writestr(
                    f"collected/{source}.json",
                    json.dumps(clean_records, indent=2, default=str)
                )

            # SIGMA findings per rule
            for rule_name, matches in findings.items():
                zf.writestr(
                    f"findings/{rule_name}.json",
                    json.dumps(matches, indent=2, default=str)
                )

            # LLM analysis
            if analysis:
                for artifact, summary in analysis.items():
                    zf.writestr(
                        f"analysis/{artifact}.md",
                        summary if isinstance(summary, str) else json.dumps(summary, indent=2)
                    )

            # Scan metadata
            metadata = {
                'run_id': run_id,
                'mode': run_data.get('mode'),
                'start_time': run_data.get('start_time'),
                'sources_collected': list(collected.keys()),
                'total_records': sum(len(v) for v in collected.values()),
                'sigma_rules_fired': len(findings),
                'total_findings': sum(len(v) for v in findings.values()),
            }
            zf.writestr('metadata.json', json.dumps(metadata, indent=2))

        zip_buffer.seek(0)

        return Response(
            zip_buffer.getvalue(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="azure_scan_{run_id}.zip"'
            }
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/runs/<run_id>', methods=['DELETE'])
def delete_run(run_id):
    """Delete a run and its data."""
    try:
        if run_id not in _azure_runs or not _run_visible_in_active_workspace(run_id):
            return jsonify({'error': 'Run not found'}), 404

        del _azure_runs[run_id]

        # Clean up uploaded files if offline mode
        run_dir = os.path.join(UPLOAD_FOLDER, run_id)
        if os.path.exists(run_dir):
            import shutil
            shutil.rmtree(run_dir)

        return jsonify({'status': 'deleted', 'run_id': run_id})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
