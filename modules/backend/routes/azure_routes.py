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
    get_available_sources
)
from services.azure.collectors import parse_uploaded_logs
from services.azure.sigma_runner import validate_rules_directory, get_available_rules_count
from services.workflow_logger import add_log_to_run
from routes.config_routes import _load_cloud_config
from config import is_module_enabled

azure_bp = Blueprint('azure', __name__)

# In-memory storage for run results (would use database in production)
_azure_runs = {}

# Upload configuration
UPLOAD_FOLDER = '/tmp/azure_uploads'
ALLOWED_EXTENSIONS = {'json', 'jsonl', 'csv'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
        if rules_valid:
            counts = get_available_rules_count()
            return jsonify({
                'available': True,
                'message': rules_msg,
                'counts': counts
            })
        else:
            return jsonify({
                'available': False,
                'message': rules_msg
            })
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
        "time_filter": {"type": "relative", "value": "7d"} | {"type": "between", "start": "...", "end": "..."},
        "enable_llm": true/false,
        "iris_config": {...}
    }
    """
    # Always create workflow first so everything is visible in logs
    from services.workflow_service import create_automation_run, update_run_status

    data = request.json or {}
    blueprint_id = data.get('blueprint', 'azure_quick_triage')

    run_id = create_automation_run(
        automation_type="azure_scan",
        name=f"Azure Scan: {blueprint_id}",
        details={
            "trigger": "manual",
            "blueprint": blueprint_id,
            "mode": "online",
            "target_users": data.get('target_users', []),
            "target_ips": data.get('target_ips', []),
        }
    )
    update_run_status(run_id, "running", progress=5)

    # Run everything in background thread - all errors go to workflow log
    import threading
    def run_scan():
        try:
            # Validate module
            if not is_module_enabled('azure'):
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

            # Load LLM config
            from services.file_storage_service import load_frontend_config
            llm_config = load_frontend_config() or {}

            # Build options with identity filters
            options = {
                'enable_llm': data.get('enable_llm', False),
                'llm_config': llm_config,
                'time_filter': data.get('time_filter'),
                'min_severity': data.get('min_severity', 'medium'),
                'iris_config': data.get('iris_config'),
                'target_users': data.get('target_users', []),
                'target_ips': data.get('target_ips', []),
                'pivot_mode': data.get('pivot_mode', False),
                'anonymizer': None
            }

            result = run_azure_pipeline(
                run_id=run_id,
                azure_config=azure_config,
                blueprint=blueprint,
                options=options
            )
            _azure_runs[run_id] = result

            # Persist raw data to disk so it survives backend restart
            try:
                persist_dir = "/data/db/azure_runs"
                os.makedirs(persist_dir, exist_ok=True)
                with open(f"{persist_dir}/{run_id}.json", 'w') as f:
                    json.dump(result, f, default=str)
            except Exception as persist_err:
                print(f"[AZURE] Warning: Could not persist raw data: {persist_err}", flush=True)

            if result.get('status') == 'failed':
                update_run_status(run_id, "failed", error=result.get('error', 'Unknown error'))
            else:
                update_run_status(run_id, "completed", progress=100, details={'has_report': bool(result.get('has_report'))})

        except Exception as e:
            add_log_to_run(run_id, f"[AZURE] Scan failed: {str(e)}", "error")
            update_run_status(run_id, "failed", error=str(e))
            traceback.print_exc()

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
    if not is_module_enabled('azure'):
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

        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(run_dir, filename)
                file.save(file_path)

                # Parse the file
                try:
                    data, parse_status = parse_uploaded_logs(file_path)
                    parsed_data.update(data)

                    uploaded_files.append({
                        'filename': filename,
                        'records': parse_status.get('record_count', 0),
                        'source_type': parse_status.get('detected_source')
                    })
                except Exception as e:
                    uploaded_files.append({
                        'filename': filename,
                        'error': str(e)
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
    Run SIGMA detection and LLM analysis on uploaded logs.

    Request body:
    {
        "run_id": "azure_offline_xxx",
        "time_filter": {...},
        "enable_llm": true/false,
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

        # Build options
        options = {
            'enable_llm': data.get('enable_llm', False),
            'llm_config': data.get('llm_config', {}),
            'time_filter': data.get('time_filter'),
            'min_severity': data.get('min_severity', 'low'),
            'iris_config': data.get('iris_config')
        }

        add_log_to_run(run_id, "[AZURE] Starting offline analysis", "info")

        # Run analysis pipeline
        result = run_azure_on_existing(
            run_id=run_id,
            uploaded_data=uploaded_data,
            options=options
        )

        # Update stored data
        _azure_runs[run_id].update(result)

        return jsonify({
            'run_id': run_id,
            'status': result.get('status'),
            'findings_count': result.get('phases', {}).get('detection', {}).get('total_findings', 0),
            'message': 'Analysis complete' if result.get('status') == 'complete' else result.get('error', 'Analysis failed')
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Results Endpoints (Shared)
# =============================================================================

@azure_bp.route('/api/azure/status/<run_id>', methods=['GET'])
def get_run_status(run_id):
    """Get status of a specific run."""
    try:
        if run_id not in _azure_runs:
            return jsonify({'error': 'Run not found'}), 404

        run_data = _azure_runs[run_id]

        return jsonify({
            'run_id': run_id,
            'status': run_data.get('status'),
            'mode': run_data.get('mode'),
            'phases': run_data.get('phases', {}),
            'start_time': run_data.get('start_time'),
            'end_time': run_data.get('end_time'),
            'error': run_data.get('error')
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/results/<run_id>', methods=['GET'])
def get_run_results(run_id):
    """Get collected/uploaded data for a run."""
    try:
        if run_id not in _azure_runs:
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
        if run_id not in _azure_runs:
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
        if run_id not in _azure_runs:
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
    """List all Azure runs."""
    try:
        runs = []
        for run_id, run_data in _azure_runs.items():
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


@azure_bp.route('/api/azure/report/<run_id>/download', methods=['GET'])
def download_azure_report(run_id):
    """Download Azure security report as markdown file.

    Query params:
        type: 'executive', 'technical', or omit for combined
    """
    try:
        from services.azure.reports import get_azure_report, get_azure_report_types

        report_type = request.args.get('type')
        content = get_azure_report(run_id, report_type)

        if not content:
            available = get_azure_report_types(run_id)
            if available:
                return jsonify({
                    'error': f"Report type '{report_type}' not found. Available: {available}"
                }), 404
            return jsonify({'error': 'No report found for this run'}), 404

        if report_type:
            filename = f"azure_{report_type}_report_{run_id}.md"
        else:
            filename = f"azure_report_{run_id}.md"

        return Response(
            content,
            mimetype='text/markdown',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/report/<run_id>/types', methods=['GET'])
def get_azure_report_types_endpoint(run_id):
    """Get available report types for an Azure scan."""
    try:
        from services.azure.reports import get_azure_report_types
        types = get_azure_report_types(run_id)
        return jsonify({'types': types})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@azure_bp.route('/api/azure/data/<run_id>/download', methods=['GET'])
def download_azure_raw_data(run_id):
    """Download raw collected data, SIGMA findings, and LLM analysis as a ZIP file."""
    import zipfile
    import io

    try:
        # Try in-memory first, then persisted data
        run_data = _azure_runs.get(run_id)
        if not run_data:
            # Load from persisted file
            data_path = f"/data/db/azure_runs/{run_id}.json"
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
        if run_id not in _azure_runs:
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
