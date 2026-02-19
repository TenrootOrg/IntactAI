#!/usr/bin/env python3
"""
Agentic Routes - AI-powered forensics pipeline endpoints
"""

import threading
from flask import Blueprint, jsonify, request, Response

from services.agentic import run_agentic_pipeline, run_agentic_on_existing, get_report_content, get_available_report_types
from services.file_storage_service import load_frontend_config
from services.workflow_service import (
    create_automation_run,
    get_automation_run
)

agentic_bp = Blueprint('agentic', __name__)

# Default LLM config
DEFAULT_LLM_CONFIG = {
    "agentic": {
        "llm_mode": "offline",
        "max_concurrent_requests": 5,
        "offline_llm": {
            "provider": "ollama",
            "model": "llama3.3:70b",
            "url": "http://localhost:11434",
            "batch_size": 100
        },
        "online_llm": {
            "provider": "claude",
            "api_key": "",
            "model": "claude-sonnet-4-20250514",
            "batch_size": 100
        }
    }
}


def _load_llm_config():
    """Load LLM configuration from database"""
    try:
        config = load_frontend_config()
        if config:
            return config
    except Exception as e:
        print(f"[AGENTIC] Error loading config: {e}", flush=True)
    return DEFAULT_LLM_CONFIG


@agentic_bp.route('/api/agentic/run', methods=['POST'])
def start_agentic_run():
    """Start a full agentic forensics pipeline"""
    try:
        data = request.get_json()
        blueprint_id = data.get('blueprint_id')
        blueprint_name = data.get('blueprint', 'Unknown')
        client_ids = data.get('client_ids', [])
        collection_minutes = data.get('collection_minutes', 30)
        report_types = data.get('report_types', ['technical'])  # Default: both

        # Severity level filter (informational, low, medium, high, critical)
        severity_level = data.get('severity_level', 'medium')

        # Anonymization options
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])

        # IRIS import options
        import_to_iris = data.get('import_to_iris', False)
        iris_case_name = data.get('iris_case_name', '')

        # Validate
        if not blueprint_id:
            return jsonify({"error": "blueprint_id is required"}), 400
        if not client_ids or len(client_ids) == 0:
            return jsonify({"error": "At least one client must be selected"}), 400
        if collection_minutes < 1 or collection_minutes > 1440:
            return jsonify({"error": "collection_minutes must be between 1 and 1440"}), 400

        # Validate report_types - allow empty list (no reports, just IRIS import)
        valid_types = ['technical']
        report_types = [t for t in report_types if t in valid_types]
        # Note: empty report_types is valid when using IRIS import only

        # Parse custom patterns (handle string input from textarea)
        if isinstance(custom_patterns, str):
            custom_patterns = [p.strip() for p in custom_patterns.split('\n') if p.strip()]

        # Load LLM config
        llm_config = _load_llm_config()

        # Validate severity level
        valid_severities = ['informational', 'low', 'medium', 'high', 'critical']
        if severity_level not in valid_severities:
            severity_level = 'medium'

        # Create workflow run
        run_id = create_automation_run(
            automation_type="agentic",
            name=f"Agentic Analysis ({len(client_ids)} clients, {collection_minutes}m)",
            details={
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_name,
                "client_ids": client_ids,
                "collection_minutes": collection_minutes,
                "report_types": report_types,
                "severity_level": severity_level,
                "anonymize_data": anonymize_data,
                "custom_patterns": custom_patterns,
                "import_to_iris": import_to_iris,
                "iris_case_name": iris_case_name,
                "phase": "starting"
            }
        )

        anonymize_info = f", anonymize={anonymize_data}" if anonymize_data else ""
        iris_info = f", iris={import_to_iris}" if import_to_iris else ""
        print(f"[AGENTIC] Starting pipeline: run_id={run_id}, severity={severity_level}, reports={report_types}{anonymize_info}{iris_info}", flush=True)

        # Start pipeline in background thread
        thread = threading.Thread(
            target=run_agentic_pipeline,
            args=(run_id, blueprint_id, client_ids, collection_minutes, llm_config, report_types,
                  severity_level, anonymize_data, custom_patterns, import_to_iris, iris_case_name),
            daemon=True
        )
        thread.start()

        return jsonify({
            "run_id": run_id,
            "status": "started",
            "report_types": report_types,
            "anonymize_data": anonymize_data,
            "import_to_iris": import_to_iris
        })

    except Exception as e:
        print(f"[AGENTIC] Error starting pipeline: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/analyze-existing', methods=['POST'])
def analyze_existing_collection():
    """Run AI analysis on an existing Velociraptor flow or hunt (skip collection step)"""
    try:
        data = request.get_json()
        flow_id = data.get('flow_id')
        hunt_id = data.get('hunt_id')
        report_types = data.get('report_types', ['technical'])
        severity_level = data.get('severity_level', 'medium')
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])
        import_to_iris = data.get('import_to_iris', False)
        iris_case_name = data.get('iris_case_name', '')

        # Validate - need either flow_id or hunt_id
        if not flow_id and not hunt_id:
            return jsonify({"error": "Either flow_id or hunt_id is required"}), 400

        # Validate report_types
        valid_types = ['technical']
        report_types = [t for t in report_types if t in valid_types]

        # Validate severity level
        valid_severities = ['informational', 'low', 'medium', 'high', 'critical']
        if severity_level not in valid_severities:
            severity_level = 'medium'

        # Parse custom patterns
        if isinstance(custom_patterns, str):
            custom_patterns = [p.strip() for p in custom_patterns.split('\n') if p.strip()]

        # Load LLM config
        llm_config = _load_llm_config()

        # Create workflow run
        collection_id = flow_id or hunt_id
        collection_type = "flow" if flow_id else "hunt"
        run_id = create_automation_run(
            automation_type="agentic",
            name=f"Agentic Analysis (existing {collection_type}: {collection_id})",
            details={
                "flow_id": flow_id,
                "hunt_id": hunt_id,
                "report_types": report_types,
                "severity_level": severity_level,
                "anonymize_data": anonymize_data,
                "custom_patterns": custom_patterns,
                "import_to_iris": import_to_iris,
                "iris_case_name": iris_case_name,
                "phase": "starting",
                "analyze_existing": True
            }
        )

        print(f"[AGENTIC] Starting analysis on existing {collection_type}: {collection_id}, run_id={run_id}", flush=True)

        # Start pipeline in background thread
        thread = threading.Thread(
            target=run_agentic_on_existing,
            args=(run_id, flow_id, hunt_id, llm_config, report_types,
                  severity_level, anonymize_data, custom_patterns, import_to_iris, iris_case_name),
            daemon=True
        )
        thread.start()

        return jsonify({
            "run_id": run_id,
            "status": "started",
            "collection_type": collection_type,
            "collection_id": collection_id,
            "report_types": report_types,
            "anonymize_data": anonymize_data,
            "import_to_iris": import_to_iris
        })

    except Exception as e:
        print(f"[AGENTIC] Error starting analysis on existing: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/status', methods=['GET'])
def get_agentic_status(run_id):
    """Get status of an agentic pipeline run"""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404

        # Check if report exists and get available types
        has_report = get_report_content(run_id) is not None
        available_reports = get_available_report_types(run_id) if has_report else []

        # Get IRIS result if present
        details = run.get('details', {})
        iris_result = details.get('iris_result') if isinstance(details, dict) else None

        return jsonify({
            "run_id": run_id,
            "status": run.get('status', 'unknown'),
            "progress": run.get('progress', 0),
            "phase": run.get('phase', ''),
            "has_report": has_report,
            "available_reports": available_reports,
            "iris_result": iris_result,
            "logs": run.get('logs', [])[-20:],  # Last 20 log entries
            "created_at": run.get('created_at'),
            "updated_at": run.get('updated_at')
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/download', methods=['GET'])
def download_agentic_report(run_id):
    """Download the generated report. Optionally specify report_type query param."""
    try:
        report_type = request.args.get('type')  # 'executive', 'technical', or None for combined
        content = get_report_content(run_id, report_type)
        if not content:
            return jsonify({"error": "Report not found"}), 404

        # Determine filename based on type
        if report_type:
            filename = f"agentic_{report_type}_report_{run_id}.md"
        else:
            filename = f"agentic_combined_report_{run_id}.md"

        return Response(
            content,
            mimetype='text/markdown',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
