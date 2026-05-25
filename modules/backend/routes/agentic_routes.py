#!/usr/bin/env python3
"""
Agentic Routes - AI-powered forensics pipeline endpoints
"""

import threading
from flask import Blueprint, jsonify, request, Response

from services.agentic import run_agentic_pipeline, run_agentic_on_existing, get_report_content, get_available_report_types
from services.file_storage_service import load_frontend_config, get_agentic_blueprint, get_velociraptor_blueprint
from services.workflow_service import (
    create_automation_run,
    get_automation_run
)
from config import is_module_enabled

agentic_bp = Blueprint('agentic', __name__)

# Default LLM config
DEFAULT_LLM_CONFIG = {
    "agentic": {
        "llm_mode": "online",
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
            "model": "claude-sonnet-4-6",
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
    if not is_module_enabled('agentic'):
        return jsonify({"error": "Agentic module is not enabled. Enable it in config.yaml and rebuild the backend."}), 400
    try:
        data = request.get_json()
        blueprint_id = data.get('blueprint_id')
        # Look up blueprint name from database if not provided (check both agentic and velociraptor tables)
        blueprint_name = data.get('blueprint')
        if not blueprint_name:
            bp = get_agentic_blueprint(blueprint_id) or get_velociraptor_blueprint(blueprint_id)
            blueprint_name = bp.get('name', 'Unknown') if bp else 'Unknown'
        client_ids = data.get('client_ids', [])
        collection_minutes = data.get('collection_minutes', 30)
        report_types = data.get('report_types', ['technical'])  # Default: both

        # Anonymization options
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])

        # IRIS import options
        import_to_iris = data.get('import_to_iris', False)
        iris_case_name = data.get('iris_case_name', '')

        # Time filter options (handle null from frontend)
        time_filter = data.get('time_filter') or {}

        # Severity filter (post-collection, before LLM)
        min_severity = data.get('min_severity', 'informational')
        valid_severities = ['informational', 'low', 'medium', 'high', 'critical']
        if min_severity not in valid_severities:
            min_severity = 'informational'

        # External log files (optional)
        # Each item: {'upload_id': '...', 'filename': 'crowdstrike.csv'}
        external_files = data.get('external_files', [])

        # Cross-client synthesis flag (multi-client only). When False
        # (default), multi-client runs still produce per-client reports
        # but skip the org-wide macro `00_ORGANIZATION_SUMMARY.md` and
        # the extra LLM call that produces it. Operators opt in only when
        # they want the cross-host narrative. Ignored when N=1 — single-
        # client runs never generated a macro anyway.
        cross_client_synthesis = bool(data.get('cross_client_synthesis'))

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

        # Validate time filter if enabled
        if time_filter.get('enabled'):
            mode = time_filter.get('mode', 'relative')
            if mode == 'between':
                start_dt = time_filter.get('start_datetime')
                if not start_dt:
                    return jsonify({"error": "start_datetime required for time filter 'between' mode"}), 400
                # Validate date format and order if both provided
                end_dt = time_filter.get('end_datetime')
                if start_dt and end_dt:
                    try:
                        from datetime import datetime
                        s = datetime.fromisoformat(start_dt.replace('Z', '+00:00'))
                        e = datetime.fromisoformat(end_dt.replace('Z', '+00:00'))
                        if s >= e:
                            return jsonify({"error": "start_datetime must be before end_datetime"}), 400
                    except ValueError:
                        return jsonify({"error": "Invalid datetime format. Use ISO 8601 (e.g., 2024-01-15T00:00:00Z)"}), 400
            elif mode == 'relative':
                valid_ranges = ['24h', '7d', '30d', '90d']
                rel_range = time_filter.get('relative_range', '7d')
                if rel_range not in valid_ranges:
                    return jsonify({"error": f"relative_range must be one of: {valid_ranges}"}), 400

        # Load LLM config
        llm_config = _load_llm_config()

        # Resolve hostnames upfront so the workflow name + run details
        # carry human-readable names from the moment the row appears in
        # the Workflows tab. Mirrors the Timesketch pattern (which uses
        # the client list it already has) — the agentic side only had
        # client_ids in hand at request time, so we add one VQL roundtrip
        # against the Velociraptor server here. Falls back to client_id
        # if the lookup fails (operator still sees something usable).
        from services.agentic.collectors import resolve_hostnames as _resolve
        hostnames = _resolve(client_ids)
        names = [hostnames.get(cid, cid) for cid in client_ids]

        # Workflow-name label uses the "show up to 3 names, then collapse"
        # rule. Past 3 the names string would overflow the table column
        # in the dashboard and stop being useful at a glance.
        if len(client_ids) <= 3:
            client_label = f"{len(client_ids)} clients ({', '.join(names)})"
        else:
            client_label = f"{len(client_ids)} clients"

        # Create workflow run
        run_id = create_automation_run(
            automation_type="agentic",
            name=f"Agentic Analysis - {client_label}, {collection_minutes}m",
            details={
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_name,
                "client_ids": client_ids,
                # Stashed so the report generator can read the same map
                # without re-querying. Keys are client_ids; values are
                # the human hostnames (or the client_id as fallback).
                "hostnames": hostnames,
                "collection_minutes": collection_minutes,
                "report_types": report_types,
                "anonymize_data": anonymize_data,
                "custom_patterns": custom_patterns,
                "import_to_iris": import_to_iris,
                "iris_case_name": iris_case_name,
                "time_filter": time_filter if time_filter.get('enabled') else None,
                "min_severity": min_severity,
                "external_files": external_files if external_files else None,
                "cross_client_synthesis": cross_client_synthesis,
                "phase": "starting"
            }
        )

        severity_info = f", min_severity={min_severity}" if min_severity != 'informational' else ""
        anonymize_info = f", anonymize={anonymize_data}" if anonymize_data else ""
        iris_info = f", iris={import_to_iris}" if import_to_iris else ""
        time_filter_info = ""
        if time_filter.get('enabled'):
            mode = time_filter.get('mode', 'relative')
            if mode == 'relative':
                time_filter_info = f", time_filter=relative({time_filter.get('relative_range', '7d')})"
            else:
                time_filter_info = f", time_filter=between"
        external_info = f", external_files={len(external_files)}" if external_files else ""
        print(f"[AGENTIC] Starting pipeline: run_id={run_id}, reports={report_types}{severity_info}{anonymize_info}{iris_info}{time_filter_info}{external_info}", flush=True)

        # Register cancel event for stop support
        from services.workflow_service import register_cancel_event
        cancel_event = register_cancel_event(run_id)

        # Start pipeline in background thread
        time_filter_arg = time_filter if time_filter.get('enabled') else None
        thread = threading.Thread(
            target=run_agentic_pipeline,
            args=(run_id, blueprint_id, client_ids, collection_minutes, llm_config, report_types,
                  anonymize_data, custom_patterns, import_to_iris, iris_case_name, time_filter_arg, min_severity,
                  external_files, cancel_event),
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
    if not is_module_enabled('agentic'):
        return jsonify({"error": "Agentic module is not enabled. Enable it in config.yaml and rebuild the backend."}), 400
    try:
        data = request.get_json()
        # `flow_id` may arrive as a single string (legacy single-flow run),
        # a JSON array of IDs (future-friendly), or a comma-separated string
        # (what the current multi-client UI sends). Normalise to one of:
        #   - None
        #   - single string (legacy single-flow path)
        #   - list[str] (new multi-flow path — handled by the collector loop)
        flow_id_raw = data.get('flow_id')
        if isinstance(flow_id_raw, list):
            _flow_ids = [str(f).strip() for f in flow_id_raw if str(f).strip()]
        elif isinstance(flow_id_raw, str) and flow_id_raw.strip():
            _flow_ids = [f.strip() for f in flow_id_raw.split(',') if f.strip()]
        else:
            _flow_ids = []
        if len(_flow_ids) > 1:
            flow_id = _flow_ids                          # list
        elif _flow_ids:
            flow_id = _flow_ids[0]                       # single string (back-compat)
        else:
            flow_id = None
        hunt_id = data.get('hunt_id')
        report_types = data.get('report_types', ['technical'])
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])
        import_to_iris = data.get('import_to_iris', False)
        iris_case_name = data.get('iris_case_name', '')
        time_filter = data.get('time_filter') or {}  # Handle null from frontend

        # Severity filter (post-collection, before LLM)
        min_severity = data.get('min_severity', 'informational')
        valid_severities = ['informational', 'low', 'medium', 'high', 'critical']
        if min_severity not in valid_severities:
            min_severity = 'informational'

        # External log files (optional)
        external_files = data.get('external_files', [])

        # Cross-client synthesis flag (multi-client only). Same semantics
        # as the main /api/agentic/run route: opt-in macro pass. Useful
        # on re-runs where the operator already has per-client reports
        # and now wants the cross-host narrative.
        cross_client_synthesis = bool(data.get('cross_client_synthesis'))

        # Optional client scoping for hunt mode. When the analyst pastes a
        # hunt-derived flow ID (`F.xxx.H`) the frontend opens the multi-
        # client picker and sends the selection here so the collector can
        # push a `WHERE ClientId IN (...)` filter into the hunt-flows
        # enumeration. Ignored on single-flow runs.
        client_ids = data.get('client_ids') or []
        if not isinstance(client_ids, list):
            return jsonify({"error": "client_ids must be a list of client ID strings"}), 400
        client_ids = [str(c) for c in client_ids if c]

        # Validate - need either flow_id or hunt_id
        if not flow_id and not hunt_id:
            return jsonify({"error": "Either flow_id or hunt_id is required"}), 400

        # If a hunt is being analyzed and the picker was offered, require
        # at least one client. (Frontend should also enforce — defence in
        # depth.) For standalone H.<id> runs without picker we keep the
        # current "all clients" behavior, so empty client_ids is allowed.
        # The frontend signals "picker was offered" by sending client_ids
        # explicitly; if it's missing entirely we treat as "all clients".

        # Validate report_types
        valid_types = ['technical']
        report_types = [t for t in report_types if t in valid_types]

        # Parse custom patterns
        if isinstance(custom_patterns, str):
            custom_patterns = [p.strip() for p in custom_patterns.split('\n') if p.strip()]

        # Load LLM config
        llm_config = _load_llm_config()

        # Create workflow run
        # flow_id can now be a list — render as comma-separated for the
        # workflow name + details.flow_id (DB field accepts string or list
        # but the run-name template needs a string).
        if isinstance(flow_id, list):
            collection_id = ', '.join(flow_id)
        else:
            collection_id = flow_id or hunt_id
        collection_type = "flow" if flow_id else "hunt"
        run_id = create_automation_run(
            automation_type="agentic",
            name=f"Agentic Analysis (existing {collection_type}: {collection_id})",
            details={
                "flow_id": flow_id,
                "hunt_id": hunt_id,
                "report_types": report_types,
                "anonymize_data": anonymize_data,
                "custom_patterns": custom_patterns,
                "import_to_iris": import_to_iris,
                "iris_case_name": iris_case_name,
                "time_filter": time_filter if time_filter.get('enabled') else None,
                "min_severity": min_severity,
                "external_files": external_files if external_files else None,
                "cross_client_synthesis": cross_client_synthesis,
                "phase": "starting",
                "analyze_existing": True
            }
        )

        severity_info = f", min_severity={min_severity}" if min_severity != 'informational' else ""
        time_filter_info = ""
        if time_filter.get('enabled'):
            mode = time_filter.get('mode', 'relative')
            if mode == 'relative':
                time_filter_info = f", time_filter=relative({time_filter.get('relative_range', '7d')})"
            else:
                time_filter_info = f", time_filter=between"
        external_info = f", external_files={len(external_files)}" if external_files else ""
        print(f"[AGENTIC] Starting analysis on existing {collection_type}: {collection_id}, run_id={run_id}{severity_info}{time_filter_info}{external_info}", flush=True)

        # Register cancel event for stop support
        from services.workflow_service import register_cancel_event
        cancel_event = register_cancel_event(run_id)

        # Start pipeline in background thread
        time_filter_arg = time_filter if time_filter.get('enabled') else None
        thread = threading.Thread(
            target=run_agentic_on_existing,
            args=(run_id, flow_id, hunt_id, llm_config, report_types,
                  anonymize_data, custom_patterns, import_to_iris, iris_case_name, time_filter_arg, min_severity,
                  external_files, cancel_event),
            kwargs={'client_ids': client_ids or None},
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

        # Get details
        details = run.get('details', {})
        if not isinstance(details, dict):
            details = {}

        iris_result = details.get('iris_result')
        multi_client = details.get('multi_client', False)
        report_zip = details.get('report_zip')
        client_count = details.get('client_count', 1)
        hostnames = details.get('hostnames', {})

        return jsonify({
            "run_id": run_id,
            "status": run.get('status', 'unknown'),
            "progress": run.get('progress', 0),
            "phase": run.get('phase', ''),
            "has_report": has_report,
            "available_reports": available_reports,
            "iris_result": iris_result,
            "multi_client": multi_client,
            "report_zip": report_zip is not None,
            "client_count": client_count,
            "hostnames": hostnames,
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


@agentic_bp.route('/api/agentic/run/<run_id>/download/zip', methods=['GET'])
def download_agentic_reports_zip(run_id):
    """Download all reports as a ZIP file (for multi-client analysis)."""
    import os
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404

        details = run.get('details', {})
        if not isinstance(details, dict):
            return jsonify({"error": "No multi-client reports available"}), 404

        zip_path = details.get('report_zip')
        if not zip_path or not os.path.exists(zip_path):
            return jsonify({"error": "Report ZIP not found"}), 404

        # Read ZIP file
        with open(zip_path, 'rb') as f:
            zip_content = f.read()

        return Response(
            zip_content,
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="agentic_reports_{run_id}.zip"'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/report/<client_id>', methods=['GET'])
def get_client_report(run_id, client_id):
    """Get the report for a specific client (for multi-client analysis)."""
    import os
    import zipfile
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404

        details = run.get('details', {})
        if not isinstance(details, dict):
            return jsonify({"error": "No multi-client reports available"}), 404

        zip_path = details.get('report_zip')
        if not zip_path or not os.path.exists(zip_path):
            return jsonify({"error": "Report ZIP not found"}), 404

        hostnames = details.get('hostnames', {})
        hostname = hostnames.get(client_id, client_id)
        safe_hostname = "".join(c if c.isalnum() or c in '-_' else '_' for c in hostname)

        # Read from ZIP
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Try to find the client's report
            for name in zf.namelist():
                if safe_hostname in name and name.endswith('_report.md'):
                    content = zf.read(name).decode('utf-8')
                    return Response(
                        content,
                        mimetype='text/markdown',
                        headers={
                            'Content-Disposition': f'attachment; filename="{name}"'
                        }
                    )

        return jsonify({"error": f"Report for client {client_id} not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500
