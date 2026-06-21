#!/usr/bin/env python3
"""
Agentic Routes - AI-powered forensics pipeline endpoints
"""

import threading
from flask import Blueprint, jsonify, request

from services.agentic import run_agentic_pipeline
from services.file_storage_service import load_frontend_config, get_agentic_blueprint, get_velociraptor_blueprint
from services.workflow_service import (
    create_automation_run,
    get_automation_run,
    add_log_to_run,
    update_run_status,
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
    try:
        data = request.get_json()
        blueprint_id = data.get('blueprint_id')
        # Look up blueprint name from database if not provided (check both agentic and velociraptor tables)
        blueprint_name = data.get('blueprint')
        if not blueprint_name:
            bp = get_agentic_blueprint(blueprint_id) or get_velociraptor_blueprint(blueprint_id)
            blueprint_name = bp.get('name', 'Unknown') if bp else 'Unknown'
        # SHAPE VALIDATION (Mythos #2 extended): every `client_ids`
        # element flows into `services/agentic/collectors.py` VQL
        # strings via f-string concat (`get_flow(client_id='{cid}',
        # ...)`, `cancel_flow(client_id='{cid}', ...)`, etc. — 9+
        # sites). Reject anything that's not Velociraptor's strict
        # `C.<hex>` ID format. Legitimate clients always match.
        from services.vql_safety import validate_client_ids_list
        client_ids, _cid_err = validate_client_ids_list(data.get('client_ids'))
        if _cid_err:
            return jsonify({"error": _cid_err}), 400
        collection_minutes = data.get('collection_minutes', 30)
        report_types = []   # collection-only — per-run LLM reporting retired; the case reports

        # Anonymization options
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])

        # IRIS import options
        import_to_iris = data.get('import_to_iris', False)
        iris_case_name = data.get('iris_case_name', '')

        # Time filter options (handle null from frontend)
        time_filter = data.get('time_filter') or {}
        # Case-window propagation: a run launched UNDER a Case can pass the case's
        # {start,end} window directly; translate it to a time_filter so the incident
        # window bounds collection (per-artifact DateAfter + post-collection filter) —
        # cutting wasted rows/tokens. Explicit time_filter still wins.
        tw = data.get('time_window') or {}
        if not time_filter.get('enabled') and (tw.get('start') or tw.get('end')):
            time_filter = {'enabled': True, 'mode': 'between',
                           'start_datetime': tw.get('start'), 'end_datetime': tw.get('end')}

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


@agentic_bp.route('/api/agentic/run/<run_id>/status', methods=['GET'])
def get_agentic_status(run_id):
    """Get status of an agentic pipeline run"""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404

        # Collection-only: no per-run report; the case is the reporting surface.
        details = run.get('details', {})
        if not isinstance(details, dict):
            details = {}

        return jsonify({
            "run_id": run_id,
            "status": run.get('status', 'unknown'),
            "progress": run.get('progress', 0),
            "phase": run.get('phase', ''),
            "client_count": details.get('client_count', 1),
            "hostnames": details.get('hostnames', {}),
            "logs": run.get('logs', [])[-20:],  # Last 20 log entries
            "created_at": run.get('created_at'),
            "updated_at": run.get('updated_at')
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
