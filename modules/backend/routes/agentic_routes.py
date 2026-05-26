#!/usr/bin/env python3
"""
Agentic Routes - AI-powered forensics pipeline endpoints
"""

import threading
from flask import Blueprint, jsonify, request, Response

from services.agentic import run_agentic_pipeline, run_agentic_on_existing, get_report_content, get_available_report_types
from services.agentic import chat as agentic_chat
from services.file_storage_service import load_frontend_config, get_agentic_blueprint, get_velociraptor_blueprint, get_workflow, save_workflow
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


# ---------------------------------------------------------------------------
# Interactive mode: chat about the report, synthesise a master prompt, then
# re-run the pipeline against the same data with the master prompt in scope.
# ---------------------------------------------------------------------------


@agentic_bp.route('/api/agentic/run/<run_id>/chat', methods=['GET'])
def get_agentic_chat(run_id):
    """Snapshot of the chat transcript + the current master prompt + report
    version. Used by the UI to populate the chat modal on open."""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        state = agentic_chat.get_chat_state(run_id)
        return jsonify(state)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/chat', methods=['POST'])
def post_agentic_chat(run_id):
    """Append an operator message, get an assistant reply (single-turn LLM
    call with prior history flattened into the prompt), persist both."""
    if not is_module_enabled('agentic'):
        return jsonify({"error": "Agentic module is not enabled."}), 400
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404

        data = request.get_json() or {}
        message = data.get('message', '')
        llm_config = _load_llm_config()

        try:
            reply = agentic_chat.send_chat_message(run_id, message, llm_config)
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except RuntimeError as re_:
            return jsonify({"error": str(re_)}), 502

        return jsonify({"assistant": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/chat', methods=['DELETE'])
def clear_agentic_chat(run_id):
    """Wipe the chat transcript + synthesised master prompt for this run.
    Used by the modal's 'Clear chat' link."""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        agentic_chat.clear_chat(run_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/chat/synthesize', methods=['POST'])
def synthesize_agentic_chat(run_id):
    """Compress the chat into a structured master prompt. Persisted to
    workflow.details.master_prompt so the operator can edit it before
    triggering the re-run."""
    if not is_module_enabled('agentic'):
        return jsonify({"error": "Agentic module is not enabled."}), 400
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        llm_config = _load_llm_config()
        try:
            master = agentic_chat.synthesize_master_prompt(run_id, llm_config)
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except RuntimeError as re_:
            return jsonify({"error": str(re_)}), 502
        return jsonify({"master_prompt": master})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/api/agentic/run/<run_id>/master-prompt', methods=['PUT'])
def update_master_prompt(run_id):
    """Operator-edited master prompt override. Empty string clears it."""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        data = request.get_json() or {}
        agentic_chat.set_master_prompt(run_id, data.get('master_prompt'))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _bump_run_version(run_id, run):
    """Bump workflow.details.report_version (1 → 2 → …) and rewrite the
    workflow `name` to carry the version suffix. Idempotent on the name
    side: an existing ` [vN]` suffix is stripped before the new one is
    appended, so repeated re-runs don't accumulate `[v2] [v3]`."""
    import re
    details = run.get('details') or {}
    if not isinstance(details, dict):
        details = {}
    cur_version = int(details.get('report_version') or 1)
    new_version = cur_version + 1
    cur_name = run.get('name') or 'Agentic run'
    # Strip any prior ` [vN]` suffix to keep the name clean across re-runs.
    base_name = re.sub(r'\s*\[v\d+\]\s*$', '', cur_name).rstrip()
    new_name = f"{base_name} [v{new_version}]"

    workflow = get_workflow(run_id)
    if not workflow:
        return new_version
    workflow['name'] = new_name
    existing_details = workflow.get('details') or {}
    if not isinstance(existing_details, dict):
        existing_details = {}
    existing_details['report_version'] = new_version
    workflow['details'] = existing_details
    save_workflow(workflow)
    return new_version


def _load_existing_client_reports_from_zip(run_id, hostnames):
    """Read the per-client report markdown out of the current reports.zip
    so we can carry forward un-touched clients on a narrowed re-run.
    Returns dict[client_id -> markdown]; missing files = empty dict."""
    import os
    import zipfile
    zip_path = f"/data/downloads/{run_id}/reports.zip"
    if not os.path.exists(zip_path):
        return {}
    out = {}
    # Reverse the safe_hostname transform so we can map filenames back to
    # client_ids. The original code uses: replace any non-alnum/-/_ with _.
    rev = {}
    for cid, hn in (hostnames or {}).items():
        safe = "".join(c if c.isalnum() or c in '-_' else '_' for c in (hn or cid))
        rev[f"{safe}_report.md"] = cid
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                cid = rev.get(name)
                if cid:
                    out[cid] = zf.read(name).decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[AGENTIC] Failed to read existing reports from {zip_path}: {e}", flush=True)
    return out


def _rerun_reports_only(run_id, master_prompt, llm_config, target_client_ids=None):
    """Regenerate per-client + (optionally) macro reports from cached
    artifact_summaries.json + raw_results.json, with master_prompt in scope.

    target_client_ids: optional subset of client IDs to regenerate. When
    set, only those clients get a fresh LLM-generated report; the rest
    are carried forward verbatim from the previous reports.zip. Saves
    money + time when the operator's chat only concerns one host on a
    multi-client run. None / empty / equal to the full set = regenerate
    everyone (the previous behaviour).

    No per-artifact LLM re-analysis. Typical cost: 1 LLM call per
    regenerated client (+1 for the macro if cross_client_synthesis is on
    and we're regenerating all clients). Raises FileNotFoundError if
    the sidecars weren't persisted (older runs predating the interactive-
    mode plumbing)."""
    import json
    import os
    from services.agentic.reports import (
        generate_multi_client_reports,
        generate_final_report,
        create_report_package,
        persist_per_client_reports,
        save_report_content,
    )

    sidecar_dir = f"/data/downloads/{run_id}"
    summaries_path = f"{sidecar_dir}/artifact_summaries.json"
    raw_path = f"{sidecar_dir}/raw_results.json"
    if not os.path.exists(summaries_path) or not os.path.exists(raw_path):
        raise FileNotFoundError(
            "cached artifact_summaries.json / raw_results.json missing — "
            "this run pre-dates the interactive-mode plumbing. "
            "Use scope='full' instead (re-runs per-artifact analysis)."
        )

    with open(summaries_path) as f:
        artifact_summaries = json.load(f)
    with open(raw_path) as f:
        all_results = json.load(f)

    run = get_automation_run(run_id) or {}
    details = run.get('details') or {}
    if not isinstance(details, dict):
        details = {}
    client_ids = details.get('client_ids') or []
    hostnames = details.get('hostnames') or {}
    collection_minutes = int(details.get('collection_minutes') or 30)
    cross_client = bool(details.get('cross_client_synthesis'))
    blueprint_name = details.get('blueprint') or 'Unknown'
    report_types = details.get('report_types') or ['technical']

    blueprint_stub = {'name': blueprint_name}

    # Derive client_ids from raw_results if the workflow didn't stash them
    # (analyze-existing path on a hunt may not have recorded the resolved
    # client list in details).
    if not client_ids:
        derived = set()
        for rows in all_results.values():
            for row in rows or []:
                if isinstance(row, dict):
                    cid = row.get('_client_id')
                    if cid:
                        derived.add(cid)
        client_ids = sorted(derived)

    # Narrow the regen set to whatever the operator picked, but only if
    # it's a proper subset of the run's clients — otherwise treat as "all".
    targets = None
    if target_client_ids:
        wanted = [c for c in target_client_ids if c in client_ids]
        if wanted and len(wanted) < len(client_ids):
            targets = wanted

    if targets:
        target_names = ", ".join(hostnames.get(c, c) for c in targets)
        add_log_to_run(
            run_id,
            f"[Pipeline] Reports-only re-run — regenerating {len(targets)} "
            f"of {len(client_ids)} clients: {target_names}",
            "info",
        )
    else:
        add_log_to_run(run_id, "[Pipeline] Reports-only re-run — regenerating all clients", "info")
    # Mark "report generation" phase — gives the workflows tab progress
    # bar something to show after the initial 10% bump.
    update_run_status(run_id, 'running', progress=30)

    if len(client_ids) > 1:
        # Multi-client run.
        # If a target subset is requested, generate fresh reports for
        # those clients only (master_prompt in scope), then merge with
        # the previous ZIP's reports for the un-touched clients. This
        # is what makes single-client targeting cheap.
        regen_ids = targets if targets else client_ids
        # Skip the macro re-gen on a narrowed run — cross-client narrative
        # only makes sense when every client report reflects the same
        # operator context. Keep the existing macro from the prior ZIP.
        generate_macro_now = cross_client and not targets

        multi_reports = generate_multi_client_reports(
            run_id, blueprint_stub, regen_ids, collection_minutes,
            artifact_summaries, all_results, llm_config, None,
            hostnames=hostnames,
            generate_macro=generate_macro_now,
            master_prompt=master_prompt,
        )

        if targets:
            # Merge: targeted clients = freshly generated; others =
            # whatever the previous ZIP had. The macro is preserved from
            # the previous ZIP if it existed (reading from disk below).
            existing_per_client = _load_existing_client_reports_from_zip(run_id, hostnames)
            merged_per_client = dict(existing_per_client)
            merged_per_client.update(multi_reports.get('per_client') or {})
            # Carry the prior macro forward if there was one.
            prior_macro = None
            try:
                import zipfile
                zp = f"/data/downloads/{run_id}/reports.zip"
                if os.path.exists(zp):
                    with zipfile.ZipFile(zp, 'r') as zf:
                        if "00_ORGANIZATION_SUMMARY.md" in zf.namelist():
                            prior_macro = zf.read("00_ORGANIZATION_SUMMARY.md").decode('utf-8', errors='replace')
            except Exception as e:
                print(f"[AGENTIC] Could not preserve prior macro: {e}", flush=True)

            multi_reports = {
                'per_client': merged_per_client,
                'macro': prior_macro,
                'hostnames': {**(multi_reports.get('hostnames') or {}), **hostnames},
            }
            add_log_to_run(
                run_id,
                f"[Report] Merged {len(merged_per_client) - len(regen_ids)} "
                f"carried-over reports with {len(regen_ids)} regenerated",
                "info",
            )

        # Reports built, about to package + persist.
        update_run_status(run_id, 'running', progress=80)
        zip_path = create_report_package(run_id, multi_reports)
        add_log_to_run(run_id, f"[Report] Re-created ZIP package: {zip_path}", "info")

        # Refresh disk copy of per-client reports so the chat assistant
        # sees the new content on the next turn. Mirrors the call from
        # the main pipeline finish path.
        persist_per_client_reports(
            run_id,
            multi_reports.get('per_client') or {},
            multi_reports.get('hostnames') or hostnames or {},
        )
        update_run_status(run_id, 'running', progress=95)

        macro_md = multi_reports.get('macro')
        if not macro_md:
            hn_list = list((multi_reports.get('hostnames') or {}).values())
            macro_md = (
                "# Multi-client run — per-client reports only\n\n"
                "Cross-client synthesis is disabled for this re-run.\n\n"
                f"Per-host reports for {len(multi_reports.get('per_client', {}))} "
                f"client(s) are inside the ZIP.\n\n"
                f"Hosts: {', '.join(hn_list) if hn_list else '(unknown)'}.\n"
            )
        save_report_content(run_id, {'technical': macro_md})

        workflow = get_workflow(run_id)
        if workflow:
            wd = workflow.get('details') or {}
            wd['multi_client'] = True
            wd['report_zip'] = zip_path
            wd['client_count'] = len(client_ids)
            wd['hostnames'] = multi_reports.get('hostnames', {})
            workflow['details'] = wd
            save_workflow(workflow)
    else:
        # Single-client run: per-client target is meaningless.
        report_content = generate_final_report(
            run_id, blueprint_stub, client_ids, collection_minutes,
            artifact_summaries, all_results, llm_config, report_types, None,
            hostnames=hostnames,
            master_prompt=master_prompt,
        )
        save_report_content(run_id, report_content)


@agentic_bp.route('/api/agentic/run/<run_id>/rerun', methods=['POST'])
def rerun_agentic(run_id):
    """Re-run the agentic pipeline against the SAME run_id (no new
    workflow row). Body: {scope: "reports_only" | "full"}.

      - "reports_only": cheap; reads cached artifact summaries and
        regenerates only the per-client + macro reports with the master
        prompt in scope. ~1 LLM call per client. <60s typical.
      - "full": re-runs analyse_artifacts on the prior collection's raw
        data — every per-artifact LLM call repeats, this time with the
        master prompt as a system-prompt prefix. Expensive; use when the
        operator's corrections need to influence individual artifact
        analyses (not just the final synthesis)."""
    if not is_module_enabled('agentic'):
        return jsonify({"error": "Agentic module is not enabled."}), 400
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        if run.get('automation_type') != 'agentic':
            return jsonify({"error": "Re-run is only supported for agentic runs"}), 400
        if run.get('status') == 'running':
            return jsonify({"error": "Run is already in progress"}), 409

        data = request.get_json() or {}
        scope = (data.get('scope') or 'reports_only').strip()
        if scope not in ('reports_only', 'full'):
            return jsonify({"error": "scope must be 'reports_only' or 'full'"}), 400

        # Optional per-client targeting: regenerate the report for one
        # (or a few) specific hosts on a multi-client run, carrying the
        # rest forward from the previous ZIP. Only meaningful for
        # scope='reports_only'; ignored on a full re-analysis (which
        # re-runs per-artifact LLM calls that aren't per-client scoped).
        target_client_ids = data.get('client_ids') or None
        if target_client_ids is not None and not isinstance(target_client_ids, list):
            return jsonify({"error": "client_ids must be a list of strings"}), 400
        if target_client_ids:
            target_client_ids = [str(c) for c in target_client_ids if c]

        details = run.get('details') or {}
        if not isinstance(details, dict):
            details = {}

        llm_config = _load_llm_config()

        # Cheap pre-flight checks (no LLM, no DB writes) that must run
        # synchronously so the HTTP response can carry a meaningful 400.
        # The expensive parts (master-prompt synthesis + actual re-run)
        # happen in the worker thread below so the modal can close
        # instantly and the workflow row reflects progress like a
        # normal pipeline run.
        chat_messages = details.get('chat_messages') or []
        if not chat_messages:
            return jsonify({
                "error": "No chat history — send at least one message "
                         "describing what to correct or investigate."
            }), 400

        if scope == 'full':
            if not details.get('flow_id') and not details.get('hunt_id'):
                return jsonify({
                    "error": "No flow_id / hunt_id stored on this run — "
                             "cannot re-run the per-artifact analysis "
                             "without the source collection. Use "
                             "scope='reports_only' instead."
                }), 400

        # Bump version + workflow name. From here on, failures show up
        # in the workflow log (and the row flips to 'failed') rather
        # than as an HTTP error — the frontend has already moved on.
        new_version = _bump_run_version(run_id, run)
        add_log_to_run(
            run_id,
            f"[Pipeline] Interactive re-run (scope={scope}, v{new_version}) starting",
            "info",
        )
        # Flip to running immediately so the workflow row shows the
        # progress bar the moment the modal closes — without this the
        # row would briefly read 'completed' while the worker spins
        # up.
        update_run_status(run_id, 'running', progress=5)

        if scope == 'reports_only':
            # Background thread: synthesise the master prompt + do the
            # actual rerun. The HTTP response returns immediately.
            def _reports_only_worker():
                try:
                    add_log_to_run(run_id, "[Interactive] Synthesising master prompt from chat…", "info")
                    mp = agentic_chat.synthesize_master_prompt(run_id, llm_config)
                    mp = (mp or '').strip()
                    if not mp:
                        raise RuntimeError("synthesised master prompt was empty — add more detail to the chat")
                    _rerun_reports_only(run_id, mp, llm_config, target_client_ids=target_client_ids)
                    update_run_status(run_id, 'completed', progress=100, force=True)
                    add_log_to_run(run_id, f"[Pipeline] Reports-only re-run (v{new_version}) complete", "success")
                except FileNotFoundError as fe:
                    add_log_to_run(run_id, f"[Pipeline] Reports-only re-run aborted: {fe}", "warning")
                    update_run_status(run_id, run.get('status') or 'completed', progress=run.get('progress') or 100, force=True)
                except Exception as e:
                    import traceback as _tb
                    _tb.print_exc()
                    add_log_to_run(run_id, f"[Pipeline] Reports-only re-run failed: {e}", "error")
                    update_run_status(run_id, 'failed', error=str(e))

            thread = threading.Thread(target=_reports_only_worker, daemon=True)
            thread.start()
            return jsonify({
                "run_id": run_id,
                "scope": scope,
                "version": new_version,
                "status": "started",
            })

        # scope == 'full': dispatch through run_agentic_on_existing, which
        # already knows how to redo analysis on prior flow/hunt data. The
        # master prompt is picked up from workflow.details by the pipeline.
        # (Validation that flow_id/hunt_id exist happened up top.)
        flow_id = details.get('flow_id')
        hunt_id = details.get('hunt_id')

        from services.workflow_service import register_cancel_event
        cancel_event = register_cancel_event(run_id)

        # Wrap synthesise + dispatch in a worker so the HTTP response
        # returns instantly. The chat modal closes immediately, and
        # `run_agentic_on_existing` drives the progress bar from there.
        def _full_worker():
            try:
                add_log_to_run(run_id, "[Interactive] Synthesising master prompt from chat…", "info")
                mp = agentic_chat.synthesize_master_prompt(run_id, llm_config)
                mp = (mp or '').strip()
                if not mp:
                    raise RuntimeError("synthesised master prompt was empty — add more detail to the chat")
                # `run_agentic_on_existing` picks the master prompt up
                # from workflow.details, where synthesize_master_prompt
                # has already persisted it.
                run_agentic_on_existing(
                    run_id, flow_id, hunt_id, llm_config,
                    details.get('report_types') or ['technical'],
                    bool(details.get('anonymize_data')),
                    details.get('custom_patterns') or [],
                    bool(details.get('import_to_iris')),
                    details.get('iris_case_name') or '',
                    details.get('time_filter'),
                    details.get('min_severity') or 'informational',
                    details.get('external_files'),
                    cancel_event,
                    client_ids=details.get('client_ids') or None,
                )
            except Exception as e:
                import traceback as _tb
                _tb.print_exc()
                add_log_to_run(run_id, f"[Pipeline] Full re-analysis failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))

        thread = threading.Thread(target=_full_worker, daemon=True)
        thread.start()

        return jsonify({
            "run_id": run_id,
            "scope": scope,
            "version": new_version,
            "status": "started",
        })

    except Exception as e:
        print(f"[AGENTIC] Re-run error: {e}", flush=True)
        return jsonify({"error": str(e)}), 500
