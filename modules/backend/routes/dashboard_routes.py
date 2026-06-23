#!/usr/bin/env python3
"""
Dashboard Routes - Dashboard/workflow endpoints
"""

from flask import Blueprint, jsonify

from services import (
    get_all_automation_runs,
    get_automation_run
)

dashboard_bp = Blueprint('dashboard', __name__)


def _transform_run(run):
    """Transform backend run data to frontend format."""
    if not run:
        return None
    return {
        "id": run.get("run_id", run.get("id")),
        "type": run.get("automation_type", run.get("type", "system")),
        "name": run.get("name", "Unknown"),
        "status": run.get("status", "unknown"),
        "progress": run.get("progress", 0),
        "started_at": run.get("created_at", run.get("started_at")),
        "updated_at": run.get("updated_at"),
        "logs": run.get("logs", []),
        "details": run.get("details", {}),
        "error": run.get("error"),
        # Auto-incremented by add_log_to_run() whenever level='error'.
        # Drives the small "N errors" badge in the Workflows tab so
        # operators can quickly see runs that finished with errors —
        # even when status='completed' was forced through with force=True.
        "error_count": int(run.get("error_count") or 0),
        # Observability fields surfaced for the dashboard. Each is a JSON
        # blob persisted by the pipeline; the frontend renders these into
        # per-stage timing bar, LLM cost summary, and per-rule detection tally.
        "phase_timings": run.get("phase_timings"),
        "llm_metrics": run.get("llm_metrics"),
        "sigma_rule_tally": run.get("sigma_rule_tally"),
    }


@dashboard_bp.route('/api/dashboard/automations')
def get_all_automations():
    """Get automation runs for the dashboard, STRICTLY scoped to the active
    workspace (the X-Case-Id header).

    Each workspace shows only its own runs. System/admin runs
    (upgrade/maintenance/purge/support-bundle/settings/…) always run as the
    built-in System workspace, so they appear only there — switch to the
    System workspace then Workflows to see them. They must NOT leak into an
    investigation workspace like Default."""
    from flask import g
    automation_runs = get_all_automation_runs()
    case_id = getattr(g, "case_id", None)
    if case_id:
        automation_runs = [r for r in automation_runs if r.get("case_id") == case_id]
    transformed = [_transform_run(run) for run in automation_runs]
    return jsonify({
        "runs": transformed,
        "total": len(transformed)
    })

@dashboard_bp.route('/api/dashboard/automation/<run_id>')
def get_automation_details(run_id):
    """Get detailed information about a specific automation run"""
    run = get_automation_run(run_id)
    if run:
        return jsonify(_transform_run(run))

    return jsonify({"error": f"Automation run {run_id} not found"}), 404

@dashboard_bp.route('/api/dashboard/automation/<run_id>/stop', methods=['POST'])
def stop_automation(run_id):
    """Stop a running workflow and clean up its resources"""
    from services.workflow_service import request_stop
    run = get_automation_run(run_id)
    if not run:
        return jsonify({"error": f"Automation run {run_id} not found"}), 404
    if run.get('status') not in ('running', 'pending'):
        return jsonify({"error": f"Cannot stop workflow in '{run.get('status')}' state"}), 400

    request_stop(run_id)
    return jsonify({"status": "cancelled", "run_id": run_id})


@dashboard_bp.route('/api/dashboard/automation/<run_id>/logs')
def get_automation_logs(run_id):
    """Get logs for a specific automation run"""
    run = get_automation_run(run_id)
    if run:
        return jsonify({
            "id": run_id,
            "logs": run["logs"]
        })

    return jsonify({"error": f"Automation run {run_id} not found"}), 404
