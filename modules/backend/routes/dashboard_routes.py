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
        "error": run.get("error")
    }


@dashboard_bp.route('/api/dashboard/automations')
def get_all_automations():
    """Get all automation runs with their logs for the dashboard"""
    automation_runs = get_all_automation_runs()
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
