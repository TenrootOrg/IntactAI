#!/usr/bin/env python3
"""
Scheduler Routes - API endpoints for managing scheduled blueprint runs.

Note: All scheduled times are in UTC (Coordinated Universal Time).
"""

from datetime import datetime
from flask import Blueprint, jsonify, request

from services.scheduler_service import (
    create_scheduled_job,
    get_scheduled_job,
    list_scheduled_jobs,
    update_scheduled_job,
    delete_scheduled_job,
    toggle_scheduled_job,
    run_job_now
)

scheduler_bp = Blueprint('scheduler', __name__)


@scheduler_bp.route('/api/scheduler/jobs', methods=['GET'])
def get_jobs():
    """List all scheduled jobs."""
    try:
        jobs = list_scheduled_jobs()
        now_utc = datetime.utcnow()
        return jsonify({
            "jobs": jobs,
            "count": len(jobs),
            "timezone": "UTC",
            "current_time_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "All scheduled times are in UTC (Coordinated Universal Time)"
        })
    except Exception as e:
        print(f"[SCHEDULER] Error listing jobs: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs', methods=['POST'])
def create_job():
    """Create a new scheduled job."""
    try:
        data = request.get_json()

        # Required fields
        name = data.get('name')
        blueprint_id = data.get('blueprint_id')
        blueprint_type = data.get('blueprint_type', 'velociraptor')
        interval_value = data.get('interval_value', 1)

        if not name:
            return jsonify({"error": "name is required"}), 400
        if not blueprint_id:
            return jsonify({"error": "blueprint_id is required"}), 400

        # Validate interval_value
        if interval_value < 1:
            return jsonify({"error": "interval_value must be at least 1"}), 400

        # Optional fields
        # SHAPE VALIDATION (Mythos #2 extended): scheduled agentic jobs
        # eventually call into services/agentic/collectors.py with
        # these client IDs in the same VQL-concat sites the manual
        # agentic route uses. Reject malformed shapes at schedule time
        # so a bad schedule doesn't sit around and fire injection on
        # every cron tick.
        from services.vql_safety import validate_client_ids_list
        client_ids, _cid_err = validate_client_ids_list(data.get('client_ids'))
        if _cid_err:
            return jsonify({"error": _cid_err}), 400
        description = data.get('description', '')
        report_types = data.get('report_types', ['technical'])
        anonymize_data = data.get('anonymize_data', False)
        custom_patterns = data.get('custom_patterns', [])
        run_time = data.get('run_time', '02:00')

        # Time filter options (for agentic jobs)
        time_filter_enabled = data.get('time_filter_enabled', False)
        time_filter_mode = data.get('time_filter_mode', 'relative')
        time_filter_relative_range = data.get('time_filter_relative_range', '7d')
        time_filter_start = data.get('time_filter_start')
        time_filter_end = data.get('time_filter_end')

        # Validate run_time format
        try:
            parts = run_time.split(':')
            if len(parts) != 2:
                raise ValueError()
            hour, minute = int(parts[0]), int(parts[1])
            if hour < 0 or hour > 23 or minute < 0 or minute > 59:
                raise ValueError()
        except (ValueError, AttributeError):
            return jsonify({"error": "Invalid run_time format. Use HH:MM format."}), 400

        job = create_scheduled_job(
            name=name,
            blueprint_id=blueprint_id,
            blueprint_type=blueprint_type,
            interval_value=interval_value,
            run_time=run_time,
            client_ids=client_ids,
            report_types=report_types,
            anonymize_data=anonymize_data,
            custom_patterns=custom_patterns,
            description=description,
            time_filter_enabled=time_filter_enabled,
            time_filter_mode=time_filter_mode,
            time_filter_relative_range=time_filter_relative_range,
            time_filter_start=time_filter_start,
            time_filter_end=time_filter_end
        )

        return jsonify(job), 201

    except Exception as e:
        print(f"[SCHEDULER] Error creating job: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs/<job_id>', methods=['GET'])
def get_job(job_id):
    """Get a specific scheduled job."""
    try:
        job = get_scheduled_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs/<job_id>', methods=['PUT'])
def update_job(job_id):
    """Update a scheduled job."""
    try:
        data = request.get_json()

        job = update_scheduled_job(job_id, data)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        return jsonify(job)

    except Exception as e:
        print(f"[SCHEDULER] Error updating job: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    """Delete a scheduled job."""
    try:
        success = delete_scheduled_job(job_id)
        if not success:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({"success": True, "message": "Job deleted"})
    except Exception as e:
        print(f"[SCHEDULER] Error deleting job: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs/<job_id>/toggle', methods=['POST'])
def toggle_job(job_id):
    """Enable or disable a scheduled job."""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)

        job = toggle_scheduled_job(job_id, enabled)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        return jsonify(job)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scheduler_bp.route('/api/scheduler/jobs/<job_id>/run', methods=['POST'])
def trigger_job(job_id):
    """Manually trigger a job to run now."""
    try:
        success = run_job_now(job_id)
        if not success:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({"success": True, "message": "Job triggered"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
