#!/usr/bin/env python3
"""
Workflow Service - Centralized workflow and job tracking with SQLite + Elasticsearch
"""

import time
from datetime import datetime
from services.file_storage_service import (
    save_workflow,
    load_workflows,
    get_workflow as file_get_workflow
)

# Try to import Elasticsearch service
try:
    from services.elasticsearch_service import (
        get_all_workflow_runs as es_get_all_workflows,
        get_workflow_run as es_get_workflow,
        es_update_workflow_status
    )
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

# Enhanced job tracking with detailed logs
jobs = {}

# Initialize file storage on module load
print("[WORKFLOW] Using SQLite + Elasticsearch storage for workflows", flush=True)

def create_automation_run(automation_type, name, details=None):
    """Create a new automation run entry with logging"""
    run_id = f"{automation_type}_{int(time.time() * 1000)}"

    # Create workflow run structure
    workflow_data = {
        "run_id": run_id,
        "automation_type": automation_type,
        "name": name,
        "details": details or {},
        "status": "pending",
        "progress": 0,
        "logs": [],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }

    # Save to file
    save_workflow(workflow_data)

    return run_id

def add_log_to_run(run_id, log_message, log_level="info"):
    """Add a log entry to an automation run"""
    workflow = file_get_workflow(run_id)
    if workflow:
        if "logs" not in workflow:
            workflow["logs"] = []

        workflow["logs"].append({
            "timestamp": datetime.now().isoformat(),
            "level": log_level,
            "message": log_message
        })
        workflow["updated_at"] = datetime.now().isoformat()

        save_workflow(workflow)

def update_run_status(run_id, status, progress=None, error=None, details=None):
    """Update automation run status and optionally merge additional details"""
    workflow = file_get_workflow(run_id)
    if workflow:
        workflow["status"] = status
        if progress is not None:
            workflow["progress"] = progress
        if error:
            workflow["error"] = error
        if details:
            # Merge new details with existing details
            existing_details = workflow.get("details", {})
            existing_details.update(details)
            workflow["details"] = existing_details
        workflow["updated_at"] = datetime.now().isoformat()

        save_workflow(workflow)

def cleanup_orphan_workflows():
    """Mark workflows as failed if they've been running for more than 10 hours"""
    now = datetime.now()
    max_runtime_hours = 10

    # Clean up SQLite workflows
    sqlite_workflows = load_workflows()
    for workflow in sqlite_workflows:
        if workflow.get('status') in ['running', 'pending']:
            created_at = workflow.get('created_at', '')
            if created_at:
                try:
                    start_time = datetime.fromisoformat(created_at)
                    elapsed_hours = (now - start_time).total_seconds() / 3600

                    if elapsed_hours > max_runtime_hours:
                        workflow['status'] = 'failed'
                        workflow['error'] = f'Workflow timed out after {elapsed_hours:.1f} hours (max: {max_runtime_hours}h)'
                        workflow['updated_at'] = now.isoformat()

                        if 'logs' not in workflow:
                            workflow['logs'] = []
                        workflow['logs'].append({
                            'timestamp': now.isoformat(),
                            'level': 'error',
                            'message': f'Workflow automatically marked as failed - exceeded {max_runtime_hours} hour timeout'
                        })

                        save_workflow(workflow)
                        print(f"[WORKFLOW] Marked SQLite orphan workflow as failed: {workflow.get('run_id')}", flush=True)
                except Exception as e:
                    print(f"[WORKFLOW] Error checking SQLite workflow age: {e}", flush=True)

    # Clean up Elasticsearch workflows
    if ES_AVAILABLE:
        try:
            es_workflows = es_get_all_workflows(size=200)
            for workflow in es_workflows:
                if workflow.get('status') in ['running', 'pending']:
                    started_at = workflow.get('started_at', workflow.get('created_at', ''))
                    if started_at:
                        try:
                            start_time = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                            elapsed_hours = (now - start_time.replace(tzinfo=None)).total_seconds() / 3600

                            if elapsed_hours > max_runtime_hours:
                                run_id = workflow.get('run_id', workflow.get('id'))
                                es_update_workflow_status(
                                    run_id,
                                    status='failed',
                                    error=f'Workflow timed out after {elapsed_hours:.1f} hours (max: {max_runtime_hours}h)'
                                )
                                print(f"[WORKFLOW] Marked ES orphan workflow as failed: {run_id}", flush=True)
                        except Exception as e:
                            print(f"[WORKFLOW] Error checking ES workflow age: {e}", flush=True)
        except Exception as e:
            print(f"[WORKFLOW] Error cleaning ES workflows: {e}", flush=True)


def get_all_automation_runs():
    """Get all automation runs from SQLite + Elasticsearch (with automatic orphan cleanup)"""
    # Clean up orphan workflows first
    cleanup_orphan_workflows()

    # Get SQLite workflows
    sqlite_workflows = load_workflows()
    sqlite_ids = {w.get('run_id') for w in sqlite_workflows}

    # Get Elasticsearch workflows and merge (avoiding duplicates)
    all_workflows = list(sqlite_workflows)

    if ES_AVAILABLE:
        try:
            es_workflows = es_get_all_workflows(size=200)
            for es_wf in es_workflows:
                es_id = es_wf.get('run_id', es_wf.get('id'))
                if es_id and es_id not in sqlite_ids:
                    # Normalize field names
                    all_workflows.append({
                        'run_id': es_id,
                        'automation_type': es_wf.get('type', es_wf.get('automation_type', 'unknown')),
                        'name': es_wf.get('name', 'Unknown'),
                        'status': es_wf.get('status', 'unknown'),
                        'progress': es_wf.get('progress', 0),
                        'created_at': es_wf.get('started_at', es_wf.get('created_at', '')),
                        'updated_at': es_wf.get('updated_at', ''),
                        'logs': es_wf.get('logs', []),
                        'details': es_wf.get('details', {}),
                        'error': es_wf.get('error')
                    })
        except Exception as e:
            print(f"[WORKFLOW] Error loading ES workflows: {e}", flush=True)

    # Sort by created_at descending (newest first)
    all_workflows.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return all_workflows

def get_automation_run(run_id):
    """Get a specific automation run by ID (checks SQLite first, then Elasticsearch)"""
    # Try SQLite first
    workflow = file_get_workflow(run_id)
    if workflow:
        return workflow

    # Try Elasticsearch
    if ES_AVAILABLE:
        try:
            es_wf = es_get_workflow(run_id)
            if es_wf:
                return {
                    'run_id': es_wf.get('run_id', es_wf.get('id', run_id)),
                    'automation_type': es_wf.get('type', es_wf.get('automation_type', 'unknown')),
                    'name': es_wf.get('name', 'Unknown'),
                    'status': es_wf.get('status', 'unknown'),
                    'progress': es_wf.get('progress', 0),
                    'created_at': es_wf.get('started_at', es_wf.get('created_at', '')),
                    'updated_at': es_wf.get('updated_at', ''),
                    'logs': es_wf.get('logs', []),
                    'details': es_wf.get('details', {}),
                    'error': es_wf.get('error')
                }
        except Exception as e:
            print(f"[WORKFLOW] Error getting ES workflow {run_id}: {e}", flush=True)

    return None

def get_jobs():
    """Get all jobs"""
    return jobs

def add_job(flow_id, job_data):
    """Add a new job to tracking"""
    jobs[flow_id] = job_data

def get_job(flow_id):
    """Get a specific job"""
    return jobs.get(flow_id)

def update_job(flow_id, updates):
    """Update a job with new data"""
    if flow_id in jobs:
        jobs[flow_id].update(updates)
