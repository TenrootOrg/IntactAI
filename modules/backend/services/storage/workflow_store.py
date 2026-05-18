#!/usr/bin/env python3
"""
Workflow Storage - CRUD operations for workflow runs
"""

import json
from typing import Dict, List, Any, Optional

from .base import get_connection, row_to_dict


_JSON_FIELDS = ['details', 'logs', 'phase_timings', 'llm_metrics', 'sigma_rule_tally']


def _json_or_default(value, default):
    """Serialize a JSON-bearing field, using default when value is None."""
    if value is None:
        return default
    return json.dumps(value)


def save_workflow(workflow_data: Dict[str, Any]) -> bool:
    """Save or update a workflow run"""
    try:
        conn = get_connection()
        conn.execute(
            """INSERT OR REPLACE INTO workflows
               (run_id, automation_type, name, details, status, progress, logs, phase, error,
                created_at, updated_at, phase_timings, llm_metrics, sigma_rule_tally, error_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (workflow_data.get('run_id'),
             workflow_data.get('automation_type'),
             workflow_data.get('name'),
             _json_or_default(workflow_data.get('details'), None),
             workflow_data.get('status'),
             workflow_data.get('progress', 0),
             _json_or_default(workflow_data.get('logs'), '[]'),
             workflow_data.get('phase'),
             workflow_data.get('error'),
             workflow_data.get('created_at'),
             workflow_data.get('updated_at'),
             _json_or_default(workflow_data.get('phase_timings'), None),
             _json_or_default(workflow_data.get('llm_metrics'), None),
             _json_or_default(workflow_data.get('sigma_rule_tally'), None),
             int(workflow_data.get('error_count') or 0))
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving workflow: {e}", flush=True)
        return False


def load_workflows() -> List[Dict[str, Any]]:
    """Load all workflows"""
    try:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM workflows").fetchall()
        return [row_to_dict(r, _JSON_FIELDS) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading workflows: {e}", flush=True)
        return []


def get_workflow(run_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific workflow by run_id"""
    try:
        conn = get_connection()
        row = conn.execute("SELECT * FROM workflows WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            return row_to_dict(row, _JSON_FIELDS)
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting workflow: {e}", flush=True)
        return None


def delete_workflow(run_id: str) -> bool:
    """Delete a workflow"""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM workflows WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting workflow: {e}", flush=True)
        return False
