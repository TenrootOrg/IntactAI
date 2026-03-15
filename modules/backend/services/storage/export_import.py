#!/usr/bin/env python3
"""
Export/Import - Database export and import functionality
"""

import json
from datetime import datetime
from typing import Dict, Any

from .base import get_connection, row_to_dict
from .config_store import save_frontend_config, load_frontend_config


def export_db() -> Dict[str, Any]:
    """Export all tables to a JSON-serializable dict"""
    conn = get_connection()
    data = {
        "exported_at": datetime.now().isoformat(),
        "workflows": [],
        "blueprints_velociraptor": [],
        "blueprints_agentic": [],
        "offline_collectors": [],
        "reports": [],
        "frontend_config": {}
    }

    # Workflows
    for row in conn.execute("SELECT * FROM workflows").fetchall():
        data["workflows"].append(row_to_dict(row, ['details', 'logs']))

    # Blueprints
    for row in conn.execute("SELECT * FROM blueprints_velociraptor").fetchall():
        data["blueprints_velociraptor"].append(row_to_dict(row, ['artifacts', 'settings']))

    for row in conn.execute("SELECT * FROM blueprints_agentic").fetchall():
        data["blueprints_agentic"].append(row_to_dict(row, ['artifacts', 'settings']))

    # Offline collectors
    for row in conn.execute("SELECT * FROM offline_collectors").fetchall():
        data["offline_collectors"].append(row_to_dict(row, ['artifacts', 'parameters']))

    # Reports
    for row in conn.execute("SELECT * FROM reports").fetchall():
        data["reports"].append(dict(row))

    # Frontend config
    data["frontend_config"] = load_frontend_config()

    return data


def import_db(data: Dict[str, Any]) -> bool:
    """Import data from a JSON dict (from export_db) into the database"""
    try:
        conn = get_connection()

        # Import workflows
        for wf in data.get("workflows", []):
            conn.execute(
                """INSERT OR REPLACE INTO workflows
                   (run_id, automation_type, name, details, status, progress, logs, phase, error, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (wf.get('run_id'), wf.get('automation_type'), wf.get('name'),
                 json.dumps(wf.get('details')) if isinstance(wf.get('details'), (dict, list)) else wf.get('details'),
                 wf.get('status'), wf.get('progress', 0),
                 json.dumps(wf.get('logs')) if isinstance(wf.get('logs'), list) else wf.get('logs', '[]'),
                 wf.get('phase'), wf.get('error'),
                 wf.get('created_at'), wf.get('updated_at'))
            )

        # Import velociraptor blueprints
        for bp in data.get("blueprints_velociraptor", []):
            conn.execute(
                """INSERT OR REPLACE INTO blueprints_velociraptor
                   (id, name, description, is_default, artifacts, settings, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (bp.get('id'), bp.get('name'), bp.get('description'),
                 1 if bp.get('is_default') else 0,
                 json.dumps(bp.get('artifacts')) if isinstance(bp.get('artifacts'), list) else bp.get('artifacts', '[]'),
                 json.dumps(bp.get('settings')) if isinstance(bp.get('settings'), dict) else bp.get('settings', '{}'),
                 bp.get('created_at'), bp.get('updated_at'))
            )

        # Import agentic blueprints
        for bp in data.get("blueprints_agentic", []):
            conn.execute(
                """INSERT OR REPLACE INTO blueprints_agentic
                   (id, name, description, is_default, artifacts, settings, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (bp.get('id'), bp.get('name'), bp.get('description'),
                 1 if bp.get('is_default') else 0,
                 json.dumps(bp.get('artifacts')) if isinstance(bp.get('artifacts'), list) else bp.get('artifacts', '[]'),
                 json.dumps(bp.get('settings')) if isinstance(bp.get('settings'), dict) else bp.get('settings', '{}'),
                 bp.get('created_at'), bp.get('updated_at'))
            )

        # Import offline collectors
        for cfg in data.get("offline_collectors", []):
            conn.execute(
                """INSERT OR REPLACE INTO offline_collectors
                   (config_id, config_name, description, artifacts, parameters, is_template, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (cfg.get('config_id'), cfg.get('config_name'), cfg.get('description'),
                 json.dumps(cfg.get('artifacts')) if isinstance(cfg.get('artifacts'), list) else cfg.get('artifacts', '[]'),
                 json.dumps(cfg.get('parameters')) if isinstance(cfg.get('parameters'), dict) else cfg.get('parameters', '{}'),
                 1 if cfg.get('is_template') else 0,
                 cfg.get('created_at'), cfg.get('updated_at'))
            )

        # Import reports
        for report in data.get("reports", []):
            conn.execute(
                "INSERT OR REPLACE INTO reports (run_id, content, created_at) VALUES (?, ?, ?)",
                (report.get('run_id'), report.get('content'), report.get('created_at'))
            )

        # Import frontend config
        fc = data.get("frontend_config", {})
        if fc:
            save_frontend_config(fc)

        conn.commit()
        print(f"[STORAGE] Database import complete", flush=True)
        return True
    except Exception as e:
        print(f"[STORAGE] Error importing database: {e}", flush=True)
        return False
