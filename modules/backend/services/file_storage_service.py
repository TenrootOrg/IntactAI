#!/usr/bin/env python3
"""
File Storage Service - SQLite-based persistence for workflows, blueprints, configs, and reports
"""

import json
import os
import sqlite3
import threading
import glob as glob_module
from datetime import datetime
from typing import Dict, List, Any, Optional

# Storage
STORAGE_BASE = "/app/data"
DB_PATH = os.path.join(STORAGE_BASE, "mssp.db")
REPORTS_DIR = os.path.join(STORAGE_BASE, "reports")

# Legacy JSON file paths (for migration)
WORKFLOWS_FILE = os.path.join(STORAGE_BASE, "workflows.json")
OFFLINE_COLLECTORS_FILE = os.path.join(STORAGE_BASE, "offline_collectors.json")
BLUEPRINTS_VELOCIRAPTOR_FILE = os.path.join(STORAGE_BASE, "blueprints_velociraptor.json")
BLUEPRINTS_AGENTIC_FILE = os.path.join(STORAGE_BASE, "blueprints_agentic.json")
FRONTEND_CONFIG_FILE = os.path.join(STORAGE_BASE, "frontend_config.json")

# Thread-local storage for connections
_local = threading.local()


def _get_connection() -> sqlite3.Connection:
    """Get a thread-local SQLite connection with WAL mode.

    Note: This returns a cached connection. Callers should NOT call conn.close()
    as it would close the cached connection for all future callers.
    """
    need_new_connection = False

    if not hasattr(_local, 'connection') or _local.connection is None:
        need_new_connection = True
    else:
        # Check if the cached connection is still valid (not closed)
        try:
            _local.connection.execute("SELECT 1")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            # Connection is closed or invalid
            need_new_connection = True
            _local.connection = None

    if need_new_connection:
        os.makedirs(STORAGE_BASE, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.connection = conn

    return _local.connection


def _row_to_dict(row: sqlite3.Row, json_fields: list) -> Dict[str, Any]:
    """Convert a sqlite3.Row to a dict, parsing JSON string fields"""
    d = dict(row)
    for field in json_fields:
        if field in d and d[field] is not None:
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    # Convert is_default/is_template from int to bool
    if 'is_default' in d:
        d['is_default'] = bool(d['is_default'])
    if 'is_template' in d:
        d['is_template'] = bool(d['is_template'])
    return d


def _create_tables():
    """Create all tables if they don't exist"""
    conn = _get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS workflows (
            run_id TEXT PRIMARY KEY,
            automation_type TEXT,
            name TEXT,
            details TEXT,
            status TEXT,
            progress INTEGER DEFAULT 0,
            logs TEXT,
            phase TEXT,
            error TEXT,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS blueprints_velociraptor (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            is_default INTEGER DEFAULT 0,
            artifacts TEXT,
            settings TEXT,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS blueprints_agentic (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            is_default INTEGER DEFAULT 0,
            artifacts TEXT,
            settings TEXT,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS blueprints_timesketch (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            is_default INTEGER DEFAULT 0,
            settings TEXT,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS offline_collectors (
            config_id TEXT PRIMARY KEY,
            config_name TEXT,
            description TEXT,
            artifacts TEXT,
            parameters TEXT,
            is_template INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS reports (
            run_id TEXT PRIMARY KEY,
            content TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS frontend_config (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
    """)
    conn.commit()


# ============================================================================
# Migration from JSON files
# ============================================================================

def _migrate_from_json():
    """One-time migration from JSON files to SQLite"""
    conn = _get_connection()
    migrated_any = False

    # Migrate workflows.json
    if os.path.exists(WORKFLOWS_FILE) and not os.path.exists(WORKFLOWS_FILE + ".migrated"):
        try:
            with open(WORKFLOWS_FILE, 'r') as f:
                workflows = json.load(f)
            for wf in workflows:
                conn.execute(
                    """INSERT OR IGNORE INTO workflows
                       (run_id, automation_type, name, details, status, progress, logs, phase, error, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (wf.get('run_id'), wf.get('automation_type'), wf.get('name'),
                     json.dumps(wf.get('details')) if wf.get('details') else None,
                     wf.get('status'), wf.get('progress', 0),
                     json.dumps(wf.get('logs')) if wf.get('logs') else '[]',
                     wf.get('phase'), wf.get('error'),
                     wf.get('created_at'), wf.get('updated_at'))
                )
            conn.commit()
            os.rename(WORKFLOWS_FILE, WORKFLOWS_FILE + ".migrated")
            print(f"[STORAGE] Migrated {len(workflows)} workflows from JSON", flush=True)
            migrated_any = True
        except Exception as e:
            print(f"[STORAGE] Error migrating workflows: {e}", flush=True)

    # Migrate blueprints_velociraptor.json
    if os.path.exists(BLUEPRINTS_VELOCIRAPTOR_FILE) and not os.path.exists(BLUEPRINTS_VELOCIRAPTOR_FILE + ".migrated"):
        try:
            with open(BLUEPRINTS_VELOCIRAPTOR_FILE, 'r') as f:
                blueprints = json.load(f)
            for bp in blueprints:
                conn.execute(
                    """INSERT OR IGNORE INTO blueprints_velociraptor
                       (id, name, description, is_default, artifacts, settings, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (bp.get('id'), bp.get('name'), bp.get('description'),
                     1 if bp.get('is_default') else 0,
                     json.dumps(bp.get('artifacts')) if bp.get('artifacts') else '[]',
                     json.dumps(bp.get('settings')) if bp.get('settings') else '{}',
                     bp.get('created_at'), bp.get('updated_at'))
                )
            conn.commit()
            os.rename(BLUEPRINTS_VELOCIRAPTOR_FILE, BLUEPRINTS_VELOCIRAPTOR_FILE + ".migrated")
            print(f"[STORAGE] Migrated {len(blueprints)} velociraptor blueprints from JSON", flush=True)
            migrated_any = True
        except Exception as e:
            print(f"[STORAGE] Error migrating velociraptor blueprints: {e}", flush=True)

    # Migrate blueprints_agentic.json
    if os.path.exists(BLUEPRINTS_AGENTIC_FILE) and not os.path.exists(BLUEPRINTS_AGENTIC_FILE + ".migrated"):
        try:
            with open(BLUEPRINTS_AGENTIC_FILE, 'r') as f:
                blueprints = json.load(f)
            for bp in blueprints:
                conn.execute(
                    """INSERT OR IGNORE INTO blueprints_agentic
                       (id, name, description, is_default, artifacts, settings, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (bp.get('id'), bp.get('name'), bp.get('description'),
                     1 if bp.get('is_default') else 0,
                     json.dumps(bp.get('artifacts')) if bp.get('artifacts') else '[]',
                     json.dumps(bp.get('settings')) if bp.get('settings') else '{}',
                     bp.get('created_at'), bp.get('updated_at'))
                )
            conn.commit()
            os.rename(BLUEPRINTS_AGENTIC_FILE, BLUEPRINTS_AGENTIC_FILE + ".migrated")
            print(f"[STORAGE] Migrated {len(blueprints)} agentic blueprints from JSON", flush=True)
            migrated_any = True
        except Exception as e:
            print(f"[STORAGE] Error migrating agentic blueprints: {e}", flush=True)

    # Migrate offline_collectors.json
    if os.path.exists(OFFLINE_COLLECTORS_FILE) and not os.path.exists(OFFLINE_COLLECTORS_FILE + ".migrated"):
        try:
            with open(OFFLINE_COLLECTORS_FILE, 'r') as f:
                configs = json.load(f)
            for cfg in configs:
                conn.execute(
                    """INSERT OR IGNORE INTO offline_collectors
                       (config_id, config_name, description, artifacts, parameters, is_template, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (cfg.get('config_id'), cfg.get('config_name'), cfg.get('description'),
                     json.dumps(cfg.get('artifacts')) if cfg.get('artifacts') else '[]',
                     json.dumps(cfg.get('parameters')) if cfg.get('parameters') else '{}',
                     1 if cfg.get('is_template') else 0,
                     cfg.get('created_at'), cfg.get('updated_at'))
                )
            conn.commit()
            os.rename(OFFLINE_COLLECTORS_FILE, OFFLINE_COLLECTORS_FILE + ".migrated")
            print(f"[STORAGE] Migrated {len(configs)} offline collectors from JSON", flush=True)
            migrated_any = True
        except Exception as e:
            print(f"[STORAGE] Error migrating offline collectors: {e}", flush=True)

    # Migrate frontend_config.json
    if os.path.exists(FRONTEND_CONFIG_FILE) and not os.path.exists(FRONTEND_CONFIG_FILE + ".migrated"):
        try:
            with open(FRONTEND_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            now = datetime.now().isoformat()
            for key, value in config.items():
                conn.execute(
                    "INSERT OR IGNORE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), now)
                )
            conn.commit()
            os.rename(FRONTEND_CONFIG_FILE, FRONTEND_CONFIG_FILE + ".migrated")
            print(f"[STORAGE] Migrated frontend config from JSON", flush=True)
            migrated_any = True
        except Exception as e:
            print(f"[STORAGE] Error migrating frontend config: {e}", flush=True)

    # Migrate report .md files
    if os.path.exists(REPORTS_DIR):
        md_files = glob_module.glob(os.path.join(REPORTS_DIR, "agentic_*.md"))
        if md_files:
            migrated_reports = 0
            for md_path in md_files:
                try:
                    filename = os.path.basename(md_path)
                    # Extract run_id from "agentic_{run_id}.md"
                    run_id = filename.replace("agentic_", "").replace(".md", "")
                    with open(md_path, 'r') as f:
                        content = f.read()
                    mtime = datetime.fromtimestamp(os.path.getmtime(md_path)).isoformat()
                    conn.execute(
                        "INSERT OR IGNORE INTO reports (run_id, content, created_at) VALUES (?, ?, ?)",
                        (run_id, content, mtime)
                    )
                    migrated_reports += 1
                except Exception as e:
                    print(f"[STORAGE] Error migrating report {md_path}: {e}", flush=True)
            conn.commit()
            if migrated_reports > 0:
                # Rename reports dir to mark as migrated
                migrated_dir = REPORTS_DIR + ".migrated"
                if not os.path.exists(migrated_dir):
                    os.rename(REPORTS_DIR, migrated_dir)
                print(f"[STORAGE] Migrated {migrated_reports} reports from files", flush=True)
                migrated_any = True

    if migrated_any:
        print("[STORAGE] JSON to SQLite migration complete", flush=True)


# ============================================================================
# Init
# ============================================================================

def init_storage():
    """Initialize SQLite database, create tables, and migrate from JSON if needed"""
    try:
        os.makedirs(STORAGE_BASE, exist_ok=True)
        _create_tables()
        _migrate_from_json()
        return True
    except Exception as e:
        print(f"[STORAGE] Failed to initialize: {e}", flush=True)
        return False


# ============================================================================
# Workflow Storage
# ============================================================================

def save_workflow(workflow_data: Dict[str, Any]) -> bool:
    """Save or update a workflow run"""
    try:
        conn = _get_connection()
        conn.execute(
            """INSERT OR REPLACE INTO workflows
               (run_id, automation_type, name, details, status, progress, logs, phase, error, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (workflow_data.get('run_id'),
             workflow_data.get('automation_type'),
             workflow_data.get('name'),
             json.dumps(workflow_data.get('details')) if workflow_data.get('details') is not None else None,
             workflow_data.get('status'),
             workflow_data.get('progress', 0),
             json.dumps(workflow_data.get('logs')) if workflow_data.get('logs') is not None else '[]',
             workflow_data.get('phase'),
             workflow_data.get('error'),
             workflow_data.get('created_at'),
             workflow_data.get('updated_at'))
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving workflow: {e}", flush=True)
        return False


def load_workflows() -> List[Dict[str, Any]]:
    """Load all workflows"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM workflows").fetchall()
        return [_row_to_dict(r, ['details', 'logs']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading workflows: {e}", flush=True)
        return []


def get_workflow(run_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific workflow by run_id"""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM workflows WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            return _row_to_dict(row, ['details', 'logs'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting workflow: {e}", flush=True)
        return None


def delete_workflow(run_id: str) -> bool:
    """Delete a workflow"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM workflows WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting workflow: {e}", flush=True)
        return False


# ============================================================================
# Offline Collector Configuration Storage
# ============================================================================

def save_offline_collector_config(config_data: Dict[str, Any]) -> bool:
    """Save or update an offline collector configuration"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()

        # Check if existing
        existing = conn.execute(
            "SELECT config_id FROM offline_collectors WHERE config_id = ?",
            (config_data.get('config_id'),)
        ).fetchone()

        created_at = config_data.get('created_at', now) if not existing else \
            conn.execute("SELECT created_at FROM offline_collectors WHERE config_id = ?",
                         (config_data.get('config_id'),)).fetchone()['created_at']

        conn.execute(
            """INSERT OR REPLACE INTO offline_collectors
               (config_id, config_name, description, artifacts, parameters, is_template, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (config_data.get('config_id'),
             config_data.get('config_name'),
             config_data.get('description'),
             json.dumps(config_data.get('artifacts')) if config_data.get('artifacts') is not None else '[]',
             json.dumps(config_data.get('parameters')) if config_data.get('parameters') is not None else '{}',
             1 if config_data.get('is_template') else 0,
             created_at,
             now)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving offline collector config: {e}", flush=True)
        return False


def load_offline_collector_configs() -> List[Dict[str, Any]]:
    """Load all offline collector configurations"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM offline_collectors").fetchall()
        return [_row_to_dict(r, ['artifacts', 'parameters']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading offline collector configs: {e}", flush=True)
        return []


def get_offline_collector_config(config_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific offline collector configuration by config_id"""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM offline_collectors WHERE config_id = ?", (config_id,)).fetchone()
        if row:
            d = _row_to_dict(row, ['artifacts', 'parameters'])
            d['id'] = d['config_id']  # Add 'id' field for compatibility
            return d
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting offline collector config: {e}", flush=True)
        return None


def delete_offline_collector_config(config_id: str) -> bool:
    """Delete an offline collector configuration"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM offline_collectors WHERE config_id = ?", (config_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting offline collector config: {e}", flush=True)
        return False


# ============================================================================
# Velociraptor Blueprint Storage
# ============================================================================

def save_velociraptor_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    """Save or update a velociraptor blueprint"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()

        existing = conn.execute(
            "SELECT id FROM blueprints_velociraptor WHERE id = ?",
            (blueprint_data.get('id'),)
        ).fetchone()

        created_at = blueprint_data.get('created_at', now) if not existing else \
            conn.execute("SELECT created_at FROM blueprints_velociraptor WHERE id = ?",
                         (blueprint_data.get('id'),)).fetchone()['created_at']

        conn.execute(
            """INSERT OR REPLACE INTO blueprints_velociraptor
               (id, name, description, is_default, artifacts, settings, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (blueprint_data.get('id'),
             blueprint_data.get('name'),
             blueprint_data.get('description'),
             1 if blueprint_data.get('is_default') else 0,
             json.dumps(blueprint_data.get('artifacts')) if blueprint_data.get('artifacts') is not None else '[]',
             json.dumps(blueprint_data.get('settings')) if blueprint_data.get('settings') is not None else '{}',
             created_at,
             now)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving velociraptor blueprint: {e}", flush=True)
        return False


def load_velociraptor_blueprints() -> List[Dict[str, Any]]:
    """Load all velociraptor blueprints"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM blueprints_velociraptor").fetchall()
        return [_row_to_dict(r, ['artifacts', 'settings']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading velociraptor blueprints: {e}", flush=True)
        return []


def get_velociraptor_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific velociraptor blueprint by id"""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM blueprints_velociraptor WHERE id = ?", (blueprint_id,)).fetchone()
        if row:
            return _row_to_dict(row, ['artifacts', 'settings'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting velociraptor blueprint: {e}", flush=True)
        return None


def delete_velociraptor_blueprint(blueprint_id: str) -> bool:
    """Delete a velociraptor blueprint"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM blueprints_velociraptor WHERE id = ?", (blueprint_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting velociraptor blueprint: {e}", flush=True)
        return False


# ============================================================================
# Agentic Blueprint Storage
# ============================================================================

def save_agentic_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    """Save or update an agentic blueprint"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()

        existing = conn.execute(
            "SELECT id FROM blueprints_agentic WHERE id = ?",
            (blueprint_data.get('id'),)
        ).fetchone()

        created_at = blueprint_data.get('created_at', now) if not existing else \
            conn.execute("SELECT created_at FROM blueprints_agentic WHERE id = ?",
                         (blueprint_data.get('id'),)).fetchone()['created_at']

        conn.execute(
            """INSERT OR REPLACE INTO blueprints_agentic
               (id, name, description, is_default, artifacts, settings, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (blueprint_data.get('id'),
             blueprint_data.get('name'),
             blueprint_data.get('description'),
             1 if blueprint_data.get('is_default') else 0,
             json.dumps(blueprint_data.get('artifacts')) if blueprint_data.get('artifacts') is not None else '[]',
             json.dumps(blueprint_data.get('settings')) if blueprint_data.get('settings') is not None else '{}',
             created_at,
             now)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving agentic blueprint: {e}", flush=True)
        return False


def load_agentic_blueprints() -> List[Dict[str, Any]]:
    """Load all agentic blueprints"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM blueprints_agentic").fetchall()
        return [_row_to_dict(r, ['artifacts', 'settings']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading agentic blueprints: {e}", flush=True)
        return []


def get_agentic_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific agentic blueprint by id"""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM blueprints_agentic WHERE id = ?", (blueprint_id,)).fetchone()
        if row:
            return _row_to_dict(row, ['artifacts', 'settings'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting agentic blueprint: {e}", flush=True)
        return None


def delete_agentic_blueprint(blueprint_id: str) -> bool:
    """Delete an agentic blueprint"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM blueprints_agentic WHERE id = ?", (blueprint_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting agentic blueprint: {e}", flush=True)
        return False


# ============================================================================
# Timesketch Blueprint Storage
# ============================================================================

def save_timesketch_blueprint(blueprint_data: Dict[str, Any]) -> bool:
    """Save or update a timesketch blueprint"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()

        existing = conn.execute(
            "SELECT id FROM blueprints_timesketch WHERE id = ?",
            (blueprint_data.get('id'),)
        ).fetchone()

        created_at = blueprint_data.get('created_at', now) if not existing else \
            conn.execute("SELECT created_at FROM blueprints_timesketch WHERE id = ?",
                         (blueprint_data.get('id'),)).fetchone()['created_at']

        conn.execute(
            """INSERT OR REPLACE INTO blueprints_timesketch
               (id, name, description, is_default, settings, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (blueprint_data.get('id'),
             blueprint_data.get('name'),
             blueprint_data.get('description'),
             1 if blueprint_data.get('is_default') else 0,
             json.dumps(blueprint_data.get('settings')) if blueprint_data.get('settings') is not None else '{}',
             created_at,
             now)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving timesketch blueprint: {e}", flush=True)
        return False


def load_timesketch_blueprints() -> List[Dict[str, Any]]:
    """Load all timesketch blueprints"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM blueprints_timesketch").fetchall()
        return [_row_to_dict(r, ['settings']) for r in rows]
    except Exception as e:
        print(f"[STORAGE] Error loading timesketch blueprints: {e}", flush=True)
        return []


def get_timesketch_blueprint(blueprint_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific timesketch blueprint by id"""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM blueprints_timesketch WHERE id = ?", (blueprint_id,)).fetchone()
        if row:
            return _row_to_dict(row, ['settings'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting timesketch blueprint: {e}", flush=True)
        return None


def delete_timesketch_blueprint(blueprint_id: str) -> bool:
    """Delete a timesketch blueprint"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM blueprints_timesketch WHERE id = ?", (blueprint_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting timesketch blueprint: {e}", flush=True)
        return False


# ============================================================================
# Report Storage
# ============================================================================

def save_report(run_id: str, content: str) -> bool:
    """Save a report to the database"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO reports (run_id, content, created_at) VALUES (?, ?, ?)",
            (run_id, content, now)
        )
        conn.commit()
        print(f"[STORAGE] Report saved for run_id: {run_id}", flush=True)
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving report: {e}", flush=True)
        return False


def get_report(run_id: str) -> Optional[str]:
    """Get report content by run_id. Returns the markdown string or None."""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT content FROM reports WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            return row['content']
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting report: {e}", flush=True)
        return None


def delete_report(run_id: str) -> bool:
    """Delete a report"""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting report: {e}", flush=True)
        return False


# ============================================================================
# Frontend Config Storage
# ============================================================================

def save_frontend_config(config: Dict[str, Any]) -> bool:
    """Save frontend configuration to the database"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()
        for key, value in config.items():
            conn.execute(
                "INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), now)
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving frontend config: {e}", flush=True)
        return False


def load_frontend_config() -> Dict[str, Any]:
    """Load frontend configuration from the database"""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT key, value FROM frontend_config").fetchall()
        config = {}
        for row in rows:
            try:
                config[row['key']] = json.loads(row['value'])
            except (json.JSONDecodeError, TypeError):
                config[row['key']] = row['value']
        return config
    except Exception as e:
        print(f"[STORAGE] Error loading frontend config: {e}", flush=True)
        return {}


# ============================================================================
# Cloud Configuration
# ============================================================================

def save_cloud_config(config: Dict[str, Any]) -> bool:
    """Save cloud provider configuration to the database"""
    try:
        conn = _get_connection()
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES (?, ?, ?)",
            ("cloud", json.dumps(config), now)
        )
        conn.commit()
        print(f"[STORAGE] Cloud config saved for provider: {config.get('provider', 'unknown')}", flush=True)
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving cloud config: {e}", flush=True)
        return False


def load_cloud_config() -> Optional[Dict[str, Any]]:
    """Load cloud provider configuration from the database"""
    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT value FROM frontend_config WHERE key = ?",
            ("cloud",)
        ).fetchone()
        if row:
            return json.loads(row['value'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error loading cloud config: {e}", flush=True)
        return None


# ============================================================================
# Export / Import
# ============================================================================

def export_db() -> Dict[str, Any]:
    """Export all tables to a JSON-serializable dict"""
    conn = _get_connection()
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
        data["workflows"].append(_row_to_dict(row, ['details', 'logs']))

    # Blueprints
    for row in conn.execute("SELECT * FROM blueprints_velociraptor").fetchall():
        data["blueprints_velociraptor"].append(_row_to_dict(row, ['artifacts', 'settings']))

    for row in conn.execute("SELECT * FROM blueprints_agentic").fetchall():
        data["blueprints_agentic"].append(_row_to_dict(row, ['artifacts', 'settings']))

    # Offline collectors
    for row in conn.execute("SELECT * FROM offline_collectors").fetchall():
        data["offline_collectors"].append(_row_to_dict(row, ['artifacts', 'parameters']))

    # Reports
    for row in conn.execute("SELECT * FROM reports").fetchall():
        data["reports"].append(dict(row))

    # Frontend config
    data["frontend_config"] = load_frontend_config()

    return data


def import_db(data: Dict[str, Any]) -> bool:
    """Import data from a JSON dict (from export_db) into the database"""
    try:
        conn = _get_connection()

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


# Initialize storage on module load
print("[STORAGE] Initializing SQLite storage...", flush=True)
storage_initialized = init_storage()
if storage_initialized:
    print(f"[STORAGE] SQLite storage initialized: {DB_PATH}", flush=True)
else:
    print("[STORAGE] SQLite storage initialization failed", flush=True)
