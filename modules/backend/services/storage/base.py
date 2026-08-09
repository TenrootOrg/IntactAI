#!/usr/bin/env python3
"""
Storage Base - SQLite connection, schema, and migration utilities
"""

import json
import os
import sqlite3
import threading
import glob as glob_module
from datetime import datetime
from typing import Dict, List, Any, Optional

# Storage paths. STORAGE_BASE defaults to the production data dir but can be
# redirected via INTACT_STORAGE_BASE so test harnesses run against a throwaway
# SQLite DB instead of polluting the live database (fusion unit tests boot real
# storage at import time — see services/fusion/tests/run_all.py).
STORAGE_BASE = os.environ.get("INTACT_STORAGE_BASE", "/app/data")
DB_PATH = os.path.join(STORAGE_BASE, "intact.db")
REPORTS_DIR = os.path.join(STORAGE_BASE, "reports")

# Legacy JSON file paths (for migration)
WORKFLOWS_FILE = os.path.join(STORAGE_BASE, "workflows.json")
OFFLINE_COLLECTORS_FILE = os.path.join(STORAGE_BASE, "offline_collectors.json")
BLUEPRINTS_VELOCIRAPTOR_FILE = os.path.join(STORAGE_BASE, "blueprints_velociraptor.json")
BLUEPRINTS_AGENTIC_FILE = os.path.join(STORAGE_BASE, "blueprints_agentic.json")
FRONTEND_CONFIG_FILE = os.path.join(STORAGE_BASE, "frontend_config.json")

# Thread-local storage for connections
_local = threading.local()


def get_connection() -> sqlite3.Connection:
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


def row_to_dict(row: sqlite3.Row, json_fields: list) -> Dict[str, Any]:
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


def create_tables():
    """Create all tables if they don't exist"""
    conn = get_connection()
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
            updated_at TEXT,
            phase_timings TEXT,
            llm_metrics TEXT,
            sigma_rule_tally TEXT,
            error_count INTEGER DEFAULT 0
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

        CREATE TABLE IF NOT EXISTS blueprints_memory (
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

        -- upgrade_state used to live here: the two-phase upgrade wrote its
        -- progress to a table because the backend was restarting itself
        -- mid-upgrade and needed something that survived. upgrade.sh runs on
        -- the host and never restarts under itself, so there is no state to
        -- carry across. upgrade.sh drops any leftover row on first run.

        -- Runtime secrets (api keys, passwords). Deliberately separate from
        -- frontend_config so export_db() never dumps these into a backup
        -- file. install.sh's bootstrap_iris_api_key writes here (IRIS is
        -- install/upgrade-only; nothing currently reads this back at runtime).
        CREATE TABLE IF NOT EXISTS secrets (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
    """)
    conn.commit()

    # Lightweight schema migrations — ALTER TABLE columns added after the
    # initial CREATE TABLE shipped. SQLite has no IF NOT EXISTS for ADD
    # COLUMN, so we introspect via PRAGMA table_info and skip if present.
    _ensure_column(conn, "workflows", "error_count", "INTEGER DEFAULT 0")
    # Workspace model: every analysis run is tagged to a case (workspace).
    _ensure_column(conn, "workflows", "case_id", "TEXT")
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_case_id ON workflows(case_id)")
        conn.commit()
    except Exception as e:
        print(f"[STORAGE] Could not create idx_workflows_case_id: {e}", flush=True)


def _ensure_column(conn, table: str, column: str, decl: str):
    """Add `column decl` to `table` if it isn't already present.
    Idempotent — safe to call on every startup."""
    try:
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            conn.commit()
            print(f"[STORAGE] Added column {table}.{column}", flush=True)
    except Exception as e:
        print(f"[STORAGE] Could not ensure column {table}.{column}: {e}", flush=True)


def migrate_from_json():
    """One-time migration from JSON files to SQLite"""
    conn = get_connection()
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


def migrate_agentic_to_velociraptor():
    """Merge blueprints_agentic into blueprints_velociraptor (they share same schema)"""
    conn = get_connection()
    try:
        # Check if agentic table exists and has data
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blueprints_agentic'")
        if not cursor.fetchone():
            return  # Table doesn't exist, nothing to migrate

        # Get count of agentic blueprints
        count = conn.execute("SELECT COUNT(*) FROM blueprints_agentic").fetchone()[0]
        if count == 0:
            return  # No data to migrate

        # Copy agentic blueprints to velociraptor table (INSERT OR IGNORE to skip duplicates)
        conn.execute("""
            INSERT OR IGNORE INTO blueprints_velociraptor
            (id, name, description, is_default, artifacts, settings, created_at, updated_at)
            SELECT id, name, description, is_default, artifacts, settings, created_at, updated_at
            FROM blueprints_agentic
        """)
        conn.commit()
        print(f"[STORAGE] Merged {count} agentic blueprints into velociraptor table", flush=True)
    except Exception as e:
        print(f"[STORAGE] Error merging agentic blueprints: {e}", flush=True)



def migrate_add_workflow_observability_columns():
    """Add phase_timings/llm_metrics/sigma_rule_tally columns to workflows."""
    conn = get_connection()
    try:
        cursor = conn.execute("PRAGMA table_info(workflows)")
        columns = {row[1] for row in cursor.fetchall()}
        added = []
        for col in ('phase_timings', 'llm_metrics', 'sigma_rule_tally'):
            if col not in columns:
                conn.execute(f"ALTER TABLE workflows ADD COLUMN {col} TEXT")
                added.append(col)
        if added:
            conn.commit()
            print(f"[STORAGE] Added workflow observability columns: {', '.join(added)}", flush=True)
    except Exception as e:
        print(f"[STORAGE] Error adding workflow observability columns: {e}", flush=True)


def init_storage() -> bool:
    """Initialize SQLite database, create tables, and migrate from JSON if needed"""
    try:
        os.makedirs(STORAGE_BASE, exist_ok=True)
        create_tables()
        migrate_from_json()
        migrate_agentic_to_velociraptor()
        migrate_add_workflow_observability_columns()
        return True
    except Exception as e:
        print(f"[STORAGE] Failed to initialize: {e}", flush=True)
        return False


# =============================================================================
# Upgrade State Management (Two-Phase Upgrade Support)
# =============================================================================















