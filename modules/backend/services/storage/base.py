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

        CREATE TABLE IF NOT EXISTS upgrade_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE,
            phase TEXT,
            target_modules TEXT,
            completed_modules TEXT,
            mode TEXT,
            package_dir TEXT,
            db_overwrite TEXT DEFAULT '{}',
            created_at TEXT,
            updated_at TEXT
        );

        -- Runtime secrets (api keys, passwords). Deliberately separate from
        -- frontend_config so export_db() never dumps these into a backup
        -- file. install.sh's bootstrap_iris_api_key writes here; backend
        -- reads here at startup.
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
    # Two-phase upgrade resilience: bounded resume retries + the module that
    # was mid-dispatch when a crash hit (so its noop shortcut is bypassed on
    # resume). save_upgrade_state's upsert doesn't SET these, so Phase-1
    # re-saves never clobber them.
    _ensure_column(conn, "upgrade_state", "resume_count", "INTEGER DEFAULT 0")
    _ensure_column(conn, "upgrade_state", "in_flight", "TEXT")
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


def migrate_add_db_overwrite_column():
    """Add db_overwrite column to upgrade_state table if it doesn't exist."""
    conn = get_connection()
    try:
        # Check if column exists
        cursor = conn.execute("PRAGMA table_info(upgrade_state)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'db_overwrite' not in columns:
            conn.execute("ALTER TABLE upgrade_state ADD COLUMN db_overwrite TEXT DEFAULT '{}'")
            conn.commit()
            print("[STORAGE] Added db_overwrite column to upgrade_state table", flush=True)
    except Exception as e:
        print(f"[STORAGE] Error adding db_overwrite column: {e}", flush=True)


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
        migrate_add_db_overwrite_column()
        migrate_add_workflow_observability_columns()
        return True
    except Exception as e:
        print(f"[STORAGE] Failed to initialize: {e}", flush=True)
        return False


# =============================================================================
# Upgrade State Management (Two-Phase Upgrade Support)
# =============================================================================

def save_upgrade_state(run_id: str, phase: str, target_modules: Dict,
                       completed_modules: List[str], mode: str,
                       package_dir: str = None, package_path: str = None,
                       db_overwrite: Dict = None) -> bool:
    """Save or update upgrade state for two-phase upgrades.

    Args:
        run_id: The workflow run ID
        phase: Current phase (phase1, awaiting_restart, phase2, completed)
        target_modules: Dict of module -> version to upgrade
        completed_modules: List of completed module names
        mode: 'online' or 'offline'
        package_dir: Path to extracted package directory (for offline mode)
        package_path: Path to uploaded package file (for cleanup after Phase 2)
        db_overwrite: Dict of module -> bool for fresh install (e.g., {"timesketch": True, "iris": False})
    """
    # Store both paths as JSON in package_dir field for cleanup
    if package_path:
        package_dir = json.dumps({'extract_dir': package_dir, 'package_path': package_path})
    # Default empty dict for db_overwrite
    db_overwrite = db_overwrite or {}
    conn = get_connection()
    now = datetime.now().isoformat()
    try:
        conn.execute("""
            INSERT INTO upgrade_state
            (run_id, phase, target_modules, completed_modules, mode, package_dir, db_overwrite, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                phase = excluded.phase,
                target_modules = excluded.target_modules,
                completed_modules = excluded.completed_modules,
                mode = excluded.mode,
                package_dir = excluded.package_dir,
                db_overwrite = excluded.db_overwrite,
                updated_at = excluded.updated_at
        """, (run_id, phase, json.dumps(target_modules), json.dumps(completed_modules),
              mode, package_dir, json.dumps(db_overwrite), now, now))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving upgrade state: {e}", flush=True)
        return False


def get_pending_upgrade() -> Optional[Dict]:
    """Get pending upgrade that needs to be resumed after restart.

    Matches 'awaiting_restart' (the expected Phase-1 -> Phase-2 handoff) AND
    'phase2' — a phase2 row at boot means the previous process DIED mid-Phase-2
    (crash/OOM/manual restart); it used to be stranded forever because only
    awaiting_restart was matched. The boot resume-guard bounds retries via
    resume_count so a crash-looping upgrade can't restart-storm.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM upgrade_state WHERE phase IN ('awaiting_restart', 'phase2') "
            "ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row:
            return row_to_dict(row, ['target_modules', 'completed_modules', 'db_overwrite'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting pending upgrade: {e}", flush=True)
        return None


def increment_upgrade_resume_count(run_id: str) -> int:
    """Atomically bump upgrade_state.resume_count for a boot-time resume
    attempt; returns the NEW count, or -1 on error."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE upgrade_state SET resume_count = COALESCE(resume_count, 0) + 1 "
            "WHERE run_id = ?", (run_id,))
        conn.commit()
        row = conn.execute(
            "SELECT resume_count FROM upgrade_state WHERE run_id = ?", (run_id,)
        ).fetchone()
        return int(row[0]) if row else -1
    except Exception as e:
        print(f"[STORAGE] Error incrementing resume_count: {e}", flush=True)
        return -1


def set_upgrade_in_flight(run_id: str, module: Optional[str]) -> bool:
    """Record (or clear, with None) the module currently being dispatched in
    Phase 2. On resume, this module bypasses the already-at-version noop
    shortcut: a crash AFTER its .env pin bump but BEFORE compose-up otherwise
    makes it LOOK done while containers still run the old image."""
    conn = get_connection()
    try:
        conn.execute("UPDATE upgrade_state SET in_flight = ? WHERE run_id = ?",
                     (module, run_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error setting in_flight: {e}", flush=True)
        return False


def get_active_upgrade_state() -> Optional[Dict]:
    """Any upgrade_state row, regardless of phase (phase1 | awaiting_restart |
    phase2). Presence means an upgrade currently OWNS the system — rows are
    created at workflow start and deleted in its finally/finalizer — so this
    is the single-writer lock predicate. Newest first."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM upgrade_state ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row:
            return row_to_dict(row, ['target_modules', 'completed_modules', 'db_overwrite'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting active upgrade state: {e}", flush=True)
        return None


def get_upgrade_state(run_id: str) -> Optional[Dict]:
    """Get upgrade state for a specific run_id."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM upgrade_state WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row:
            return row_to_dict(row, ['target_modules', 'completed_modules', 'db_overwrite'])
        return None
    except Exception as e:
        print(f"[STORAGE] Error getting upgrade state: {e}", flush=True)
        return None


def update_upgrade_phase(run_id: str, phase: str, completed_modules: List[str] = None) -> bool:
    """Update the phase and optionally completed modules for an upgrade."""
    conn = get_connection()
    now = datetime.now().isoformat()
    try:
        if completed_modules is not None:
            conn.execute(
                "UPDATE upgrade_state SET phase = ?, completed_modules = ?, updated_at = ? WHERE run_id = ?",
                (phase, json.dumps(completed_modules), now, run_id)
            )
        else:
            conn.execute(
                "UPDATE upgrade_state SET phase = ?, updated_at = ? WHERE run_id = ?",
                (phase, now, run_id)
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error updating upgrade phase: {e}", flush=True)
        return False


def clear_upgrade_state(run_id: str) -> bool:
    """Remove upgrade state after successful completion."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM upgrade_state WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error clearing upgrade state: {e}", flush=True)
        return False
