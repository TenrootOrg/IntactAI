#!/usr/bin/env python3
"""
Workflow Storage - CRUD operations for workflow runs
"""

import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from .base import get_connection, row_to_dict


_JSON_FIELDS = ['details', 'logs', 'phase_timings', 'llm_metrics', 'sigma_rule_tally']


def _json_or_default(value, default):
    """Serialize a JSON-bearing field, using default when value is None."""
    if value is None:
        return default
    return json.dumps(value)


def save_workflow(workflow_data: Dict[str, Any]) -> bool:
    """Save or update a workflow run.

    `logs` and `error_count` are written only when the row is first created.
    After that both belong to append_workflow_log(): a caller that read the run,
    changed its status and saved it back would otherwise write its stale copy
    over lines and error counts other threads appended in between -- the
    lost-log race the per-run lock used to paper over. The embedded `logs`
    column now only holds what runs created before workflow_logs carry (and
    rows inserted whole, e.g. an imported case bundle)."""
    try:
        conn = get_connection()
        conn.execute(
            """INSERT INTO workflows
               (run_id, automation_type, name, details, status, progress, logs, phase, error,
                created_at, updated_at, phase_timings, llm_metrics, sigma_rule_tally, error_count,
                case_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET
                automation_type = excluded.automation_type, name = excluded.name,
                details = excluded.details, status = excluded.status,
                progress = excluded.progress, phase = excluded.phase,
                error = excluded.error, created_at = excluded.created_at,
                updated_at = excluded.updated_at, phase_timings = excluded.phase_timings,
                llm_metrics = excluded.llm_metrics,
                sigma_rule_tally = excluded.sigma_rule_tally, case_id = excluded.case_id""",
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
             int(workflow_data.get('error_count') or 0),
             workflow_data.get('case_id'))
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error saving workflow: {e}", flush=True)
        return False


def _log_entry(ts, level, msg) -> Dict[str, Any]:
    return {"timestamp": ts, "level": level, "message": msg}


def _embedded_logs(value) -> list:
    """The pre-table `logs` column, parsed or not; anything that isn't a list
    of lines counts as no lines."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


def _select_runs(where: str = "", params: tuple = (), with_logs: bool = True) -> List[Dict[str, Any]]:
    """Runs matching `where`, each with `logs` = its embedded (pre-table) lines
    followed by its workflow_logs rows -- the exact shape every reader got when
    the logs lived in the row. with_logs=False drops `logs` altogether: for the
    read-modify-write paths, which never write it back anyway."""
    conn = get_connection()
    runs = [row_to_dict(r, _JSON_FIELDS)
            for r in conn.execute(f"SELECT * FROM workflows {where}", params)]
    if not with_logs:
        for r in runs:
            r.pop("logs", None)
        return runs
    table: Dict[str, list] = {}
    for rid, ts, level, msg in conn.execute(
            f"SELECT run_id, ts, level, msg FROM workflow_logs WHERE run_id IN "
            f"(SELECT run_id FROM workflows {where}) ORDER BY id", params):
        table.setdefault(rid, []).append(_log_entry(ts, level, msg))
    for r in runs:
        r["logs"] = _embedded_logs(r.get("logs")) + table.get(r.get("run_id"), [])
    return runs


def load_workflows(with_logs: bool = True, statuses=None) -> List[Dict[str, Any]]:
    """Load all workflows (only those in `statuses`, when given)."""
    try:
        if statuses:
            return _select_runs(f"WHERE status IN ({','.join('?' * len(statuses))})",
                                tuple(statuses), with_logs)
        return _select_runs(with_logs=with_logs)
    except Exception as e:
        print(f"[STORAGE] Error loading workflows: {e}", flush=True)
        return []


def get_workflows_by_case(case_id: str, with_logs: bool = True) -> List[Dict[str, Any]]:
    """Load all workflows tagged to a case (workspace)."""
    try:
        return _select_runs("WHERE case_id = ?", (case_id,), with_logs)
    except Exception as e:
        print(f"[STORAGE] Error loading workflows by case: {e}", flush=True)
        return []


def reassign_null_case(case_id: str, automation_types: List[str]) -> int:
    """One-time backfill: tag legacy analysis runs that have no case to `case_id`.
    Returns the number of rows updated. Idempotent (only touches NULL case_id)."""
    try:
        conn = get_connection()
        placeholders = ",".join("?" for _ in automation_types)
        cur = conn.execute(
            f"UPDATE workflows SET case_id = ? "
            f"WHERE case_id IS NULL AND automation_type IN ({placeholders})",
            (case_id, *automation_types))
        conn.commit()
        return cur.rowcount or 0
    except Exception as e:
        print(f"[STORAGE] Error reassigning null-case workflows: {e}", flush=True)
        return 0


def get_workflow(run_id: str, with_logs: bool = True) -> Optional[Dict[str, Any]]:
    """Get a specific workflow by run_id"""
    try:
        runs = _select_runs("WHERE run_id = ?", (run_id,), with_logs)
        return runs[0] if runs else None
    except Exception as e:
        print(f"[STORAGE] Error getting workflow: {e}", flush=True)
        return None


def delete_workflow(run_id: str) -> bool:
    """Delete a workflow and its log lines"""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM workflows WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM workflow_logs WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting workflow: {e}", flush=True)
        return False


# How often a plain log line may also bump the run's updated_at. Bumping on every
# line rewrites the whole row (details and all) per line -- the cost this table
# exists to remove -- while the idle reaper (cleanup_orphan_workflows) only needs
# updated_at to within hours. Error lines always write: they bump error_count.
_UPDATED_AT_EVERY = timedelta(seconds=30)


def append_workflow_log(run_id: str, message, level: str = "info", force: bool = False,
                        count_error: bool = True) -> bool:
    """Append one log line to a run. Returns True when it was stored.

    One INSERT, guarded in the same statement: nothing is written for a run that
    does not exist, and nothing for a 'cancelled' run unless `force` (see
    workflow_service.add_log_to_run for why). Being one statement, it stays
    consistent with a concurrent status change without any per-run lock.
    An 'error' line bumps error_count unless count_error=False."""
    if not isinstance(message, str):
        message = str(message)
    for attempt in range(3):
        try:
            conn = get_connection()
            now = datetime.now()
            ts = now.isoformat()
            cur = conn.execute(
                "INSERT INTO workflow_logs (run_id, ts, level, msg) SELECT ?, ?, ?, ? "
                "WHERE EXISTS (SELECT 1 FROM workflows WHERE run_id = ? "
                "AND (? OR status IS NOT 'cancelled'))",
                (run_id, ts, level, message, run_id, 1 if force else 0))
            stored = bool(cur.rowcount)
            if stored and level == "error" and count_error:
                conn.execute(
                    "UPDATE workflows SET error_count = COALESCE(error_count, 0) + 1, "
                    "updated_at = ? WHERE run_id = ?", (ts, run_id))
            elif stored:
                conn.execute(
                    "UPDATE workflows SET updated_at = ? WHERE run_id = ? "
                    "AND (updated_at IS NULL OR updated_at < ?)",
                    (ts, run_id, (now - _UPDATED_AT_EVERY).isoformat()))
            conn.commit()
            return stored
        except sqlite3.OperationalError as e:
            # "database is locked" after the 5 s busy_timeout. This used to be
            # printed and the line dropped; a log line is the operator's only
            # record of what a run did, so try again before giving up loudly.
            try:
                get_connection().rollback()
            except Exception:
                pass
            if attempt == 2 or "locked" not in str(e):
                print(f"[STORAGE] LOST log line for {run_id} ({e}): {message[:200]}", flush=True)
                return False
            time.sleep(0.2)
        except Exception as e:
            print(f"[STORAGE] LOST log line for {run_id} ({e}): {message[:200]}", flush=True)
            return False
    return False


def get_workflow_logs(run_id: str, since: Optional[int] = None,
                      limit: Optional[int] = None) -> Dict[str, Any]:
    """A run's log lines, for a viewer that polls.

    since=None: the whole log (embedded pre-table lines first), or only its last
    `limit` lines. since=N: only workflow_logs rows with id > N, oldest first, at
    most `limit` -- a viewer that falls behind catches up over a few polls
    instead of skipping lines. `cursor` is what to pass as `since` next time;
    `truncated` says older lines were left out."""
    conn = get_connection()
    if since is not None:
        sql = "SELECT id, ts, level, msg FROM workflow_logs WHERE run_id = ? AND id > ? ORDER BY id"
        params: tuple = (run_id, int(since))
        if limit:
            sql += " LIMIT ?"
            params += (int(limit),)
        rows = conn.execute(sql, params).fetchall()
        return {"logs": [_log_entry(r[1], r[2], r[3]) for r in rows],
                "cursor": rows[-1][0] if rows else int(since), "truncated": False}
    row = conn.execute("SELECT logs FROM workflows WHERE run_id = ?", (run_id,)).fetchone()
    embedded = _embedded_logs(row[0]) if row else []
    sql = "SELECT id, ts, level, msg FROM workflow_logs WHERE run_id = ? ORDER BY id DESC"
    params = (run_id,)
    if limit:
        sql += " LIMIT ?"
        params += (int(limit) + 1,)        # one extra row says whether more exist
    rows = conn.execute(sql, params).fetchall()[::-1]
    logs = embedded + [_log_entry(r[1], r[2], r[3]) for r in rows]
    truncated = bool(limit) and len(logs) > int(limit)
    if truncated:
        logs = logs[-int(limit):]
    return {"logs": logs, "cursor": rows[-1][0] if rows else 0, "truncated": truncated}
