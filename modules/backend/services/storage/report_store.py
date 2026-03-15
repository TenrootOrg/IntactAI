#!/usr/bin/env python3
"""
Report Storage - CRUD operations for reports
"""

from datetime import datetime
from typing import Optional

from .base import get_connection


def save_report(run_id: str, content: str) -> bool:
    """Save a report to the database"""
    try:
        conn = get_connection()
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
        conn = get_connection()
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
        conn = get_connection()
        conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[STORAGE] Error deleting report: {e}", flush=True)
        return False
