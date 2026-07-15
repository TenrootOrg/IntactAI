#!/usr/bin/env python3
"""
Database Routes - Export/import endpoints for SQLite database
"""

import os
import json
import sqlite3
import tempfile
from flask import Blueprint, jsonify, request, Response, send_file, after_this_request

from services.file_storage_service import export_db, import_db, DB_PATH

db_bp = Blueprint('db', __name__)


def _make_redacted_backup_copy(src_path: str) -> str:
    """Copy the live SQLite file and scrub real credentials from the copy
    before it's ever sent to a client — the secrets table (IRIS admin key,
    etc.) and the AWS/Azure/LLM secrets nested in frontend_config's JSON
    blobs must never leave this box in a downloadable backup. Returns the
    path to the redacted temp copy; caller is responsible for deleting it."""
    import shutil
    fd, tmp_path = tempfile.mkstemp(suffix=".db", prefix="intact_backup_")
    os.close(fd)
    shutil.copy2(src_path, tmp_path)

    conn = sqlite3.connect(tmp_path)
    try:
        conn.execute("UPDATE secrets SET value = '[REDACTED]'")

        rows = conn.execute(
            "SELECT key, value FROM frontend_config WHERE key IN ('cloud', 'agentic')"
        ).fetchall()
        for key, raw_value in rows:
            try:
                value = json.loads(raw_value)
            except (TypeError, ValueError):
                continue
            changed = False
            if key == 'cloud' and isinstance(value, dict):
                if value.get('aws', {}).get('secret_access_key'):
                    value['aws']['secret_access_key'] = '[REDACTED]'
                    changed = True
                if value.get('aws', {}).get('session_token'):
                    value['aws']['session_token'] = '[REDACTED]'
                    changed = True
                if value.get('azure', {}).get('client_secret'):
                    value['azure']['client_secret'] = '[REDACTED]'
                    changed = True
            elif key == 'agentic' and isinstance(value, dict):
                if value.get('online_llm', {}).get('api_key'):
                    value['online_llm']['api_key'] = '[REDACTED]'
                    changed = True
            if changed:
                conn.execute(
                    "UPDATE frontend_config SET value = ? WHERE key = ?",
                    (json.dumps(value), key)
                )
        conn.commit()
    finally:
        conn.close()
    return tmp_path


@db_bp.route('/api/db/export', methods=['GET'])
def export_database():
    """Export the entire database as a JSON download"""
    try:
        data = export_db()
        import json
        json_str = json.dumps(data, indent=2, default=str)
        return Response(
            json_str,
            mimetype='application/json',
            headers={
                'Content-Disposition': 'attachment; filename="intact_db_export.json"'
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@db_bp.route('/api/db/import', methods=['POST'])
def import_database():
    """Import database from a JSON upload"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        success = import_db(data)
        if success:
            return jsonify({"status": "ok", "message": "Database imported successfully"})
        else:
            return jsonify({"error": "Import failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@db_bp.route('/api/db/backup', methods=['GET'])
def backup_database():
    """Download the SQLite .db file, with real credentials redacted from a
    scratch copy — the live file's secrets table and frontend_config JSON
    blobs hold real IRIS/AWS/Azure/LLM credentials that must never leave
    this box in a backup."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({"error": "Database file not found"}), 404

        tmp_path = _make_redacted_backup_copy(DB_PATH)

        @after_this_request
        def _cleanup(response):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return response

        return send_file(
            tmp_path,
            mimetype='application/x-sqlite3',
            as_attachment=True,
            download_name='intact.db'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
