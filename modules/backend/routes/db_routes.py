#!/usr/bin/env python3
"""
Database Routes - Export/import endpoints for SQLite database
"""

import os
from flask import Blueprint, jsonify, request, Response, send_file

from services.file_storage_service import export_db, import_db, DB_PATH

db_bp = Blueprint('db', __name__)


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
                'Content-Disposition': 'attachment; filename="mssp_db_export.json"'
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
    """Download the raw SQLite .db file"""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({"error": "Database file not found"}), 404

        return send_file(
            DB_PATH,
            mimetype='application/x-sqlite3',
            as_attachment=True,
            download_name='mssp.db'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
