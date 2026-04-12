#!/usr/bin/env python3
"""
Client Routes - Client endpoints
"""

import os
from flask import Blueprint, jsonify, send_file, request
import traceback

from services import get_clients_from_snapshot
from services.msi_generator_service import download_client_installer

client_bp = Blueprint('client', __name__)

@client_bp.route('/api/clients')
def get_clients():
    """Get Velociraptor clients with optional search and limit.

    Query params:
        search: filter by hostname (case-insensitive contains)
        limit: max number of clients to return (default: all)
    """
    try:
        clients = get_clients_from_snapshot()
        total = len(clients)

        # Filter by hostname search
        search = request.args.get('search', '').strip().lower()
        if search:
            clients = [c for c in clients if search in (c.get('hostname') or '').lower()]

        filtered = len(clients)

        # Apply limit
        limit = request.args.get('limit', type=int)
        if limit and limit > 0:
            clients = clients[:limit]

        return jsonify({
            "items": clients,
            "total": total,
            "filtered": filtered
        })

    except Exception as e:
        print(f"API Error: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "items": [], "total": 0}), 500

@client_bp.route('/api/client/<client_id>')
def get_client(client_id):
    """Get specific client details"""
    # This endpoint would require VQL query implementation
    return jsonify({"error": "Not implemented yet"}), 501

@client_bp.route('/api/clients/download/<platform>')
def download_client(platform):
    """Download a Velociraptor client installer

    Platforms: windows-msi, windows-exe, linux, mac

    Clients are pre-generated during platform installation.
    """
    try:
        print(f"[CLIENT-ROUTE] Download request for platform: {platform}", flush=True)

        # Get the installer file path
        file_path = download_client_installer(platform)

        if not file_path or not os.path.exists(file_path):
            error_msg = (
                f"Client installer not found for platform: {platform}. "
                "Clients should be generated during platform installation. "
                "Run: bash scripts/generate_clients.sh"
            )
            return jsonify({"error": error_msg}), 404

        filename = os.path.basename(file_path)

        # Determine MIME type
        if filename.endswith('.msi'):
            mimetype = 'application/x-msi'
        elif filename.endswith('.exe'):
            mimetype = 'application/x-msdownload'
        else:
            mimetype = 'application/octet-stream'

        print(f"[CLIENT-ROUTE] Serving file: {filename}", flush=True)

        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        print(f"[CLIENT-ROUTE] Error downloading client: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
