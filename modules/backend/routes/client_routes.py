#!/usr/bin/env python3
"""
Client Routes - Client endpoints
"""

import os
from flask import Blueprint, jsonify, send_file, request
import traceback

from services import get_clients_from_snapshot
from services.msi_generator_service import download_client_installer
from services.legacy_velociraptor_service import (
    build_legacy_client,
    legacy_status as _legacy_status,
)

client_bp = Blueprint('client', __name__)

@client_bp.route('/api/clients')
def get_clients():
    """Get Velociraptor clients with optional search and limit.

    Query params:
        search: filter by hostname (case-insensitive contains)
        limit: max number of clients to return (default: all)
        include_offline: 'true' to include clients not seen in the last
            10 minutes. Default is online-only (current behavior). The
            existing-flow analyzer flips this on for hunt-derived flows
            where data is already collected and offline endpoints are
            valid analysis targets.
    """
    try:
        include_offline = request.args.get('include_offline', '').lower() in ('true', '1', 'yes')
        clients = get_clients_from_snapshot(include_offline=include_offline)
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
    """Download a Velociraptor client installer.

    Platforms:
        windows-msi, windows-exe, linux, mac  (modern build, pre-generated
            at velociraptor container startup)
        windows-legacy-exe                    (legacy build for Server 2008
            R2 / Win 7 — built on demand from the bundled or
            on-demand-fetched legacy binary)
        linux-legacy                          (legacy build for old-glibc
            Linux hosts like CentOS 7 / RHEL 7 / Ubuntu 16.04, where
            glibc < 2.28 makes the modern binary crash on load. Built
            on demand from the same legacy version pin.)

    Query params for the legacy platforms:
        source  : 'offline' (default) | 'online'
        version : legacy version (defaults to versions.velociraptor_legacy
                  in config.yaml). Only honoured when source='online'.
    """
    try:
        print(f"[CLIENT-ROUTE] Download request for platform: {platform}", flush=True)

        # --- Legacy builds: repack on demand --------------------------------
        # 'windows-legacy-exe' → repack legacy Windows binary
        # 'linux-legacy'        → repack legacy Linux binary (for old glibc
        #                          hosts like CentOS 7, glibc 2.17)
        if platform in ('windows-legacy-exe', 'linux-legacy'):
            target = 'linux' if platform == 'linux-legacy' else 'windows'
            source = (request.args.get('source') or 'offline').lower()
            if source not in ('offline', 'online'):
                return jsonify({"error": "source must be 'offline' or 'online'"}), 400
            version = request.args.get('version') or None

            result = build_legacy_client(target=target, version=version, source=source)
            if not result.get('success'):
                return jsonify({"error": result.get('error', 'legacy repack failed')}), 500

            return send_file(
                result['path'],
                mimetype='application/octet-stream' if target == 'linux' else 'application/x-msdownload',
                as_attachment=True,
                download_name=result['filename'],
            )

        # --- Modern builds (existing behavior) ------------------------------
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


@client_bp.route('/api/clients/legacy/status')
def legacy_client_status():
    """Snapshot of legacy-binary availability for the UI to grey/show
    the Download Legacy buttons correctly."""
    try:
        return jsonify(_legacy_status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
