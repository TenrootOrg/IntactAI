#!/usr/bin/env python3
"""
Client Routes - Client endpoints
"""

import os
import threading
import time
from flask import Blueprint, jsonify, send_file, request
import traceback

from services import get_clients_from_snapshot
from services.velociraptor_clients import ONLINE_SECONDS
from services.msi_generator_service import download_client_installer
from services.legacy_velociraptor_service import (
    build_legacy_client,
    build_modern_musl_linux_client,
    legacy_status as _legacy_status,
)

client_bp = Blueprint('client', __name__)


def _online(c, now):
    """Seen within the dashboard's window. last_seen_at is microseconds."""
    seen = c.get('last_seen_at') or 0
    return bool(seen) and now - seen / 1e6 < ONLINE_SECONDS


# The whole fleet, as last fetched. Every open dashboard tab polled /api/clients
# every 10 s -- a full fleet query (~200 KB at 1,000 clients) -- to show two numbers;
# /api/clients/summary answers from this instead, at most SUMMARY_MAX_AGE old.
# Any full /api/clients fetch refreshes it; the pickers' ↻ always fetches live.
SUMMARY_MAX_AGE = 30
_FLEET_CACHE = {"at": 0.0, "rows": None}
_FLEET_LOCK = threading.Lock()   # summary misses only: N tabs missing together cost one query


def _fetch_fleet():
    """Every enrolled client (offline ones too), live; refreshes the cache."""
    rows = get_clients_from_snapshot(include_offline=True)
    _FLEET_CACHE.update(at=time.time(), rows=rows)
    return rows


def _cached_fleet():
    """The fleet, at most SUMMARY_MAX_AGE old."""
    with _FLEET_LOCK:
        if _FLEET_CACHE["rows"] is not None and time.time() - _FLEET_CACHE["at"] < SUMMARY_MAX_AGE:
            return _FLEET_CACHE["rows"]
        return _fetch_fleet()


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

    Returns {items (online first, then hostname), total (agents), filtered
    (matching `search`), truncated (true when `limit` cut items short of
    filtered), imported (offline-collection imports left out)}.
    """
    try:
        include_offline = request.args.get('include_offline', '').lower() in ('true', '1', 'yes')
        clients = _fetch_fleet() if include_offline else get_clients_from_snapshot(include_offline=False)
        # Offline-collection imports are not agents: nothing can be sent to them,
        # so they are neither pickable nor counted (see _is_import).
        imported = sum(1 for c in clients if c.get('imported'))
        clients = [c for c in clients if not c.get('imported')]
        total = len(clients)

        # Smart filter: match the term against hostname, OS (+ version), or any
        # Velociraptor label — so "windows", "linux", or a label like "servers"
        # narrows the list, not just the hostname.
        search = request.args.get('search', '').strip().lower()
        if search:
            def _match(c):
                hay = ' '.join([
                    str(c.get('hostname') or ''),
                    str(c.get('os') or ''),
                    str(c.get('os_version') or ''),
                    ' '.join(str(l) for l in (c.get('labels') or [])),
                ]).lower()
                return search in hay
            clients = [c for c in clients if _match(c)]

        filtered = len(clients)

        # Sorted BEFORE the limit (online first, then hostname): the pickers ask
        # for limit=1000, and cut from the unsorted fleet an arbitrary subset --
        # online hosts included -- silently disappeared above 1,000 clients.
        now = time.time()
        clients.sort(key=lambda c: (not _online(c, now), str(c.get('hostname') or '').lower(),
                                    str(c.get('client_id') or '')))
        limit = request.args.get('limit', type=int)
        if limit and limit > 0:
            clients = clients[:limit]

        return jsonify({
            "items": clients,
            "total": total,
            "filtered": filtered,
            "truncated": len(clients) < filtered,
            "imported": imported,
        })

    except Exception as e:
        print(f"API Error: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "items": [], "total": 0}), 500

@client_bp.route('/api/clients/summary')
def get_clients_summary():
    """The dashboard's endpoint counter: {online, total, as_of}. total counts agents
    (offline-collection imports excluded, as in /api/clients); online = seen in the
    last ONLINE_SECONDS. Served from a fleet query at most SUMMARY_MAX_AGE old;
    as_of is when that query ran (epoch seconds)."""
    try:
        clients = [c for c in _cached_fleet() if not c.get('imported')]
        now = time.time()
        return jsonify({"online": sum(1 for c in clients if _online(c, now)),
                        "total": len(clients), "as_of": int(_FLEET_CACHE["at"])})
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"error": str(e), "online": 0, "total": 0}), 500


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

        # --- Modern musl Linux build: repack on demand ----------------------
        # 'linux-musl' → repack the modern Velociraptor musl-static binary
        # (statically linked against musl libc, zero glibc deps). Same
        # feature set as the regular linux-amd64 build but runs on ANY
        # Linux x86_64 — CentOS 7, Sophos UTM, Alpine containers, etc.
        if platform == 'linux-musl':
            source = (request.args.get('source') or 'offline').lower()
            if source not in ('offline', 'online'):
                return jsonify({"error": "source must be 'offline' or 'online'"}), 400
            version = request.args.get('version') or None
            result = build_modern_musl_linux_client(version=version, source=source)
            if not result.get('success'):
                return jsonify({"error": result.get('error', 'musl repack failed')}), 500
            return send_file(
                result['path'],
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=result['filename'],
            )

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
