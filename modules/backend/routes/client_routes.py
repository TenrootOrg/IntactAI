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
from services.velociraptor_clients import ORG_INSTALLER_SOURCES, build_org_installer
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
_FLEET_CACHE = {}                # Velociraptor org -> {"at", "rows"}: each org has its own fleet
_FLEET_LOCK = threading.Lock()   # summary misses only: N tabs missing together cost one query


def _fetch_fleet():
    """Every enrolled client (offline ones too), live; refreshes the cache."""
    from services import velo_org
    rows = get_clients_from_snapshot(include_offline=True)
    _FLEET_CACHE[velo_org.current()] = {"at": time.time(), "rows": rows}
    return rows


# Orgs change rarely, and the dashboard polls the summary every 10 s per tab.
_ORGS_MAX_AGE = 60
_ORGS_CACHE = {"at": 0.0, "orgs": None}


def _org_names():
    """[(org id, name)] of every Velociraptor org, at most _ORGS_MAX_AGE old."""
    if _ORGS_CACHE["orgs"] is None or time.time() - _ORGS_CACHE["at"] >= _ORGS_MAX_AGE:
        from services.velociraptor_clients import org_list
        _ORGS_CACHE.update(at=time.time(), orgs=org_list())
    return _ORGS_CACHE["orgs"]


def _fleet_as_of():
    from services import velo_org
    return (_FLEET_CACHE.get(velo_org.current()) or {}).get("at", 0.0)


def _cached_fleet():
    """The fleet, at most SUMMARY_MAX_AGE old."""
    from services import velo_org
    with _FLEET_LOCK:
        hit = _FLEET_CACHE.get(velo_org.current())
        if hit and time.time() - hit["at"] < SUMMARY_MAX_AGE:
            return hit["rows"]
        return _fetch_fleet()


def _os_key(os_name):
    """The picker's OS group (js/utils/client-manager.js _osKey, same rule)."""
    s = str(os_name or '').strip().lower()
    if not s:
        return 'Unknown'
    if s == 'windows' or s.startswith('win'):
        return 'Windows'
    if s == 'linux':
        return 'Linux'
    if s in ('darwin', 'macos', 'osx', 'mac'):
        return 'macOS'
    return s[:1].upper() + s[1:]


_OS_RANK = {'Windows': 0, 'Linux': 1, 'macOS': 2}


def _os_rank(key):
    """Windows, Linux, macOS, the rest A-Z, Unknown last: the picker's groups."""
    return (3, '') if key == 'Unknown' else (_OS_RANK.get(key, 2.5), key)


def _csv_arg(name):
    return {v for v in (request.args.get(name, '') or '').split(',') if v}


@client_bp.route('/api/clients')
def get_clients():
    """Velociraptor clients: the whole fleet, or one page of it.

    Query params:
        include_offline: 'true' for every enrolled client; else only those seen
            in the last 10 minutes.
        fresh: '1' to query Velociraptor live instead of the fleet cache (at most
            SUMMARY_MAX_AGE old; offline-inclusive lists only).
        search: matched against hostname, OS (+ version), labels, client id, IP.
        os, label: comma-separated picker groups / labels (any label matches).
        online: '1' for clients seen in the last ONLINE_SECONDS only.
        offset, limit: one page of the filtered list. No limit: all of it.
        ids: '1' for every matching [client_id, hostname] instead of rows --
            what "Select all (matching)" needs on a fleet the browser never loads.

    The pickers ask for one page at a time and let this side filter, count and
    sort, so a 20,000-client org never travels to the browser (2026-11-25: a
    1,000-row cap hid the rest of a larger fleet). Sorted as the picker groups
    it: OS group, online first, hostname.

    Returns {items, total (agents), filtered (matching), offset, truncated (more
    after this page), facets {os, labels, online} over the whole fleet,
    groups {os group: matches}, imported (offline-collection imports left out)}.
    """
    try:
        include_offline = request.args.get('include_offline', '').lower() in ('true', '1', 'yes')
        # The pickers load from the cache (at most SUMMARY_MAX_AGE old), so one
        # Velociraptor query serves every picker and tab; fresh=1 (the pickers'
        # ↻) always queries live.
        fresh = request.args.get('fresh', '').lower() in ('true', '1', 'yes')
        if include_offline:
            clients = _fetch_fleet() if fresh else _cached_fleet()
        else:
            clients = get_clients_from_snapshot(include_offline=False)
        # Offline-collection imports are not agents: nothing can be sent to them,
        # so they are neither pickable nor counted (see _is_import).
        imported = sum(1 for c in clients if c.get('imported'))
        clients = [c for c in clients if not c.get('imported')]
        total = len(clients)
        now = time.time()

        facets_os, facets_labels, facets_online = {}, {}, 0
        for c in clients:
            k = _os_key(c.get('os'))
            facets_os[k] = facets_os.get(k, 0) + 1
            for l in (c.get('labels') or []):
                facets_labels[str(l)] = facets_labels.get(str(l), 0) + 1
            facets_online += 1 if _online(c, now) else 0

        # Every filter here, so a page, a count and "select all matching" agree.
        search = request.args.get('search', '').strip().lower()
        want_os, want_labels = _csv_arg('os'), _csv_arg('label')
        online_only = request.args.get('online', '').lower() in ('true', '1', 'yes')

        def _match(c):
            if want_os and _os_key(c.get('os')) not in want_os:
                return False
            if want_labels and not any(str(l) in want_labels for l in (c.get('labels') or [])):
                return False
            if online_only and not _online(c, now):
                return False
            if search:
                hay = ' '.join([
                    str(c.get('hostname') or ''), str(c.get('os') or ''),
                    str(c.get('os_version') or ''),
                    ' '.join(str(l) for l in (c.get('labels') or [])),
                    str(c.get('client_id') or ''), str(c.get('last_ip') or ''),
                ]).lower()
                return search in hay
            return True

        clients = [c for c in clients if _match(c)]
        filtered = len(clients)
        groups = {}
        for c in clients:
            k = _os_key(c.get('os'))
            groups[k] = groups.get(k, 0) + 1

        # Sorted BEFORE any page is cut: limit=1000 cut from the unsorted fleet
        # once dropped an arbitrary subset, online hosts included.
        clients.sort(key=lambda c: (_os_rank(_os_key(c.get('os'))), not _online(c, now),
                                    str(c.get('hostname') or '').lower(),
                                    str(c.get('client_id') or '')))

        if request.args.get('ids', '').lower() in ('true', '1', 'yes'):
            return jsonify({"ids": [[c.get('client_id'), c.get('hostname') or ''] for c in clients],
                            "total": total, "filtered": filtered})

        offset = max(0, request.args.get('offset', 0, type=int) or 0)
        limit = request.args.get('limit', type=int)
        page = clients[offset:offset + limit] if limit and limit > 0 else clients[offset:]

        return jsonify({
            "items": page,
            "total": total,
            "filtered": filtered,
            "offset": offset,
            "truncated": offset + len(page) < filtered,
            "facets": {"os": facets_os, "labels": facets_labels, "online": facets_online},
            "groups": groups,
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
    # Every Velociraptor org, not just the one this browser has selected: the
    # dashboard is the overview, and it has no org picker. by_org breaks it down.
    try:
        from services import velo_org
        now = time.time()
        try:
            orgs = _org_names()
        except Exception:  # noqa: BLE001 -- Velociraptor down: the selected org's cached count
            orgs = [(velo_org.current() or "root", velo_org.current() or "root")]
        by_org, as_of = [], []
        for org, name in orgs:
            with velo_org.use("" if org == "root" else org):
                clients = [c for c in _cached_fleet() if not c.get('imported')]
                as_of.append(_fleet_as_of())
            by_org.append({"org": org, "name": name, "total": len(clients),
                           "online": sum(1 for c in clients if _online(c, now))})
        return jsonify({"online": sum(o["online"] for o in by_org), "total": sum(o["total"] for o in by_org),
                        "by_org": by_org, "as_of": int(min(as_of) if as_of else 0)})
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"error": str(e), "online": 0, "total": 0}), 500


@client_bp.route('/api/client/<client_id>')
def get_client(client_id):
    """Get specific client details"""
    # This endpoint would require VQL query implementation
    return jsonify({"error": "Not implemented yet"}), 501

def _org_named(filename):
    """An installer built for a non-root Velociraptor org says so in its name."""
    from services import velo_org
    org = velo_org.current()
    if not org:
        return filename
    base, dot, ext = filename.rpartition('.')
    return f"{base}-{org}.{ext}" if dot and ext in ('exe', 'msi') else f"{filename}-{org}"


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
    # A host enrols into the org whose client config its installer carries. The
    # files below are root's; for another org each is repacked on demand with
    # that org's config (the legacy / musl builds read it in
    # legacy_velociraptor_service._client_config_bytes).
    from services import velo_org
    org = velo_org.current()
    if org and platform in ORG_INSTALLER_SOURCES:
        import shutil
        import tempfile
        work = tempfile.mkdtemp(prefix="intact-org-installer-")
        try:
            path, name, mime = build_org_installer(platform, org, work)
        except Exception as e:  # noqa: BLE001
            shutil.rmtree(work, ignore_errors=True)
            print(f"[CLIENT-ROUTE] ✗ {platform} installer for org {org}: {e}", flush=True)
            return jsonify({"error": f"Could not build the {platform} installer for org {org}: {e}"}), 500
        print(f"[CLIENT-ROUTE] Serving {name} (org {org})", flush=True)
        resp = send_file(path, mimetype=mime, as_attachment=True, download_name=name)
        resp.call_on_close(lambda: shutil.rmtree(work, ignore_errors=True))
        return resp
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
                download_name=_org_named(result['filename']),
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
                download_name=_org_named(result['filename']),
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
