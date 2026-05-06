"""
ROADtools wrapper for Intact's Azure pipeline.

Public repo: https://github.com/dirkjanm/ROADtools (MIT, ~3.6K stars,
maintained by Dirk-jan Mollema).

ROADtools enumerates the Entra ID directory and produces `roadrecon.db`,
a SQLite graph of users, groups, role assignments, applications, service
principals, OAuth permission grants, and devices. We use it for one
purpose: post-compromise BLAST RADIUS scoping.

For each finding, we ask:
  - For the actor (user who did the action): what apps do they own?
    What admin roles do they hold?
  - For the target (app or service principal that was modified): what
    permissions does it have? Who else can administer it?

The answers turn "user X compromised, app Y backdoored" into "user X
compromised — and X also owns 3 other apps and is a Privileged Role
Administrator. Y has Mail.ReadWrite tenant-wide, so the planted secret
allows mailbox read across the org."

Manual install (no install.sh hooks per Round 3 directive):
  docker pull dirkjanm/roadtools:latest
  mkdir -p /home/tenroot/intact/data/roadtools-cache

When the prereq is missing, `is_available()` returns a clear message and
the pipeline silently skips enrichment — no hard failure.
"""

import os
import sqlite3
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple


DOCKER_IMAGE = "dirkjanm/roadtools:latest"
CACHE_ROOT_HOST = "/home/tenroot/intact/data/roadtools-cache"  # for docker -v
CACHE_ROOT_CONTAINER = "/app/data/roadtools-cache"  # path inside backend
CERT_PATH_CONTAINER = "/app/data/azure_cert.pfx"
GRAPH_TTL_SECONDS = 24 * 60 * 60  # 24h cache TTL


def is_available() -> Dict:
    """Check whether ROADtools is installed and ready to run.

    Returns dict with `available` (bool) and `message` (str). Operator
    sees the message in the workflow log when prereq is missing.
    """
    result = {'available': False, 'has_image': False, 'has_cert': False, 'message': ''}

    try:
        check = subprocess.run(
            f"docker image inspect {DOCKER_IMAGE}",
            shell=True, capture_output=True, timeout=10,
        )
        result['has_image'] = check.returncode == 0
    except Exception:
        result['has_image'] = False

    result['has_cert'] = os.path.exists(CERT_PATH_CONTAINER)

    if not result['has_image']:
        result['message'] = (
            f"ROADtools image not installed. Run: docker pull {DOCKER_IMAGE} "
            f"(see docs/Round3_DFIR_Tools.md)"
        )
    elif not result['has_cert']:
        result['message'] = (
            f"Azure certificate not present at {CERT_PATH_CONTAINER}. "
            f"Required for cert-based auth — same cert DFIR-O365RC uses."
        )
    else:
        result['available'] = True
        result['message'] = 'ROADtools ready'
    return result


def cache_path(tenant_id: str) -> str:
    """Per-tenant cache file path inside the backend container."""
    safe = tenant_id.replace('/', '_').replace('..', '_')
    return os.path.join(CACHE_ROOT_CONTAINER, safe, 'roadrecon.db')


def cache_age_seconds(db_path: str) -> Optional[float]:
    """Return age of the cached graph in seconds, or None if missing."""
    try:
        mtime = os.path.getmtime(db_path)
        return time.time() - mtime
    except OSError:
        return None


def cache_is_fresh(db_path: str, ttl: int = GRAPH_TTL_SECONDS) -> bool:
    age = cache_age_seconds(db_path)
    return age is not None and age < ttl


def gather(
    tenant_id: str,
    app_id: str,
    log_func=None,
    force_refresh: bool = False,
) -> Optional[str]:
    """Build (or reuse) the tenant graph and return the cache path.

    Returns None on failure (logged via `log_func`); never raises so the
    caller can decide whether to skip enrichment or hard-fail.
    """
    log = log_func or (lambda msg, level="info": print(f"[ROAD] [{level}] {msg}", flush=True))

    avail = is_available()
    if not avail['available']:
        log(f"[ROAD] {avail['message']}", "warning")
        return None

    db_path = cache_path(tenant_id)

    if not force_refresh and cache_is_fresh(db_path):
        age_min = (cache_age_seconds(db_path) or 0) / 60.0
        log(f"[ROAD] Using cached graph ({age_min:.1f} min old, TTL 24h)")
        return db_path

    # Build (cold cache). Mount the per-tenant cache dir into the
    # roadtools container; it writes roadrecon.db there.
    safe = tenant_id.replace('/', '_').replace('..', '_')
    container_cache = os.path.join(CACHE_ROOT_CONTAINER, safe)
    host_cache = os.path.join(CACHE_ROOT_HOST, safe)
    try:
        os.makedirs(container_cache, exist_ok=True)
    except Exception as ex:
        log(f"[ROAD] Could not create cache dir {container_cache}: {ex}", "error")
        return None

    container_name = f"roadtools_{int(time.time())}"
    cmd = (
        f"docker run --rm --name {container_name} "
        f"-v {host_cache}:/work "
        f"-v /home/tenroot/intact/data:/cert:ro "
        f"-w /work "
        f"{DOCKER_IMAGE} "
        f"roadrecon gather "
        f"--auth-cert /cert/azure_cert.pfx "
        f"--client {app_id} "
        f"--tenant {tenant_id}"
    )
    log("[ROAD] Gathering tenant graph (cold cache, ~30-120s)...")
    try:
        t0 = time.time()
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=600,
        )
        elapsed = time.time() - t0
        if proc.returncode != 0:
            log(
                f"[ROAD] gather failed (exit {proc.returncode}): "
                f"{(proc.stderr or proc.stdout or '')[:500]}",
                "warning",
            )
            return None
        if not os.path.exists(db_path):
            log(f"[ROAD] gather succeeded but {db_path} not found", "warning")
            return None

        # Quick stats so the operator sees what got built
        try:
            stats = _graph_stats(db_path)
            log(
                f"[ROAD] Graph built in {elapsed:.1f}s: "
                f"{stats.get('users', '?')} users, "
                f"{stats.get('applications', '?')} apps, "
                f"{stats.get('serviceprincipals', '?')} SPs, "
                f"{stats.get('directoryroles', '?')} roles "
                f"-> cached for 24h"
            )
        except Exception:
            log(f"[ROAD] Graph built in {elapsed:.1f}s -> cached for 24h")

        return db_path
    except subprocess.TimeoutExpired:
        log("[ROAD] gather timed out (>10min)", "warning")
        try:
            subprocess.run(f"docker rm -f {container_name}", shell=True, timeout=10)
        except Exception:
            pass
        return None
    except Exception as ex:
        log(f"[ROAD] gather raised: {ex}", "warning")
        return None


# =============================================================================
# Direct SQLite queries (faster than shelling to `roadrecon dump`)
# =============================================================================

def _graph_stats(db_path: str) -> Dict[str, int]:
    """Quick row-count summary for the workflow log line."""
    out = {}
    try:
        con = sqlite3.connect(db_path)
        for table in ('users', 'applications', 'serviceprincipals', 'directoryroles'):
            try:
                row = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                if row:
                    out[table] = int(row[0])
            except sqlite3.OperationalError:
                pass
        con.close()
    except Exception:
        pass
    return out


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    try:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return bool(row)
    except Exception:
        return False


def _safe_select(con: sqlite3.Connection, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
    """Run a SELECT, returning [] on any schema mismatch.

    ROADtools' schema can shift between releases. Querying defensively
    means a future schema change degrades to "no enrichment" instead of
    crashing the pipeline.
    """
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError as ex:
        # Log but don't raise — schema mismatch is recoverable
        print(f"[ROAD] query degraded ({ex})", flush=True)
        return []


def query_blast_radius(
    db_path: str,
    actor_upns: List[str],
    target_app_ids: List[str],
    target_app_object_ids: Optional[List[str]] = None,
) -> Dict:
    """Compute blast-radius facts for a set of actors and targets.

    Returns dict shape:
    {
      "actors": {
        "<upn>": {
          "owns_apps": [{"appId": "...", "displayName": "..."}],
          "role_memberships": ["Global Administrator", ...],
        },
      },
      "targets": {
        "<appId or objectId>": {
          "displayName": "...",
          "permissions": [{"resource": "Microsoft Graph", "scope": "Mail.ReadWrite", "type": "Role"}],
          "other_owners": ["other_user@..."],
        },
      },
      "summary": {
        "actors_with_role": int,
        "targets_with_high_risk_perm": int,
      }
    }

    Best-effort: missing tables / unknown UPNs / unknown appIds yield
    empty entries instead of failures.
    """
    out = {"actors": {}, "targets": {}, "summary": {"actors_with_role": 0, "targets_with_high_risk_perm": 0}}

    if not os.path.exists(db_path):
        return out

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        # ---- Actors ----
        for upn in (actor_upns or []):
            if not upn:
                continue
            entry = {"owns_apps": [], "role_memberships": []}

            # User objectId for joins
            user_rows = _safe_select(
                con,
                "SELECT objectId FROM users WHERE userPrincipalName = ? COLLATE NOCASE LIMIT 1",
                (upn,),
            )
            if not user_rows:
                out["actors"][upn] = entry
                continue
            user_oid = user_rows[0]["objectId"]

            # Apps owned by the user. ROADtools stores ownership via the
            # `owner` relationship on Applications; the join table name
            # has shifted across versions, try a few. Each attempt is
            # defensive.
            for join_table, app_table in (
                ("Application_owner", "Applications"),  # newer
                ("application_owner", "applications"),  # older lower
                ("applications_owner", "applications"),
            ):
                if _table_exists(con, join_table):
                    rows = _safe_select(
                        con,
                        f"SELECT a.appId, a.displayName FROM {app_table} a "
                        f"JOIN {join_table} ao ON ao.Application = a.objectId "
                        f"WHERE ao.User = ?",
                        (user_oid,),
                    )
                    for r in rows:
                        entry["owns_apps"].append({
                            "appId": r["appId"], "displayName": r["displayName"],
                        })
                    if rows:
                        break

            # Role memberships — DirectoryRole has a member relationship
            for role_join, role_table in (
                ("DirectoryRole_member", "DirectoryRoles"),
                ("directoryrole_member", "directoryroles"),
            ):
                if _table_exists(con, role_join):
                    rows = _safe_select(
                        con,
                        f"SELECT r.displayName FROM {role_table} r "
                        f"JOIN {role_join} rm ON rm.DirectoryRole = r.objectId "
                        f"WHERE rm.User = ?",
                        (user_oid,),
                    )
                    for r in rows:
                        if r["displayName"]:
                            entry["role_memberships"].append(r["displayName"])
                    if rows:
                        break

            if entry["role_memberships"]:
                out["summary"]["actors_with_role"] += 1
            out["actors"][upn] = entry

        # ---- Targets (apps / SPs) ----
        # Accept either appId or objectId since findings come with both shapes
        target_keys: Set[str] = set()
        for k in (target_app_ids or []):
            if k:
                target_keys.add(k)
        for k in (target_app_object_ids or []):
            if k:
                target_keys.add(k)

        for key in target_keys:
            entry = {
                "displayName": "",
                "permissions": [],
                "other_owners": [],
            }
            # Resolve to objectId if caller gave us appId
            app_rows = _safe_select(
                con,
                "SELECT objectId, appId, displayName FROM Applications "
                "WHERE appId = ? OR objectId = ? LIMIT 1",
                (key, key),
            ) or _safe_select(
                con,
                "SELECT objectId, appId, displayName FROM applications "
                "WHERE appId = ? OR objectId = ? LIMIT 1",
                (key, key),
            )
            if app_rows:
                app_oid = app_rows[0]["objectId"]
                entry["displayName"] = app_rows[0]["displayName"] or ""

                # Required resource access (what permissions the app holds)
                # Stored as JSON in `requiredResourceAccess` column
                rra_rows = _safe_select(
                    con,
                    "SELECT requiredResourceAccess FROM Applications WHERE objectId = ?",
                    (app_oid,),
                ) or _safe_select(
                    con,
                    "SELECT requiredResourceAccess FROM applications WHERE objectId = ?",
                    (app_oid,),
                )
                if rra_rows:
                    raw = rra_rows[0]["requiredResourceAccess"]
                    entry["permissions"] = _parse_required_resource_access(raw, con)

                # Other owners
                for join_table, user_table in (
                    ("Application_owner", "users"),
                    ("application_owner", "users"),
                    ("applications_owner", "users"),
                ):
                    if _table_exists(con, join_table):
                        rows = _safe_select(
                            con,
                            f"SELECT u.userPrincipalName FROM {user_table} u "
                            f"JOIN {join_table} ao ON ao.User = u.objectId "
                            f"WHERE ao.Application = ?",
                            (app_oid,),
                        )
                        entry["other_owners"] = [
                            r["userPrincipalName"] for r in rows if r["userPrincipalName"]
                        ]
                        if rows:
                            break

            # Heuristic: if any permission contains "ReadWrite", "FullControl",
            # or covers Mail/Files at directory scope, mark as high-risk
            for p in entry["permissions"]:
                scope = (p.get("scope") or "").lower()
                if any(t in scope for t in ('readwrite', 'fullcontrol', 'mail.', 'files.', 'directory.', 'application.')):
                    out["summary"]["targets_with_high_risk_perm"] += 1
                    break

            out["targets"][key] = entry
    finally:
        con.close()

    return out


# Microsoft Graph well-known appId — used to translate Graph permission GUIDs
# into human names. Stored locally so we don't need a network call.
_MSGRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def _parse_required_resource_access(raw, con: sqlite3.Connection) -> List[Dict]:
    """Parse the requiredResourceAccess JSON blob into a flat permission list.

    Each entry of the JSON looks like:
      {"resourceAppId": "<guid>",
       "resourceAccess": [{"id": "<perm-guid>", "type": "Role" | "Scope"}, ...]}

    We resolve resourceAppId to a service principal name (via SP table) and
    permission GUIDs to permission names (via SP appRoles / oauth2Permissions).
    """
    if not raw:
        return []
    import json as _json
    try:
        rra = _json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    if not isinstance(rra, list):
        return []

    out = []
    for block in rra:
        if not isinstance(block, dict):
            continue
        resource_app_id = block.get('resourceAppId') or ''
        # Look up the resource SP
        resource_name = resource_app_id
        sp_rows = _safe_select(
            con,
            "SELECT displayName, appRoles, oauth2Permissions FROM ServicePrincipals "
            "WHERE appId = ? LIMIT 1",
            (resource_app_id,),
        ) or _safe_select(
            con,
            "SELECT displayName, appRoles, oauth2Permissions FROM serviceprincipals "
            "WHERE appId = ? LIMIT 1",
            (resource_app_id,),
        )
        app_roles = []
        oauth_scopes = []
        if sp_rows:
            resource_name = sp_rows[0]["displayName"] or resource_app_id
            try:
                app_roles = _json.loads(sp_rows[0]["appRoles"] or "[]")
            except Exception:
                app_roles = []
            try:
                oauth_scopes = _json.loads(sp_rows[0]["oauth2Permissions"] or "[]")
            except Exception:
                oauth_scopes = []

        for ra in block.get('resourceAccess', []) or []:
            if not isinstance(ra, dict):
                continue
            perm_id = ra.get('id') or ''
            perm_type = ra.get('type') or ''
            scope_name = perm_id  # fallback to GUID if name lookup fails
            # Roles (application permissions) live in appRoles
            if perm_type == 'Role':
                for ar in app_roles:
                    if isinstance(ar, dict) and ar.get('id') == perm_id:
                        scope_name = ar.get('value') or perm_id
                        break
            # Scopes (delegated) live in oauth2Permissions
            elif perm_type == 'Scope':
                for op in oauth_scopes:
                    if isinstance(op, dict) and op.get('id') == perm_id:
                        scope_name = op.get('value') or perm_id
                        break
            out.append({
                "resource": resource_name,
                "scope": scope_name,
                "type": perm_type,
            })
    return out
