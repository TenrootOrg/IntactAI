#!/usr/bin/env python3
"""Kibana / Elasticsearch provider: one native-realm user per Intact user.

nginx injects `Authorization: Basic` for that user (docs/PLAN_multi_user_accounts.md
section 6: Kibana accepts it and makes no session). Kibana checks every request
against Elasticsearch with the user's own privileges, Dev Tools included, so
the two roles below are the real boundary, not Kibana's UI.

Neither role carries any security privilege: an Admin's Kibana user must not be
able to edit the Super-admin's, and API keys would outlive a disabled user.
"""

import base64
from urllib.parse import quote

import requests

TOOL = "kibana"
NEEDS_PASSWORD = True
TIMEOUT = 10

# Built-in users of the ELK stack; the configured backend user is added below.
_BUILTIN = {"elastic", "kibana_system", "kibana", "logstash_system", "beats_system",
            "apm_system", "remote_monitoring_user"}


def _config():
    from config import ELASTICSEARCH_CONFIG     # late: an upgrade provisions it after we import
    return ELASTICSEARCH_CONFIG


def _reserved():
    try:
        return _BUILTIN | {(_config().get("user") or "").strip().lower()} - {""}
    except Exception:                       # noqa: BLE001 -- no config yet: the static set still holds
        return set(_BUILTIN)


RESERVED = _reserved()

_KIBANA_ALL = [{"application": "kibana-.kibana", "privileges": ["all"], "resources": ["*"]}]
# read: search, Discover, dashboards, ES|QL. view_index_metadata: field caps and
# _resolve/index, which data views and the index picker need. `*` also covers
# data streams and their .ds- backing indices; restricted ones (.security) stay out.
_READ_ALL = {"names": ["*"], "privileges": ["read", "view_index_metadata"],
             "allow_restricted_indices": False}

ROLES = {
    "intact_member": {
        "cluster": [],
        "indices": [_READ_ALL],
        "applications": _KIBANA_ALL,
        "metadata": {"intact": True},
    },
    "intact_superadmin": {
        # Stack Management short of Security. monitor: cluster/node stats, Index
        # Management and Stack Monitoring pages. manage_index_templates: index and
        # component templates. manage_ilm: lifecycle policies (disk on the box).
        # manage_ingest_pipelines: Ingest Pipelines page.
        "cluster": ["monitor", "manage_index_templates", "manage_ilm", "manage_ingest_pipelines"],
        # manage on indices: settings, mappings, rollover, close/delete from Index
        # Management. The Super-admin is already root on the host.
        "indices": [_READ_ALL, {"names": ["*"], "privileges": ["manage"],
                                "allow_restricted_indices": False}],
        "applications": _KIBANA_ALL,
        "metadata": {"intact": True},
    },
}

_ROLE_FOR = {"superadmin": "intact_superadmin", "admin": "intact_member", "operator": "intact_member"}


def tool_role(intact_role):
    return _ROLE_FOR.get(intact_role)


def _es(method, path, body=None, ok=(200,)):
    """One call with the backend's admin user. Raises on any other status; the
    message carries ES's error, never the request body (it holds the password)."""
    c = _config()
    r = requests.request(method, f"http://{c['host']}:{c['port']}{path}", json=body,
                         auth=(c.get("user") or "elastic", c.get("password") or ""),
                         timeout=TIMEOUT)
    if r.status_code not in ok:
        raise RuntimeError(f"Elasticsearch {method} {path}: HTTP {r.status_code} {r.text[:200]}")
    return r


def ensure(tool_user, password, tool_role, set_password=True):
    if tool_role not in ROLES:
        raise ValueError(f"unknown Kibana role {tool_role!r}")
    if not password:
        raise ValueError("Kibana accounts need a password")
    for name, body in ROLES.items():        # every pass: a role edited by hand is put back
        _es("PUT", f"/_security/role/{name}", body)
    found = _es("GET", f"/_security/user/{quote(tool_user, safe='')}", ok=(200, 404))
    current = (found.json().get(tool_user) or {}) if found.status_code == 200 else None
    if current is not None:
        meta = current.get("metadata") or {}
        if not meta.get("intact"):
            # Someone made this account by hand: taking it over would hand its
            # owner's login to an Intact user.
            raise RuntimeError(f"Elasticsearch user {tool_user!r} exists and is not Intact's")
    if current is not None and current.get("roles") != [tool_role]:
        # Kibana's alerting rules run on API keys holding a frozen copy of the
        # owner's old roles: a demoted user's rules must not keep them.
        _es("DELETE", "/_security/api_key", {"username": tool_user}, ok=(200, 404))
    # PUT sets roles and enabled together, so it also reverts drift. The password
    # only when it is new (an existing user keeps its own without the field).
    body = {"roles": [tool_role], "full_name": f"{tool_user} (Intact)",
            "metadata": {"intact": True}, "enabled": True}
    if set_password or current is None:
        body["password"] = password
    _es("PUT", f"/_security/user/{quote(tool_user, safe='')}", body)


def disable(tool_user):
    path = f"/_security/user/{quote(tool_user, safe='')}"
    # Checked first: ES answers _disable of a missing user with a 400, not a 404.
    if _es("GET", path, ok=(200, 404)).status_code == 200:
        _es("PUT", path + "/_disable")
        # Kibana runs a user's alerting rules on API keys it granted for them;
        # they would keep running after the person is disabled.
        _es("DELETE", "/_security/api_key", {"username": tool_user}, ok=(200, 404))


def auth_value(tool_user, password):
    if not password:
        return None
    return "Basic " + base64.b64encode(f"{tool_user}:{password}".encode()).decode()
