#!/usr/bin/env python3
"""Velociraptor accounts for Intact users (provider contract: __init__.py).

nginx injects `Authorization: Basic user:password`; Velociraptor 0.77.4 takes
it on the GUI and API with no login prompt (docs/PLAN_multi_user_accounts.md
section 6). Accounts are made over the backend's gRPC API user with VQL.

Checked on 0.77.4 with a throwaway user:
- user_create(orgs=[...]) creates or updates the user, sets the password and
  REPLACES its roles in every org listed (administrator added by hand is gone
  after the next call), so one query does the whole ensure.
- user_grant(policy=dict(), orgs=[...]) removes the user from those orgs;
  afterwards Basic gets 403 "No access to org", a wrong password 401.
- an unknown role name in user_grant silently drops the user from that org,
  hence the role allowlist below.
- user_grant(user=, roles=, orgs=[...]) REPLACES the roles in those orgs too.

Velociraptor logs every API query in full ("Query API call", "Query: Running"),
and the backend's gRPC client can only send VQL, so a password set here lands in
Velociraptor's own log, readable by root and Velociraptor administrators (the
Super-admin). So it is set only when it is new -- the account is created or
re-enabled -- and every other pass uses user_grant, which carries none.
"""

import base64
import json
import re
import secrets

from services import velo_org
from services.velociraptor_clients import _query, org_list

TOOL = "velociraptor"
NEEDS_PASSWORD = True


def _reserved():
    """The install's own users: the API user and the GUI admin from config.yaml
    (the names lib/config.sh writes to VELOX_USER_2 / VELOX_USER), plus 'admin'."""
    try:
        from config import load_main_config
        velo = ((load_main_config() or {}).get("modules") or {}).get("velociraptor") or {}
    except Exception:                       # noqa: BLE001 -- no config: the defaults
        velo = {}
    return {str(velo.get("id") or "tenroot").strip().lower(),
            str(velo.get("api_id") or "api").strip().lower(), "admin"}


RESERVED = _reserved()

# Admin/Operator never get administrator: a Velociraptor administrator can reset
# any user's password, the Super-admin's included.
_ROLES = {
    "superadmin": ("administrator",),
    "admin": ("investigator", "artifact_writer"),
    "operator": ("investigator", "artifact_writer"),
}
_KNOWN_ROLES = {"administrator", "investigator", "artifact_writer"}

# Every value below goes inside a VQL '...' literal; execute_vql has no env
# parameters, so the charset is the guarantee: none of these can hold a quote.
_USER_RE = re.compile(r"^[a-z0-9._-]{1,64}$")
_PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")      # token_urlsafe
_ORG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def tool_role(intact_role):
    roles = _ROLES.get(intact_role)
    return list(roles) if roles else None


def _check_user(tool_user):
    if not isinstance(tool_user, str) or not _USER_RE.match(tool_user):
        raise ValueError("invalid Velociraptor user name")


def _check_password(password):
    if not isinstance(password, str) or not _PASSWORD_RE.match(password):
        # Never echo the value: it is a credential.
        raise ValueError("invalid Velociraptor password (expected urlsafe base64)")


def _orgs():
    """Every org id, root included: each case is an org and users open
    Velociraptor in the case's org."""
    ids = [o for o, _ in org_list()]
    bad = [o for o in ids if not _ORG_RE.match(o)]
    if bad:
        raise ValueError(f"unexpected Velociraptor org id(s): {bad!r}")
    return ids


def _exists(tool_user):
    return bool((_query(f"SELECT user(user='{tool_user}') AS u FROM scope()", timeout=30) or [{}])[0].get("u"))


def ensure(tool_user, password, roles, set_password=True):
    _check_user(tool_user)
    _check_password(password)
    if not roles or not set(roles) <= _KNOWN_ROLES:
        raise ValueError(f"invalid Velociraptor roles: {roles!r}")
    with velo_org.root():
        orgs = json.dumps(_orgs())
        if set_password or not _exists(tool_user):
            _query(f"SELECT user_create(user='{tool_user}', roles={json.dumps(list(roles))}, "
                   f"password='{password}', orgs={orgs}) AS r FROM scope()", timeout=60)
        else:
            _query(f"SELECT user_grant(user='{tool_user}', roles={json.dumps(list(roles))}, "
                   f"orgs={orgs}) AS r FROM scope()", timeout=60)


def disable(tool_user):
    """No disable flag in Velociraptor: drop every org membership and set a
    password nobody knows. Not deleted -- past collections carry the name."""
    _check_user(tool_user)
    with velo_org.root():
        if not _exists(tool_user):
            return
        # user_create only to change the password (it needs a role; the grant
        # below removes it again straight away).
        _query(f"SELECT user_create(user='{tool_user}', roles=['reader'], "
               f"password='{secrets.token_urlsafe(32)}', orgs=['root']) AS r FROM scope()", timeout=60)
        _query(f"SELECT user_grant(user='{tool_user}', policy=dict(), "
               f"orgs={json.dumps(_orgs())}) AS r FROM scope()", timeout=60)


def auth_value(tool_user, password):
    if not password:
        return None
    return "Basic " + base64.b64encode(f"{tool_user}:{password}".encode()).decode()
