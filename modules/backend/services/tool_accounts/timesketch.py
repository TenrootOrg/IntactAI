#!/usr/bin/env python3
"""Timesketch accounts for Intact users (provider; see __init__.py).

Way in: header SSO, no password. nginx puts the user name into
`X-Intact-User-<per-box secret>` (lib/modules/timesketch.sh _ts_render_sso) and
Timesketch's /login/ gets-or-creates that user. So ensure() only has to fix
what SSO does not: the admin flag, membership of `intact-team`, and that group's
read+write on every sketch -- the backend creates the case sketches as its API
user, and without the grant an Operator would see none of them.

Timesketch 20261014 never checks `User.active` (UserMixin.is_active is always
True, load_user ignores it), so disable() also takes the admin flag and the
group away: what keeps a disabled user out is the nginx gate plus losing those.

All of it runs as ONE `docker exec ... python3 -` inside intact_timesketch_web,
in the app context tsctl itself uses. Measured on the dev box: ~6 s per call,
against ~11 s for each tsctl call (create_app dominates both), and ensure()
would need six of them.
"""

import json
import re
import subprocess

import config
from services.users import ADMIN, OPERATOR, SUPERADMIN

TOOL = "timesketch"
NEEDS_PASSWORD = False
CONTAINER = "intact_timesketch_web"
GROUP = "intact-team"
TIMEOUT_SECONDS = 120
_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9._-]{0,63}$")   # the Intact user-name rule


def _reserved():
    # The install's own admin (config.yaml modules.timesketch.id) and the
    # backend's API user: an Intact user of that name must not take them over.
    try:
        ts = (config.load_main_config() or {}).get("modules", {}).get("timesketch", {}) or {}
        admin = str(ts.get("id") or "").strip().lower() or "tenroot"
    except Exception:                       # noqa: BLE001 -- unreadable config: the default
        admin = "tenroot"
    api = str(config.TIMESKETCH_CONFIG.get("username") or "").strip().lower()
    return frozenset(n for n in (admin, api) if n)


RESERVED = _reserved()

# Runs inside the Timesketch container. argv: op, user, role, group.
_SCRIPT = r'''
import json, sys
from timesketch.app import create_app
from timesketch.models import db_session
from timesketch.models.sketch import Sketch
from timesketch.models.user import Group, User

op, name, role, group_name = sys.argv[1:5]
out = {"created": False, "granted": 0, "sketches": 0}
with create_app().app_context():
    user = User.query.filter_by(username=name).first()
    group = Group.query.filter_by(name=group_name).first()
    if op == "ensure":
        if user is None:
            user = User(username=name, name=name)
            db_session.add(user)
            out["created"] = True
        # SSO looks the user up by username AND name; a renamed one would make
        # it insert a duplicate username and fail the login.
        user.name = name
        user.active = True
        user.admin = role == "admin"
        if group is None:
            group = Group(name=group_name, display_name=group_name)
            db_session.add(group)
        if group not in user.groups:
            user.groups.append(group)
        db_session.commit()
        # read+write is what a collaborator needs to add timelines, comment and
        # label events (tsctl grant-group's default); delete stays the owner's.
        # grant_permission's own body, with one commit for all sketches
        # instead of one per entry.
        for sketch in Sketch.query.all():
            out["sketches"] += 1
            for perm in ("read", "write"):
                if not sketch._get_ace(perm, group=group):
                    sketch.acl.append(sketch.AccessControlEntry(permission=perm, group=group))
                    out["granted"] += 1
        db_session.commit()
    elif op == "disable" and user is not None:
        user.active = False
        user.admin = False
        if group is not None and group in user.groups:
            user.groups.remove(group)
        db_session.commit()
    out["exists"] = user is not None
    out["admin"] = bool(user is not None and user.admin)
    out["in_group"] = bool(user is not None and group is not None and group in user.groups)
print("INTACT-RESULT " + json.dumps(out))
'''


def _run(op: str, tool_user: str, role: str = "") -> dict:
    if not _NAME_RE.match(tool_user or ""):
        raise ValueError(f"not a valid Timesketch user name: {tool_user!r}")
    # argv list, no shell: the name reaches python3 as sys.argv, never parsed.
    proc = subprocess.run(["docker", "exec", "-i", CONTAINER, "python3", "-", op, tool_user, role, GROUP],
                          input=_SCRIPT, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("INTACT-RESULT "):
            return json.loads(line[len("INTACT-RESULT "):])
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
    raise RuntimeError(f"timesketch {op} failed (rc {proc.returncode}): {tail[0][:200]}")


def tool_role(intact_role: str):
    if intact_role in (SUPERADMIN, ADMIN):
        return "admin"
    if intact_role == OPERATOR:
        return "user"
    return None


def ensure(tool_user: str, password, role: str, set_password: bool = True) -> dict:
    if role not in ("admin", "user"):
        raise ValueError(f"unknown Timesketch role: {role!r}")
    return _run("ensure", tool_user, role)


def disable(tool_user: str) -> dict:
    return _run("disable", tool_user)


def auth_value(tool_user: str, password):
    return tool_user                        # nginx puts it into the secret-named header
