#!/usr/bin/env python3
"""VolWeb provider: one Django user per Intact user, inside intact_volweb_backend.

Users go through VolWeb's own ORM (`manage.py shell`), the way the installer's
seed_volweb_admin does: VolWeb has no user-management API. nginx replaces the
SPA's `Authorization: Bearer` with auth_value()'s token on every request, so
whatever an earlier user left in localStorage is never used.

VolWeb has no read-only role (a non-superuser sees only cases linked to it,
and can still write), so Read-only gets no account.
"""

import os
import subprocess
import threading
import time
from typing import Dict, Optional, Tuple

import requests

from services.memory.volweb_client import _config_yaml_volweb, _volweb_base

TOOL = "volweb"
NEEDS_PASSWORD = True
# The install admin (seed_volweb_admin) plus VolWeb's upstream admin/user,
# which the installer locks: an Intact user named like one gets "<name>-intact".
RESERVED = {(_config_yaml_volweb("id") or "tenroot").strip().lower(), "admin", "user"}

CONTAINER = "intact_volweb_backend"
TOKEN_TTL = 8 * 60          # SimpleJWT access lives 10 min: never hand nginx one about to die
HTTP_TIMEOUT = 3            # nginx's auth_request waits on this
EXEC_TIMEOUT = 60
# A failed login is remembered this long: with VolWeb down, every VolWeb request's
# auth_request would otherwise wait HTTP_TIMEOUT for the same failure.
FAIL_TTL = 30

_cache: Dict[str, Tuple[str, str, float]] = {}   # tool_user -> (password, token, expires)
_cache_lock = threading.Lock()


def tool_role(intact_role: str) -> Optional[str]:
    return "superuser" if intact_role in ("superadmin", "admin", "operator") else None


def _shell(script: str, **env: str) -> str:
    """Run `script` in VolWeb's Django shell. Values travel as -e NAME with the
    value in docker's own environment: never in argv (ps) or the script text."""
    names = {f"_VW_{k.upper()}": v for k, v in env.items()}
    cmd = ["docker", "exec", "--user", "app", "-w", "/home/app/web", "-i"]
    for n in names:
        cmd += ["-e", n]
    cmd += [CONTAINER, "python3", "manage.py", "shell"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True,
                       timeout=EXEC_TIMEOUT, env={**os.environ, **names})
    if r.returncode != 0 or "VW_OK" not in r.stdout:
        raise RuntimeError(f"volweb shell rc={r.returncode}: {(r.stderr or r.stdout).strip()[-300:]}")
    return r.stdout


_ENSURE = """
import os
from django.contrib.auth import get_user_model
U = get_user_model()
u, created = U.objects.get_or_create(username=os.environ['_VW_USER'])
su = os.environ['_VW_ROLE'] == 'superuser'
u.is_active, u.is_superuser, u.is_staff = True, su, su
if created or os.environ['_VW_SETPW'] == '1':
    u.set_password(os.environ['_VW_PASSWORD'])
u.save()
print('VW_OK')
"""

# Not deleted: cases link to their users. Blacklisting the outstanding refresh
# tokens stops a token issued before from being rotated into new ones;
# CHECK_USER_IS_ACTIVE already refuses its live access tokens.
_DISABLE = """
import os
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
u = get_user_model().objects.filter(username=os.environ['_VW_USER']).first()
if u:
    u.is_active = False
    u.set_unusable_password()
    u.save()
    for t in OutstandingToken.objects.filter(user=u):
        BlacklistedToken.objects.get_or_create(token=t)
print('VW_OK')
"""


def ensure(tool_user: str, password: str, role: str, set_password: bool = True) -> None:
    _shell(_ENSURE, user=tool_user, password=password, role=role,
           setpw="1" if set_password else "0")


def disable(tool_user: str) -> None:
    forget(tool_user)
    _shell(_DISABLE, user=tool_user)


def forget(tool_user: str) -> None:
    with _cache_lock:
        _cache.pop(tool_user, None)


def auth_value(tool_user: str, password: Optional[str]) -> Optional[str]:
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(tool_user)
    # A new password (re-enabled user) means the cached token is for the old one.
    if hit and hit[0] == password and hit[2] > now:
        return f"Bearer {hit[1]}" if hit[1] else None
    try:
        # Host: Django rejects the underscored container name (see volweb_client._headers).
        r = requests.post(f"{_volweb_base()}/core/token/",
                          json={"username": tool_user, "password": password},
                          headers={"Host": "localhost"}, timeout=HTTP_TIMEOUT)
        token = r.json().get("access") if r.status_code == 200 else None
    except Exception:                       # noqa: BLE001 -- VolWeb down: the SPA shows its login
        token = None
    if not token:
        with _cache_lock:
            _cache[tool_user] = (password, None, now + FAIL_TTL)
        return None
    with _cache_lock:
        _cache[tool_user] = (password, token, now + TOKEN_TTL)
    return f"Bearer {token}"


def after_pass() -> None:
    """Once per reconciler pass: every token login (one per user per TOKEN_TTL)
    leaves an OutstandingToken row that nothing else ever deletes."""
    r = subprocess.run(["docker", "exec", "--user", "app", "-w", "/home/app/web", CONTAINER,
                        "python3", "manage.py", "flushexpiredtokens"],
                       capture_output=True, text=True, timeout=EXEC_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"flushexpiredtokens rc={r.returncode}: {(r.stderr or '').strip()[-200:]}")
