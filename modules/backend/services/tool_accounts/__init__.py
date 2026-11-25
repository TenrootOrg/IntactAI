#!/usr/bin/env python3
"""Per-user accounts inside the bundled tools, kept in step with the dashboard.

The dashboard is the only login (docs/PLAN_multi_user_accounts.md). For every
Intact user whose role may open a tool, the tool holds a matching account with
a generated password nobody types; nginx's per-tool auth_request asks the
backend (routes/auth_routes.auth_verify) and injects that user's credential
(`X-Intact-Auth`), so the person lands in the tool already signed in.

One reconciler, not one-shot provisioning: reconcile_all() makes every tool
match the users table -- create, re-role, re-password, disable -- and so also
repairs a wiped tool volume, a restored DB, a new Velociraptor org, and a role
somebody raised by hand inside a tool (drift). It runs at boot, after every
users-table write, and nightly, on one background thread.

A provider is a module in this package exposing (see kibana.py etc.):

    TOOL            the access_policy.TOOLS name ("kibana")
    NEEDS_PASSWORD  True when the tool account has a password we generate
    RESERVED        tool user names already used by the install (service and
                    break-glass accounts); an Intact user with such a name gets
                    "<name>-intact" in that tool instead
    tool_role(intact_role) -> str | None     None: no account for that role
    ensure(tool_user, password, tool_role, set_password=True)
                    create or update, enabled; idempotent. set_password False:
                    the account already works with `password` -- keep it,
                    do not send it again (Velociraptor logs it)
    disable(tool_user)                       idempotent, a missing user is fine
    auth_value(tool_user, password) -> str | None
                    what nginx injects (a whole "Basic ..."/"Bearer ..." header
                    value, or the user name for Timesketch's header SSO); may be
                    cached by the provider, must return within ~3 s
    after_pass()    optional, once per reconciler pass (tool housekeeping)

Providers run against the live tools through the backend's existing service
credentials. They never log a password.
"""

import importlib
import secrets
import threading
import time
from typing import Dict, Optional

from services import users
from services.tool_accounts import vault

PROVIDER_MODULES = ("kibana", "velociraptor", "timesketch", "volweb")
NIGHTLY_SECONDS = 24 * 3600
# After a pass with errors (a tool still starting after a reboot or an upgrade,
# which recreates the backend minutes before the tools come back): retry soon,
# backing off, instead of leaving people without sign-in until the night.
RETRY_SECONDS = (120, 300, 900, 1800, 3600)
BOOT_DELAY_SECONDS = 60          # let the tools come up after a box restart
DEBOUNCE_SECONDS = 3             # a burst of user edits -> one pass

_providers: Optional[Dict[str, object]] = None
_wake = threading.Event()
_started = False
_run_lock = threading.Lock()
_last_run: Dict[str, object] = {"at": None, "seconds": None, "errors": 0}


def providers() -> Dict[str, object]:
    """{tool: module} for every provider that imports. One that fails to import
    is skipped (and logged), so a broken tool never blocks the others."""
    global _providers
    if _providers is None:
        found = {}
        for name in PROVIDER_MODULES:
            try:
                mod = importlib.import_module(f"services.tool_accounts.{name}")
                found[mod.TOOL] = mod
            except Exception as exc:        # noqa: BLE001
                print(f"[TOOL-ACCOUNTS] provider {name} unavailable: {exc}", flush=True)
        _providers = found
    return _providers


def tool_user_for(provider, username: str) -> str:
    name = username.strip().lower()
    return f"{name}-intact" if name in getattr(provider, "RESERVED", ()) else name


def _new_password() -> str:
    return secrets.token_urlsafe(32)        # ~256 bits: nothing to brute-force


def reconcile_user(row: dict) -> Dict[str, str]:
    """Bring one Intact user's account in every tool to its desired state.
    Returns {tool: "ok" | "disabled" | "none" | "error: ..."}."""
    out = {}
    for tool, prov in providers().items():
        username = row["username"]
        stored = vault.get(username, tool)
        tool_user = stored["tool_user"] if stored else tool_user_for(prov, username)
        role = prov.tool_role(row["role"]) if row["enabled"] else None
        try:
            if role is None:
                if stored:
                    prov.disable(tool_user)
                    # A re-enabled user gets a fresh password, never the old one.
                    vault.forget(username, tool)
                out[tool] = "disabled" if stored else "none"
                continue
            password = (stored or {}).get("password") if prov.NEEDS_PASSWORD else None
            if prov.NEEDS_PASSWORD and not password:
                password = _new_password()
            working = bool(stored) and stored.get("state") == "ok" and \
                (password == stored.get("password"))
            if not working:
                # Store BEFORE setting it in the tool: a crash in between leaves
                # a password we can set again, never an account nobody can use.
                vault.put(username, tool, tool_user, password, state="pending")
            # A working account stays "ok" while it is re-checked: the verify
            # injects nothing for a row that is not ok, so flipping every row
            # to pending on each pass would blank everyone's sign-in meanwhile.
            prov.ensure(tool_user, password, role, set_password=not working)
            vault.mark(username, tool, "ok", None)
            out[tool] = "ok"
        except Exception as exc:            # noqa: BLE001
            msg = f"{type(exc).__name__}: {str(exc)[:200]}"
            # A re-check of a working account that fails (the tool is down) does
            # not take that account away: its password still works there.
            state = "ok" if (stored and stored.get("state") == "ok") else "error"
            vault.mark(username, tool, state, msg)
            print(f"[TOOL-ACCOUNTS] {tool} / {username}: {msg}", flush=True)
            out[tool] = "error: " + msg
    return out


def reconcile_all() -> Dict[str, Dict[str, str]]:
    """Every user, every tool. Serialised: two passes never run at once."""
    with _run_lock:
        started = time.monotonic()
        users.invalidate()
        rows = list(users._load().values())     # noqa: SLF001 -- the table, not the public view
        result = {r["username"]: reconcile_user(r) for r in rows}
        # Vault rows of users that no longer exist (a restored older DB): the
        # tool account goes too.
        known = {r["username"] for r in rows}
        for username, tool, tool_user in vault.all_keys():
            if username not in known and tool in providers():
                try:
                    providers()[tool].disable(tool_user)
                    vault.forget(username, tool)
                except Exception as exc:    # noqa: BLE001
                    print(f"[TOOL-ACCOUNTS] {tool} / {username} (removed user): {exc}", flush=True)
        for tool, prov in providers().items():
            hook = getattr(prov, "after_pass", None)     # optional: tool housekeeping
            if hook:
                try:
                    hook()
                except Exception as exc:    # noqa: BLE001
                    print(f"[TOOL-ACCOUNTS] {tool} housekeeping: {exc}", flush=True)
        errors = sum(1 for r in result.values() for v in r.values() if v.startswith("error"))
        _last_run.update(at=time.time(), seconds=round(time.monotonic() - started, 1), errors=errors)
        print(f"[TOOL-ACCOUNTS] pass done in {_last_run['seconds']}s, {len(rows)} user(s), "
              f"{errors} error(s)", flush=True)
        return result


def auth_value(row: dict, tool: str) -> Optional[str]:
    """What nginx injects for this user in this tool, or None (nginx then sends
    no credential at all and the tool shows its own login)."""
    prov = providers().get(tool)
    if prov is None or not row:
        return None
    try:
        stored = vault.get(row["username"], tool)
        if not stored or stored.get("state") != "ok":
            return None
        return prov.auth_value(stored["tool_user"], stored.get("password"))
    except Exception as exc:                # noqa: BLE001
        print(f"[TOOL-ACCOUNTS] auth value {tool} / {row['username']}: {exc}", flush=True)
        return None


def status() -> dict:
    return {"last_run": dict(_last_run), "accounts": vault.summary()}


def request_reconcile() -> None:
    """Ask the background thread for a pass soon (debounced)."""
    _wake.set()


def _loop() -> None:
    time.sleep(BOOT_DELAY_SECONDS)
    failures = 0
    while True:
        try:
            reconcile_all()
            failures = failures + 1 if _last_run.get("errors") else 0
        except Exception as exc:            # noqa: BLE001
            print(f"[TOOL-ACCOUNTS] pass failed: {exc}", flush=True)
            failures += 1
        wait = RETRY_SECONDS[min(failures, len(RETRY_SECONDS)) - 1] if failures else NIGHTLY_SECONDS
        _wake.wait(wait)
        if _wake.is_set():
            time.sleep(DEBOUNCE_SECONDS)
            _wake.clear()


def start() -> None:
    """Start the reconciler thread once per process (app.py)."""
    global _started
    if _started:
        return
    _started = True
    users.on_change.append(request_reconcile)
    threading.Thread(target=_loop, name="tool-accounts", daemon=True).start()
