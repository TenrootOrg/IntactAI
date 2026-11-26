#!/usr/bin/env python3
"""Restricted cases (need-to-know).

A case may be marked restricted with a list of allowed user names (kept on the
case row: details.restricted, details.allowed_users). Who sees it: the names
on its list and the Super-admin, nobody else -- an Admin or Operator not on
the list gets "case not found" for it everywhere (lists, by id, as the active
case, its runs). Read-only users on the list see it read-only as usual.

Enforced here, on the server: app.py runs check_request() on every request
(the case in the URL, the run in the URL, the active case header/cookie), and
the list routes drop what hidden_case_ids() names. A request with no user is
the box itself (the loopback exemption) and sees everything.

Velociraptor and Timesketch follow (services/tool_accounts): the case's org and
sketch are granted only to the allowed users. Kibana and VolWeb cannot be
restricted (shared indices; VolWeb users are superusers), the UI says so.

The gate runs on every request and a case row holds its whole report and chat,
so the restricted set comes from an in-process snapshot, rebuilt after every
write here and at least every SNAPSHOT_SECONDS (an imported case, another
process).
"""

import threading
import time
from typing import Optional

from services import users

SNAPSHOT_SECONDS = 30
# Run types whose case is details.case_id: they run in the System workspace
# (workflow_service.SYSTEM_TYPES) but belong to one case, so they follow it.
CASE_RUN_TYPES = ("case_export", "case_import", "decision_relevance", "jev_relevance")
# A signed-in uid with no row (deleted since): sees no restricted case. Never
# None, which would mean the box itself.
_NOBODY = {"id": None, "username": "", "role": users.READONLY}

_lock = threading.Lock()
_snapshot: Optional[dict] = None
_snapshot_at = 0.0


def _load() -> dict:
    """{case_id: {"users": frozenset, "org": str, "name": str}} for every
    restricted case."""
    global _snapshot, _snapshot_at
    with _lock:
        if _snapshot is None or time.monotonic() - _snapshot_at > SNAPSHOT_SECONDS:
            import json
            import sqlite3
            from services.storage.base import get_connection
            # json_extract only on case rows, and only the four keys: a case's
            # details also hold its report and chat.
            try:
                rows = get_connection().execute(
                    "SELECT run_id, json_extract(details, '$.allowed_users'), "
                    "json_extract(details, '$.velo_org'), json_extract(details, '$.name') "
                    "FROM workflows WHERE automation_type = 'case' AND json_valid(details) "
                    "AND json_extract(details, '$.restricted') = 1").fetchall()
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc):
                    rows = []               # a fresh DB: no case yet
                elif _snapshot is not None:
                    # "database is locked" during a big import: the last known
                    # list, not a 500 on every route (login included).
                    print(f"[CASE-ACCESS] kept the previous list: {exc}", flush=True)
                    _snapshot_at = time.monotonic()
                    return _snapshot
                else:
                    raise                   # never "nothing is restricted" on a DB error
            snap = {}
            for cid, allowed, org, name in rows:
                try:
                    names = json.loads(allowed) if allowed else []
                except ValueError:
                    names = []
                snap[cid] = {"users": frozenset(str(n).lower() for n in names if isinstance(n, str)),
                             "org": org or "", "name": name or ""}
            _snapshot, _snapshot_at = snap, time.monotonic()
        return _snapshot


def invalidate() -> None:
    global _snapshot
    with _lock:
        _snapshot = None


def restricted_cases() -> dict:
    return dict(_load())


# --- who is asking -----------------------------------------------------------

def caller_row(session) -> Optional[dict]:
    """The caller's user row (role capped for an API token), or None for the box
    itself (loopback, no session)."""
    ident = users.request_identity()
    uid = ident["uid"] if ident else (session or {}).get("uid")
    if not uid:
        return None
    row = users.get(uid)
    if row is None:
        return _NOBODY
    return dict(row, role=ident["role"]) if ident else row


def sees_all(row) -> bool:
    return row is None or row.get("role") == users.SUPERADMIN


# --- the rules ---------------------------------------------------------------

def can_see(case_id, row) -> bool:
    if sees_all(row) or not case_id:
        return True
    r = _load().get(case_id)
    return r is None or (row.get("username") or "") in r["users"]


def hidden_case_ids(row) -> set:
    """The restricted cases `row` may not see (empty for the box and the
    Super-admin)."""
    if sees_all(row):
        return set()
    name = row.get("username") or ""
    return {cid for cid, r in _load().items() if name not in r["users"]}


def visible_case_ids(row):
    """Every case id `row` may see, or None for all of them."""
    hidden = hidden_case_ids(row)
    if not hidden:
        return None
    from services.storage.base import get_connection
    ids = {r[0] for r in get_connection().execute(
        "SELECT run_id FROM workflows WHERE automation_type = 'case'").fetchall()}
    return ids - hidden


def run_case_ids(run) -> set:
    """Every case a run belongs to: its tag, the case it is about (export,
    relevance, import), and itself for a case row."""
    run = run or {}
    det = run.get("details") or {}
    # source_case: a baseline row (its case_id is None) holds the case's findings.
    out = {run.get("case_id"), det.get("case_id"), det.get("source_case")}
    if run.get("automation_type") == "case":
        out.add(run.get("run_id"))
    out.discard(None)
    return out


def run_visible(run, row, hidden=None) -> bool:
    if sees_all(row):
        return True
    return not (run_case_ids(run) & (hidden_case_ids(row) if hidden is None else hidden))


def may_change(case_id, row) -> bool:
    """Restricting a case, or changing its list: the Super-admin, or an Admin or
    Operator who may see the case (on its list, or it is not restricted yet)."""
    if sees_all(row):
        return True
    return users.rank(row.get("role")) >= users.rank(users.OPERATOR) and can_see(case_id, row)


def request_refusal(case_id, session, run_id=None) -> Optional[str]:
    """Why this caller may not touch `case_id` / `run_id`, or None. Worded as
    "not found": a restricted case's existence is need-to-know too."""
    row = caller_row(session)
    if sees_all(row):
        return None
    if case_id and not can_see(case_id, row):
        return "case not found"
    if run_id:
        from services.storage.workflow_store import get_workflow
        run = get_workflow(run_id, with_logs=False)      # polled by log windows: no logs
        if run and not run_visible(run, row):
            return f"Automation run {run_id} not found"
    return None


# The active case header/cookie is ignored here: the case list is how the page
# finds out its remembered case is gone (js/active-case.js ensureActiveCase),
# and the auth routes (sign-in state, logout, nginx's tool verify) are not about
# a case at all.
ACTIVE_CASE_EXEMPT = ("case.list_cases",)
ACTIVE_CASE_EXEMPT_PREFIXES = ("auth.", "users.", "api_tokens.")


def check_request(request, session) -> Optional[str]:
    """request_refusal() for a Flask request: the case and run in the URL, and
    the active case it carries (X-Case-Id header, intact_case cookie -- the same
    sources as app.py's _velo_org_from_request)."""
    if not _load():
        return None                         # nothing restricted: nothing to refuse
    va = request.view_args or {}
    reason = request_refusal(va.get("case_id"), session, run_id=va.get("run_id"))
    if reason:
        return reason
    ep = request.endpoint or ""
    if ep in ACTIVE_CASE_EXEMPT or ep.startswith(ACTIVE_CASE_EXEMPT_PREFIXES):
        return None
    from services import velo_org
    for active in (request.headers.get("X-Case-Id"), request.cookies.get(velo_org.CASE_COOKIE)):
        reason = request_refusal((active or "").strip(), session)
        if reason:
            return reason
    return None


# --- the write ---------------------------------------------------------------

def set_access(case_id, restricted, allowed, actor) -> dict:
    """Restrict or open a case. `actor` is the caller's row (None = the box).
    The creator and the actor are always kept on the list: restricting a case
    must not lock out the person doing it or the person who opened it."""
    from services.fusion import store
    d = store.get_case(case_id)
    if not d:
        return {"error": "case not found"}
    if d.get("is_default") or d.get("is_system"):
        return {"error": "the built-in Default and System cases cannot be restricted"}
    if not isinstance(allowed, list) or not all(isinstance(n, str) for n in allowed):
        return {"error": "allowed_users must be a list of user names"}
    names = {n.strip().lower() for n in allowed if n.strip()}
    unknown = sorted(n for n in names if users.by_name(n) is None)
    if unknown:
        return {"error": f"no such user: {', '.join(unknown)}"}
    for keep in (d.get("created_by"), (actor or {}).get("username")):
        if keep and users.by_name(keep) is not None:
            names.add(keep)
    if restricted:
        from services import velo_org
        org = velo_org.clean(store.case_info(d).get("velo_org") or "")
        others = org_in_use(org, case_id) if org and org != "root" else []
        if others:
            # Everyone on those cases keeps the org, and with it this case's
            # Velociraptor data: restricting would only look safe.
            return {"error": f"Velociraptor org {org} is shared with {', '.join(map(str, others[:3]))}"
                             f"{' and more' if len(others) > 3 else ''}. Give this case its own "
                             "org first, then restrict it."}
    before = (bool(d.get("restricted")), sorted(d.get("allowed_users") or []))
    patch = {"restricted": bool(restricted), "allowed_users": sorted(names)}
    store._merge_case_details(case_id, patch)            # noqa: SLF001 -- the case row's one writer
    invalidate()
    if before != (patch["restricted"], patch["allowed_users"]):
        store.log_case_event(case_id, "Case access", "info",
                             ("restricted to " + ", ".join(patch["allowed_users"]))
                             if patch["restricted"] else "open to every user")
        try:
            from services import tool_accounts
            tool_accounts.request_reconcile()            # the case's org and sketch follow
        except Exception as exc:                         # noqa: BLE001 -- the save stands
            print(f"[CASE-ACCESS] reconcile request failed: {exc}", flush=True)
    return {"case_id": case_id, **patch, "changed": before != (patch["restricted"], patch["allowed_users"])}


def org_in_use(org, except_case_id) -> list:
    """Names of the other cases whose Velociraptor org is `org`."""
    from services.storage.base import get_connection
    return [r[0] for r in get_connection().execute(
        "SELECT json_extract(details, '$.name') FROM workflows WHERE automation_type = 'case' "
        "AND run_id != ? AND json_valid(details) AND json_extract(details, '$.velo_org') = ?",
        (except_case_id, org)).fetchall()]


def touched(case_id) -> None:
    """A restricted case was renamed, moved to another org or deleted: its
    sketch and org grants follow (tool_accounts). A no-op for an open case."""
    if case_id in _load():
        invalidate()
        try:
            from services import tool_accounts
            tool_accounts.request_reconcile()
        except Exception as exc:                         # noqa: BLE001
            print(f"[CASE-ACCESS] reconcile request failed: {exc}", flush=True)


# --- what the tools need (services/tool_accounts) ------------------------------

def denied_orgs(username: str) -> set:
    """Velociraptor orgs `username` gets no role in: the org of every restricted
    case not on its list. Root is never one: every case without an org of its
    own lives there, and the API user and Default case need it."""
    from services import velo_org
    name = (username or "").lower()
    out = set()
    for r in _load().values():
        org = velo_org.clean(r["org"])
        if org and name not in r["users"]:
            out.add(org)
    return out


def restricted_sketches() -> dict:
    """{sketch name: allowed user names} -- a case's sketch is named after it
    (timesketch_service.case_sketch_name)."""
    return {r["name"]: sorted(r["users"]) for r in _load().values() if r["name"]}
