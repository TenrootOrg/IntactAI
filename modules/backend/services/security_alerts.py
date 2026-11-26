#!/usr/bin/env python3
"""Security alerts: a few deterministic rules over the auth audit log.

An AUDIT_SINKS callable (services/auth_service.py) sees every audit entry as it
is written and raises an alert when one of these rules matches. Alerts are kept
in the security_alerts table until an Admin acknowledges them (Settings ->
Security) and, when audit forwarding is on, sent to syslog too.

    kind                   fires on                                          severity
    failed_login_burst     >= 10 login_failed/reauth_failed from one IP in 10 min   high
    failed_login_burst_box >= 20 login_failed/reauth_failed box-wide in 10 min      high
    account_locked         a `locked` event (one per IP per 10 min)           medium
    admin_granted          user_role_changed or user_created with role
                           admin or superadmin                                high
    superadmin_transferred superadmin_transferred                             high
    superadmin_setup       setup (first setup, or scripts/reset-login.sh)     high
    mfa_removed            user_mfa_reset or mfa_disabled                     medium
    csrf_rejected          denied, reason csrf_rejected (one per user+IP
                           per 10 min)                                        medium
    forbidden_burst        >= 10 refused WRITES for one user in 10 min        medium

A burst raises ONE alert per window: after it fires, the same key stays quiet
for 10 minutes, then a burst still going on raises the next one. Failed codes
count with failed passwords: a wrong two-step code is logged as login_failed
(reason bad_mfa_code) or reauth_failed.

Quick on purpose (audit() runs it inside the login request): counters are
in-memory deques, so they start empty after a restart; only a rule that fires
touches SQLite, and dedup keeps that rare.
"""

import collections
import json
import threading
import time
from datetime import datetime, timezone

from services.storage.base import get_connection

WINDOW = 600.0
IP_FAILS, BOX_FAILS, USER_FORBIDDEN = 10, 20, 10
_FAIL_EVENTS = ("login_failed", "reauth_failed")
_PRIVILEGED = ("admin", "superadmin")
_MAX_KEYS = 2000            # bound on tracked IPs/users; stale keys are pruned first

_lock = threading.Lock()
_hits = {}                  # key -> deque of timestamps (maxlen = the rule's threshold)
_fired = {}                 # dedup key -> time it last fired


def _now():
    return time.time()


def _ensure_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        user TEXT,
        detail TEXT,
        acknowledged_by TEXT,
        acknowledged_at TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_unacked "
                 "ON security_alerts (acknowledged_at)")


def _burst(key, threshold, now):
    """True when `key` reached `threshold` hits inside the window."""
    dq = _hits.get(key)
    if dq is None:
        if len(_hits) >= _MAX_KEYS:
            for k in [k for k, d in _hits.items() if not d or d[-1] < now - WINDOW]:
                del _hits[k]
            if len(_hits) >= _MAX_KEYS:
                # shortcut: under a flood of distinct keys the oldest-inserted one goes;
                # the box-wide rule still sees the flood.
                del _hits[next(iter(_hits))]
        dq = _hits[key] = collections.deque(maxlen=threshold)
    dq.append(now)
    return len(dq) == threshold and dq[0] >= now - WINDOW


def _once(key, now):
    """True the first time `key` fires in a window (dedup)."""
    if now - _fired.get(key, -WINDOW - 1) < WINDOW:
        return False
    if len(_fired) >= _MAX_KEYS:
        for k in [k for k, t in _fired.items() if t < now - WINDOW]:
            del _fired[k]
    _fired[key] = now
    return True


def evaluate(entry, now=None):
    """The alerts (kind, severity, user, detail) this entry raises. Pure apart
    from the in-memory counters."""
    now = _now() if now is None else now
    ev, user, ip = entry.get("event"), entry.get("user"), entry.get("ip") or "-"
    base = {"event": ev, "ip": ip}
    out = []
    with _lock:
        if ev in _FAIL_EVENTS:
            if _burst(("fail_ip", ip), IP_FAILS, now) and _once(("fail_ip", ip), now):
                out.append(("failed_login_burst", "high", None,
                            dict(base, count=IP_FAILS, last_user=user)))
            if _burst(("fail_box",), BOX_FAILS, now) and _once(("fail_box",), now):
                out.append(("failed_login_burst_box", "high", None,
                            dict(base, count=BOX_FAILS, last_user=user)))
        elif ev == "locked":
            if _once(("locked", ip), now):
                out.append(("account_locked", "medium", user,
                            dict(base, locked_for_seconds=entry.get("locked_for_seconds"))))
        elif ev in ("user_role_changed", "user_created"):
            if entry.get("role") in _PRIVILEGED:
                out.append(("admin_granted", "high", user,
                            dict(base, target=entry.get("target"), role=entry.get("role"),
                                 old_role=entry.get("old_role"))))
        elif ev == "superadmin_transferred":
            out.append(("superadmin_transferred", "high", user,
                        dict(base, target=entry.get("target"))))
        elif ev == "setup":
            out.append(("superadmin_setup", "high", user, dict(base, role=entry.get("role"))))
        elif ev in ("user_mfa_reset", "mfa_disabled"):
            target = entry.get("target") or user
            # Once per target per window: a user toggling their own optional
            # two-step login must not flood the list.
            if _once(("mfa", target), now):
                out.append(("mfa_removed", "medium", user, dict(base, target=target)))
        elif ev == "audit_forward_changed":
            old, new = entry.get("old") or {}, entry.get("new") or {}
            moved = tuple(old.get(k) for k in ("protocol", "host", "port")) != \
                tuple(new.get(k) for k in ("protocol", "host", "port"))
            if old.get("enabled") and (not new.get("enabled") or moved):
                out.append(("audit_forward_changed", "high", user,
                            dict(base, old_host=old.get("host"), new_host=new.get("host") if new.get("enabled") else None)))
        elif ev == "token_denied" and entry.get("reason") in ("token_invalid", "token_expired",
                                                              "disabled", "credentials_changed"):
            # A dead token still being tried (a leaked one?): counted like failed sign-ins.
            if _burst(("fail_ip", ip), IP_FAILS, now) and _once(("fail_ip", ip), now):
                out.append(("failed_login_burst", "high", None,
                            dict(base, count=IP_FAILS, last_user=user)))
        elif ev in ("denied", "token_denied"):
            reason = entry.get("reason")
            if ev == "token_denied" and reason == "token_refused":
                reason = "forbidden"            # a token probing routes it may never use
            if reason == "csrf_rejected" and _once(("csrf", user, ip), now):
                out.append(("csrf_rejected", "medium", user,
                            dict(base, endpoint=entry.get("endpoint"))))
            # Writes only: the dashboard itself asks for some things a role
            # may not read (a page load is several refused GETs), so counting
            # those raised an alert every second page load. Refused writes are
            # someone trying to change what they may not.
            elif (reason == "forbidden" and entry.get("method") not in ("GET", "HEAD", "OPTIONS")
                  and _burst(("forbidden", user), USER_FORBIDDEN, now)
                  and _once(("forbidden", user), now)):
                out.append(("forbidden_burst", "medium", user,
                            dict(base, count=USER_FORBIDDEN, endpoint=entry.get("endpoint"))))
    return out


def describe(kind, user, detail):
    """What happened, in plain words (the UI and the syslog line both use it)."""
    d = detail or {}
    who = user or "someone"
    ip = d.get("ip") or "an unknown address"
    texts = {
        "failed_login_burst": f"{d.get('count')} failed sign-ins in 10 minutes from {ip}",
        "failed_login_burst_box": f"{d.get('count')} failed sign-ins in 10 minutes across the box",
        "account_locked": f"Sign-in locked after repeated failures for {who} from {ip}",
        "admin_granted": f"{who} gave {d.get('target')} the {d.get('role')} role",
        "superadmin_transferred": f"{who} handed the Super-admin role to {d.get('target')}",
        "superadmin_setup": f"The Super-admin login was set up for {who} (first setup or reset-login.sh)",
        "mfa_removed": (f"Two-step login was turned off for {d.get('target')}" if d.get("event") == "mfa_disabled"
                        else f"{who} reset two-step login for {d.get('target')}"),
        "csrf_rejected": f"A request from another site was refused for {who}",
        "audit_forward_changed": (f"{who} moved audit forwarding from {d.get('old_host')} to {d.get('new_host')}"
                                  if d.get("new_host") else f"{who} turned audit forwarding off (was {d.get('old_host')})"),
        "forbidden_burst": f"{who} was refused {d.get('count')} times in 10 minutes (role does not allow it)",
    }
    return texts.get(kind, kind)


def _store(kind, severity, user, detail):
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    _ensure_table(conn)
    cur = conn.execute("INSERT INTO security_alerts (ts, kind, severity, user, detail) "
                       "VALUES (?, ?, ?, ?, ?)", (ts, kind, severity, user, json.dumps(detail)))
    conn.commit()
    return {"id": cur.lastrowid, "ts": ts, "kind": kind, "severity": severity, "user": user,
            "detail": detail, "text": describe(kind, user, detail)}


def sink(entry):
    """AUDIT_SINKS callable. Never raises."""
    try:
        for kind, severity, user, detail in evaluate(entry):
            alert = _store(kind, severity, user, detail)
            print(f"[SECURITY-ALERT] {severity}: {alert['text']}", flush=True)
            from services import audit_forward
            audit_forward.forward_alert(alert)
    except Exception as exc:                    # noqa: BLE001 -- see AUDIT_SINKS
        print(f"[SECURITY-ALERT] Could not record an alert: {exc}", flush=True)


def _row(r):
    d = dict(r)
    try:
        d["detail"] = json.loads(d["detail"] or "{}")
    except ValueError:
        d["detail"] = {}
    d["text"] = describe(d["kind"], d["user"], d["detail"])
    return d


def list_alerts(unacked=False, limit=200):
    conn = get_connection()
    _ensure_table(conn)
    where = "WHERE acknowledged_at IS NULL " if unacked else ""
    rows = conn.execute(f"SELECT * FROM security_alerts {where}ORDER BY id DESC LIMIT ?",
                        (int(limit),)).fetchall()
    return [_row(r) for r in rows]


def unacked_count():
    conn = get_connection()
    _ensure_table(conn)
    return conn.execute("SELECT COUNT(*) FROM security_alerts "
                        "WHERE acknowledged_at IS NULL").fetchone()[0]


def get(alert_id):
    conn = get_connection()
    _ensure_table(conn)
    row = conn.execute("SELECT * FROM security_alerts WHERE id = ?", (int(alert_id),)).fetchone()
    return _row(row) if row else None


def acknowledge(alert_id, by):
    """The alert after acknowledging it, or None when there is no such alert.
    Acknowledging twice keeps the first name and time."""
    conn = get_connection()
    _ensure_table(conn)
    conn.execute("UPDATE security_alerts SET acknowledged_by = ?, acknowledged_at = ? "
                 "WHERE id = ? AND acknowledged_at IS NULL",
                 (by, datetime.now(timezone.utc).isoformat(), int(alert_id)))
    conn.commit()
    row = conn.execute("SELECT * FROM security_alerts WHERE id = ?", (int(alert_id),)).fetchone()
    return _row(row) if row else None


def install():
    """Register the sink. Safe to call twice."""
    from services import auth_service
    if sink not in auth_service.AUDIT_SINKS:
        auth_service.AUDIT_SINKS.append(sink)
