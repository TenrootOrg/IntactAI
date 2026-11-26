#!/usr/bin/env python3
"""Forward every auth audit entry to a syslog server on the customer's network.

The hash chain in data/auth/audit.jsonl shows an edited line, but root on the
host can still rewrite the whole file; a copy already on another machine is
what makes the log trustworthy (docs/PLAN_multi_user_accounts.md section 3).
Air-gapped by design: the only destination is the host:port the Admin enters.

One message per entry: RFC 5424, MSGID = the event name, MSG = the entry as
JSON. UDP sends one datagram per message; TCP uses octet-counting framing
(RFC 6587 3.4.1: "<length> <message>").

Never in the request path: audit() calls the sink, which only appends to a
bounded in-memory queue. One daemon thread drains it. While the server is down
the thread retries the same message with backoff (1 s doubling to 60 s) and the
queue keeps the newest QUEUE_MAX entries, counting each one it drops. Nothing
is kept across a restart: the local audit.jsonl stays the full record.

The config (enabled, protocol, host, port, facility) holds no secret; it lives
in its own one-row table so the Settings page's whole-config save cannot write
an old copy back over it.
"""

import collections
import errno
import json
import re
import select
import socket
import threading
import time
from datetime import datetime, timezone

from services.storage.base import get_connection

QUEUE_MAX = 5000
SEND_TIMEOUT = 5.0
BACKOFF_MAX = 60.0
APP_NAME = "intact"

DEFAULTS = {"enabled": False, "protocol": "udp", "host": "", "port": 514,
            # 10 = authpriv: where syslog servers file security/authorization messages.
            "facility": 10}

# Audit events a SOC wants to see stand out (syslog severity 5 = notice);
# everything else is 6 = informational.
_NOTICE_EVENTS = {"login_failed", "locked", "login_blocked", "denied", "reauth_failed",
                  "setup_rejected", "setup_failed", "password_change_failed",
                  "superadmin_transfer_failed"}
ALERT_SEVERITY = {"high": 3, "medium": 4, "low": 5}     # err / warning / notice

_HOST_RE = re.compile(r"^[A-Za-z0-9.:\-]{1,253}$")

_cond = threading.Condition()
_queue = collections.deque()
_config = None          # cached dict, loaded from the DB on first use
_generation = 0         # bumped on every config change: the worker reconnects
_thread = None
_status = {"sent": 0, "dropped": 0, "last_success": None, "last_error": None,
           "last_error_at": None}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# --- config ----------------------------------------------------------------

def _ensure_table(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS audit_forward_config ("
                 "id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL, updated_at TEXT)")


def validate(data):
    """(clean config, None) or (None, message). Every field is checked: this is
    a trust boundary (the PUT body) and the values end up in a socket call."""
    if not isinstance(data, dict):
        return None, "Expected a JSON object."
    cfg = dict(get_config())
    cfg.update({k: data[k] for k in DEFAULTS if k in data})
    if not isinstance(cfg["enabled"], bool):
        return None, "enabled must be true or false."
    cfg["protocol"] = str(cfg["protocol"] or "").lower()
    if cfg["protocol"] not in ("udp", "tcp"):
        return None, "Protocol must be UDP or TCP."
    cfg["host"] = str(cfg["host"] or "").strip()
    if cfg["host"] and not (_HOST_RE.match(cfg["host"]) and (
            ":" in cfg["host"] or all(1 <= len(p) <= 63 for p in cfg["host"].rstrip(".").split(".")))):
        return None, "Server must be a host name or an IP address."
    if cfg["enabled"] and not cfg["host"]:
        return None, "Enter the syslog server to forward to."
    for key, lo, hi, what in (("port", 1, 65535, "Port"), ("facility", 0, 23, "Facility")):
        try:
            if isinstance(cfg[key], bool):
                raise ValueError
            cfg[key] = int(cfg[key])
        except (TypeError, ValueError):
            return None, f"{what} must be a number."
        if not lo <= cfg[key] <= hi:
            return None, f"{what} must be between {lo} and {hi}."
    return cfg, None


def get_config():
    global _config
    if _config is None:
        cfg = dict(DEFAULTS)
        try:
            conn = get_connection()
            _ensure_table(conn)
            row = conn.execute("SELECT value FROM audit_forward_config WHERE id = 1").fetchone()
            if row:
                stored = json.loads(row["value"])
                if isinstance(stored, dict):
                    cfg.update({k: stored[k] for k in DEFAULTS if k in stored})
        except Exception as exc:                # noqa: BLE001 -- forwarding off beats a crash
            print(f"[AUDIT-FWD] Could not read config: {exc}", flush=True)
        _config = cfg
    return dict(_config)


def save_config(data):
    """Validate, store, apply. (config, None) or (None, message)."""
    global _config, _generation
    cfg, problem = validate(data)
    if problem:
        return None, problem
    old = get_config()
    target = lambda c: (c["enabled"], c["protocol"], c["host"], c["port"])   # noqa: E731
    if old["enabled"] and target(old) != target(cfg):
        # Tell the server that is losing the feed, straight away and before
        # the switch: from its side, forwarding turned off looks like silence.
        try:
            _send_once(old, {"event": "audit_forward_changed", "ts": _now_iso(),
                             "message": "Audit forwarding to this server stops now",
                             "new_enabled": cfg["enabled"], "new_host": cfg["host"],
                             "new_port": cfg["port"], "new_protocol": cfg["protocol"]},
                       "audit_forward_changed", 4)
        except (OSError, ValueError) as exc:
            print(f"[AUDIT-FWD] Could not tell the old server about the change: {exc}", flush=True)
    conn = get_connection()
    _ensure_table(conn)
    conn.execute("INSERT OR REPLACE INTO audit_forward_config (id, value, updated_at) "
                 "VALUES (1, ?, ?)", (json.dumps(cfg), _now_iso()))
    conn.commit()
    with _cond:
        _config = dict(cfg)
        _generation += 1
        if not cfg["enabled"]:
            _queue.clear()              # nowhere to send them any more
        _status.update(last_error=None, last_error_at=None)   # a new target starts clean
        _cond.notify_all()
    return dict(cfg), None


def status():
    with _cond:
        return dict(_status, queued=len(_queue))


# --- message format --------------------------------------------------------

def _hostname():
    # RFC 5424 HOSTNAME: printable ASCII, no spaces, at most 255.
    return re.sub(r"[^!-~]", "_", socket.gethostname() or "-")[:255] or "-"


def format_message(body, msgid, severity, facility, ts=None):
    """One RFC 5424 line: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG."""
    pri = int(facility) * 8 + int(severity)
    msgid = re.sub(r"[^!-~]", "_", str(msgid or "-"))[:32] or "-"
    ts = ts if isinstance(ts, str) and re.match(r"^\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)$", ts) else _now_iso()
    # ensure_ascii keeps MSG pure ASCII, so no UTF-8 BOM is needed (RFC 5424 6.4).
    msg = json.dumps(body, sort_keys=True, default=str)
    return f"<{pri}>1 {ts} {_hostname()} {APP_NAME} - {msgid} - {msg}".encode("ascii")


def frame(data, protocol):
    return (str(len(data)).encode() + b" " + data) if protocol == "tcp" else data


def _entry_message(entry, facility):
    sev = 5 if entry.get("event") in _NOTICE_EVENTS else 6
    return format_message(entry, entry.get("event"), sev, facility, entry.get("ts"))


def alert_message(alert, facility):
    body = dict(alert, type="security_alert")
    return format_message(body, "alert", ALERT_SEVERITY.get(alert.get("severity"), 4),
                          facility, alert.get("ts"))


# --- queue and sink --------------------------------------------------------

def _enqueue(build):
    """build(facility) -> bytes; nothing happens while forwarding is off."""
    cfg = _config if _config is not None else get_config()
    if not cfg["enabled"]:
        return
    data = build(cfg["facility"])
    with _cond:
        if len(_queue) >= QUEUE_MAX:
            _queue.popleft()            # keep the newest: they matter most during an attack
            _status["dropped"] += 1
        _queue.append(data)
        _cond.notify()


def sink(entry):
    """AUDIT_SINKS callable. Quick (format + append) and never raises."""
    try:
        _enqueue(lambda fac: _entry_message(entry, fac))
    except Exception:                           # noqa: BLE001 -- see AUDIT_SINKS
        pass


def forward_alert(alert):
    """Called by services.security_alerts when an alert is raised. Never raises."""
    try:
        _enqueue(lambda fac: alert_message(alert, fac))
    except Exception:                           # noqa: BLE001
        pass


# --- sending ---------------------------------------------------------------

def _connect(cfg):
    if cfg["protocol"] == "tcp":
        sock = socket.create_connection((cfg["host"], cfg["port"]), timeout=SEND_TIMEOUT)
    else:
        family, kind, proto, _, addr = socket.getaddrinfo(
            cfg["host"], cfg["port"], 0, socket.SOCK_DGRAM)[0]
        sock = socket.socket(family, kind, proto)
        sock.settimeout(SEND_TIMEOUT)
        sock.connect(addr)
    return sock


def _peer_closed(sock):
    """A TCP peer that went away is only noticed on the SECOND send after it
    left (the first one "succeeds" into the void). Checking for EOF before each
    send catches the restart of the syslog server before a message is lost."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable) and sock.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def _send_once(cfg, body, msgid, severity):
    sock = _connect(cfg)
    try:
        sock.sendall(frame(format_message(body, msgid, severity, cfg["facility"]), cfg["protocol"]))
    finally:
        sock.close()


def send_test(data=None):
    """Send one test message now with `data` (unsaved form values) or the saved
    config. {'ok': bool, 'message': str}. UDP cannot confirm delivery."""
    cfg, problem = validate(dict(data or {}, enabled=True))
    if problem:
        return {"ok": False, "message": problem}
    body = {"event": "forward_test", "ts": _now_iso(),
            "message": "Test message from the Intact.AI audit forwarder"}
    try:
        _send_once(cfg, body, "forward_test", 6)
    except (OSError, ValueError) as exc:     # ValueError: e.g. a name idna refuses
        return {"ok": False, "message": f"Could not send: {exc}"}
    extra = "" if cfg["protocol"] == "tcp" else " UDP cannot confirm delivery: check the server received it."
    return {"ok": True, "message": f"Sent to {cfg['host']}:{cfg['port']} over {cfg['protocol'].upper()}.{extra}"}


def _worker():
    sock, sock_gen, backoff = None, -1, 1.0
    while True:
        with _cond:
            while not _queue:
                _cond.wait()
            data = _queue[0]            # peek: a failed send retries the same message
            cfg, gen = dict(_config or DEFAULTS), _generation
        try:
            if sock is not None and (sock_gen != gen or
                                     (cfg["protocol"] == "tcp" and _peer_closed(sock))):
                sock.close()
                sock = None
            if sock is None:
                sock, sock_gen = _connect(cfg), gen
            sock.sendall(frame(data, cfg["protocol"]))
        except (OSError, ValueError) as exc:     # ValueError: a name idna refuses
            if sock is not None:
                sock.close()
                sock = None
            if getattr(exc, "errno", None) == errno.EMSGSIZE:
                # This message can never fit a datagram: retrying it would
                # stall everything queued behind it. Drop it, keep going.
                with _cond:
                    if _queue and _queue[0] is data:
                        _queue.popleft()
                    _status["dropped"] += 1
                    _status["last_error"], _status["last_error_at"] = "message too long for UDP (dropped)", _now_iso()
                continue
            with _cond:
                _status["last_error"] = str(exc) or exc.__class__.__name__
                _status["last_error_at"] = _now_iso()
                # Wait out the backoff, but wake at once on a config change.
                _cond.wait_for(lambda: _generation != gen, timeout=backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)
            continue
        backoff = 1.0
        with _cond:
            if _queue and _queue[0] is data:
                _queue.popleft()
            _status["sent"] += 1
            # last_error stays: the UI says "failing" only when it is newer than this.
            _status["last_success"] = _now_iso()


def install():
    """Register the sink and start the sender thread. Safe to call twice."""
    global _thread
    from services import auth_service
    if sink not in auth_service.AUDIT_SINKS:
        auth_service.AUDIT_SINKS.append(sink)
    get_config()
    with _cond:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_worker, name="audit-forward", daemon=True)
            _thread.start()
