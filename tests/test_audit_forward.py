"""Audit forwarding to syslog (services/audit_forward.py).

Real UDP and TCP listeners on 127.0.0.1, nothing leaves the box: RFC 5424
format, RFC 6587 octet-counting on TCP, reconnect after the server goes away,
drop-oldest counting when the queue is full, and a sink that never raises
(audit() runs it inside the login request).
"""
import hashlib
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-fwdtest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_AUTH_DIR"] = os.path.join(_BASE, "auth")
os.environ["INTACT_CONFIG_PATH"] = os.path.join(_BASE, "config.yaml")
os.environ["INTACT_CLOUD_KEY_PATH"] = os.path.join(_BASE, "state", "cloud_secrets.key")
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402

try:
    import werkzeug.security  # noqa: F401
except ImportError:
    sec = types.ModuleType("werkzeug.security")
    sec.generate_password_hash = lambda pw: "sha256$" + hashlib.sha256(pw.encode()).hexdigest()
    sec.check_password_hash = lambda h, pw: h == sec.generate_password_hash(pw)
    wz = types.ModuleType("werkzeug")
    wz.security = sec
    sys.modules["werkzeug"] = wz
    sys.modules["werkzeug.security"] = sec

from services import audit_forward as fwd  # noqa: E402
from services import auth_service as auth  # noqa: E402

LINE = re.compile(r"^<(\d+)>1 (\S+) (\S+) intact - (\S+) - (\{.*\})$")


def wait(pred, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def read_frames(conn, n, timeout=10.0):
    """n octet-counted messages from a TCP stream."""
    conn.settimeout(timeout)
    buf, out = b"", []
    while len(out) < n:
        m = re.match(rb"^(\d+) ", buf)
        if m and len(buf) >= m.end() + int(m.group(1)):
            end = m.end() + int(m.group(1))
            out.append(buf[m.end():end].decode())
            buf = buf[end:]
            continue
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
    return out


def tcp_listener(port=0):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(5)
    s.settimeout(10)
    return s


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fwd.install()

    def setUp(self):
        fwd.QUEUE_MAX = 5000
        fwd.save_config(dict(fwd.DEFAULTS))
        with fwd._cond:
            fwd._status.update(sent=0, dropped=0, last_success=None, last_error=None,
                               last_error_at=None)

    def enable(self, protocol, port, **kw):
        cfg, problem = fwd.save_config(dict({"enabled": True, "protocol": protocol,
                                             "host": "127.0.0.1", "port": port}, **kw))
        self.assertIsNone(problem)
        return cfg


class FormatTest(Base):
    def test_rfc5424_line(self):
        entry = {"ts": "2026-11-26T10:00:00.123456+00:00", "event": "login_failed",
                 "user": "bob", "ip": "10.0.0.7"}
        line = fwd._entry_message(entry, 10).decode()
        m = LINE.match(line)
        self.assertTrue(m, line)
        self.assertEqual(int(m.group(1)), 10 * 8 + 5)          # authpriv.notice
        self.assertEqual(m.group(2), entry["ts"])
        self.assertEqual(m.group(4), "login_failed")
        self.assertEqual(json.loads(m.group(5)), entry)
        self.assertEqual(int(LINE.match(fwd._entry_message(
            dict(entry, event="login_ok"), 4).decode()).group(1)), 4 * 8 + 6)

    def test_msgid_and_bad_timestamp_are_cleaned(self):
        line = fwd.format_message({"x": "é"}, "has space " + "y" * 40, 6, 10, ts="not a time").decode()
        m = LINE.match(line)
        self.assertTrue(m, line)
        self.assertNotIn(" ", m.group(4))
        self.assertLessEqual(len(m.group(4)), 32)
        self.assertTrue(re.match(r"^\d{4}-\d\d-\d\dT", m.group(2)))
        line.encode("ascii")                                    # MSG stays ASCII: no BOM needed

    def test_tcp_framing(self):
        self.assertEqual(fwd.frame(b"<86>1 x", "tcp"), b"7 <86>1 x")
        self.assertEqual(fwd.frame(b"<86>1 x", "udp"), b"<86>1 x")


class ConfigTest(Base):
    def test_validation(self):
        for bad in ({"protocol": "http"}, {"port": 0}, {"port": 70000}, {"port": "x"},
                    {"host": "a b"}, {"host": "x;rm"}, {"enabled": True, "host": ""},
                    {"enabled": "yes"}, {"facility": 24}, {"port": True},
                    # labels the resolver refuses (UnicodeError used to kill the sender)
                    {"host": "syslog..corp"}, {"host": "a" * 64 + ".corp"}, {"host": "."}):
            cfg, problem = fwd.validate(bad)
            self.assertIsNone(cfg, bad)
            self.assertTrue(problem)
        cfg, problem = fwd.validate({"enabled": True, "protocol": "TCP", "host": "syslog.corp.local",
                                     "port": "6514"})
        self.assertIsNone(problem)
        self.assertEqual((cfg["protocol"], cfg["port"]), ("tcp", 6514))

    def test_persisted_and_read_at_start(self):
        self.enable("tcp", 1514, facility=13)
        fwd._config = None                                     # as after a restart
        cfg = fwd.get_config()
        self.assertEqual((cfg["enabled"], cfg["protocol"], cfg["port"], cfg["facility"]),
                         (True, "tcp", 1514, 13))

    def test_disabled_sends_nothing(self):
        auth.audit("login_ok", username_value="alice")
        self.assertEqual(fwd.status()["queued"], 0)


class UdpTest(Base):
    def test_every_audit_entry_arrives(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(10)
        self.addCleanup(rx.close)
        self.enable("udp", rx.getsockname()[1])
        auth.audit("login_ok", username_value="alice", role="admin")
        auth.audit("denied", username_value="eve", reason="forbidden")
        got = [LINE.match(rx.recvfrom(65535)[0].decode()) for _ in range(2)]
        self.assertEqual([m.group(4) for m in got], ["login_ok", "denied"])
        body = json.loads(got[0].group(5))
        self.assertEqual((body["user"], body["role"]), ("alice", "admin"))
        self.assertIn("hash", body)                            # the chained entry, as written
        self.assertEqual(int(got[1].group(1)), 10 * 8 + 5)
        self.assertTrue(wait(lambda: fwd.status()["sent"] == 2))
        self.assertTrue(fwd.status()["last_success"])

    def test_a_message_too_big_for_udp_is_dropped_not_retried(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(10)
        self.addCleanup(rx.close)
        self.enable("udp", rx.getsockname()[1])
        # The user name is capped by audit(); an extra field stays big enough
        # for no datagram when 40 of them are queued as one entry.
        auth.audit("login_failed", username_value="u" * 70000)
        self.assertLess(len(json.loads(LINE.match(rx.recvfrom(65535)[0].decode()).group(5))["user"]), 300)
        fwd._enqueue(lambda fac: b"x" * 70000)
        auth.audit("login_ok", username_value="after")
        self.assertEqual(LINE.match(rx.recvfrom(65535)[0].decode()).group(4), "login_ok")
        self.assertTrue(wait(lambda: fwd.status()["dropped"] == 1))

    def test_turning_it_off_tells_the_old_server(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(10)
        self.addCleanup(rx.close)
        self.enable("udp", rx.getsockname()[1])
        fwd.save_config({"enabled": False})
        self.assertEqual(LINE.match(rx.recvfrom(65535)[0].decode()).group(4), "audit_forward_changed")

    def test_send_test_message(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(5)
        self.addCleanup(rx.close)
        # Unsaved form values: forwarding itself stays off.
        out = fwd.send_test({"protocol": "udp", "host": "127.0.0.1", "port": rx.getsockname()[1]})
        self.assertTrue(out["ok"], out)
        self.assertIn("UDP cannot confirm", out["message"])
        self.assertEqual(LINE.match(rx.recvfrom(65535)[0].decode()).group(4), "forward_test")
        self.assertFalse(fwd.get_config()["enabled"])


class TcpTest(Base):
    def test_octet_counted_stream(self):
        srv = tcp_listener()
        self.addCleanup(srv.close)
        self.enable("tcp", srv.getsockname()[1])
        for i in range(3):
            auth.audit("action", username_value="alice", path=f"/api/x/{i}")
        conn, _ = srv.accept()
        self.addCleanup(conn.close)
        frames = read_frames(conn, 3)
        self.assertEqual([json.loads(LINE.match(f).group(5))["path"] for f in frames],
                         ["/api/x/0", "/api/x/1", "/api/x/2"])

    def test_reconnects_after_peer_closes(self):
        srv = tcp_listener()
        self.addCleanup(srv.close)
        self.enable("tcp", srv.getsockname()[1])
        auth.audit("login_ok", username_value="first")
        conn, _ = srv.accept()
        self.assertEqual(len(read_frames(conn, 1)), 1)
        conn.close()                                           # the syslog server restarts
        self.assertTrue(wait(lambda: fwd.status()["sent"] == 1))
        time.sleep(0.2)
        auth.audit("login_ok", username_value="second")
        conn2, _ = srv.accept()
        self.addCleanup(conn2.close)
        frames = read_frames(conn2, 1)
        self.assertEqual(json.loads(LINE.match(frames[0]).group(5))["user"], "second")

    def test_server_down_then_back_with_backoff(self):
        port = free_port()
        self.enable("tcp", port)
        auth.audit("login_ok", username_value="queued")
        self.assertTrue(wait(lambda: fwd.status()["last_error"]))
        self.assertEqual(fwd.status()["queued"], 1)            # kept for the retry
        srv = tcp_listener(port)
        self.addCleanup(srv.close)
        conn, _ = srv.accept()
        self.addCleanup(conn.close)
        frames = read_frames(conn, 1)
        self.assertEqual(json.loads(LINE.match(frames[0]).group(5))["user"], "queued")
        self.assertTrue(wait(lambda: fwd.status()["queued"] == 0))
        st = fwd.status()
        self.assertGreater(st["last_success"], st["last_error_at"])

    def test_queue_full_drops_oldest_and_counts(self):
        fwd.QUEUE_MAX = 5
        self.enable("tcp", free_port())                       # nothing listens: sends keep failing
        for i in range(12):
            auth.audit("action", username_value=f"u{i}")
        st = fwd.status()
        self.assertEqual((st["queued"], st["dropped"]), (5, 7))
        with fwd._cond:
            users = [json.loads(LINE.match(m.decode()).group(5))["user"] for m in fwd._queue]
        self.assertEqual(users, [f"u{i}" for i in range(7, 12)])   # the newest are kept

    def test_send_test_reports_failure(self):
        out = fwd.send_test({"protocol": "tcp", "host": "127.0.0.1", "port": free_port()})
        self.assertFalse(out["ok"])
        self.assertIn("Could not send", out["message"])
        self.assertFalse(fwd.send_test({"protocol": "tcp", "host": "bad host", "port": 514})["ok"])


class NeverRaisesTest(Base):
    def test_sink_swallows_errors(self):
        self.enable("udp", free_port(socket.SOCK_DGRAM))
        orig = fwd._entry_message
        fwd._entry_message = lambda *a: 1 / 0
        try:
            self.assertIsNone(fwd.sink({"event": "x"}))
            auth.audit("login_ok", username_value="alice")    # login still works
        finally:
            fwd._entry_message = orig
        self.assertIsNone(fwd.sink(None))
        self.assertIsNone(fwd.forward_alert(None))

    def test_install_is_idempotent(self):
        fwd.install()
        self.assertEqual(auth.AUDIT_SINKS.count(fwd.sink), 1)


if __name__ == "__main__":
    unittest.main()
