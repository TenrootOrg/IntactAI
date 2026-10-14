"""The Velociraptor API config is read once and parsed from memory, not a shared file.

Fleet-scale audit F7 (2026-10-14): every gRPC call ran `docker exec cat` on the API
config, truncated and rewrote /tmp/api.config.yaml, then read it back. Parallel
threads read it half written, yaml.safe_load gave None and that host's start or
status check failed. The config is now cached under a lock and re-read only when a
connection attempt fails (a stale hostname must still heal itself).
"""
import os
import sys
import tempfile
import threading
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velociraptor_service as vs  # noqa: E402

CONFIG = """ca_certificate: CA
client_private_key: KEY
client_cert: CERT
api_connection_string: {host}:8001
"""


class FakeGrpc:
    """Records the address of every channel; `reachable` decides readiness."""

    def __init__(self, reachable):
        self.reachable = reachable
        self.addresses = []
        self.lock = threading.Lock()

    def ssl_channel_credentials(self, **k):
        assert all(k.values()), k                      # a truncated config shows up here
        return k

    def secure_channel(self, addr, creds, options):
        with self.lock:
            self.addresses.append(addr)
        return types.SimpleNamespace(addr=addr, close=lambda: None)

    def channel_ready_future(self, channel):
        def result(timeout=None):
            if not self.reachable(channel.addr):
                raise TimeoutError("not ready")
        return types.SimpleNamespace(result=result, cancel=lambda: None)


class ConfigCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.saved = (vs.subprocess.run, vs.grpc, vs._SHARED_CONFIG_COPY, vs.velociraptor_api_config)
        vs._SHARED_CONFIG_COPY = os.path.join(self.tmp, "api.config.yaml")
        vs.velociraptor_api_config = None
        self.host = "old-host"
        self.execs = 0

        def run(cmd, **k):
            self.execs += 1
            time.sleep(0.01)                           # widen any race window
            return types.SimpleNamespace(returncode=0, stdout=CONFIG.format(host=self.host), stderr="")
        vs.subprocess.run = run

    def tearDown(self):
        vs.subprocess.run, vs.grpc, vs._SHARED_CONFIG_COPY, vs.velociraptor_api_config = self.saved

    def test_50_concurrent_calls_all_get_a_valid_config_from_one_read(self):
        vs.grpc = FakeGrpc(reachable=lambda addr: True)
        got = []
        threads = [threading.Thread(target=lambda: got.append(vs.setup_velociraptor_connection()))
                   for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(50, len(got))
        self.assertTrue(all(c is not None and c.addr == "old-host:8001" for c in got))
        self.assertEqual(1, self.execs, "the config must be read once, not per call")

    def test_failed_connect_rereads_config_and_uses_new_hostname(self):
        vs.grpc = FakeGrpc(reachable=lambda addr: addr == self.host + ":8001")  # where the server is now
        self.assertEqual("old-host:8001", vs.setup_velociraptor_connection().addr)  # first read
        self.host = "new-host"                         # e.g. after change_ip.sh
        ch = vs.setup_velociraptor_connection()
        self.assertEqual("new-host:8001", ch.addr)
        self.assertEqual(2, self.execs)
        # healthy again: served from memory
        vs.setup_velociraptor_connection()
        self.assertEqual(2, self.execs)
        with open(vs._SHARED_CONFIG_COPY) as f:        # sibling services' copy follows
            self.assertIn("new-host", f.read())

    def test_server_down_still_returns_a_channel(self):
        # Unchanged config + unreachable server: the caller's own RPC reports the
        # failure, as it always did -- setup does not turn it into None.
        vs.grpc = FakeGrpc(reachable=lambda addr: False)
        self.assertIsNotNone(vs.setup_velociraptor_connection())

    def test_unreadable_config_gives_none_and_is_retried(self):
        vs.grpc = FakeGrpc(reachable=lambda addr: True)
        vs.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr="")
        self.assertIsNone(vs.setup_velociraptor_connection())
        self.assertIsNone(vs.velociraptor_api_config)   # nothing bad was cached


if __name__ == "__main__":
    unittest.main()
