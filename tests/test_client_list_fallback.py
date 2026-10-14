"""With the Velociraptor API down, the client list must not claim the fleet is online.

The snapshot-file fallback stamped every client "seen now": the whole fleet
showed online and the pickers pre-selected all of it, while nothing could be
sent. It now lists clients as not seen, and an online-only request gets none.
"""
import json
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velociraptor_service as vs  # noqa: E402


def client_info(**fields):
    """A serialized actions_proto.ClientInfo: string fields, by field number."""
    nums = {"client_id": 1, "hostname": 3, "system": 5, "release": 6, "ip_address": 10,
            "client_version": 12, "client_name": 13, "labels": 15, "last_interrogate_flow_id": 16}
    out = bytearray(b"\x58\x96\x01")                  # ping=150 (a varint field) first
    for name, val in fields.items():
        for v in (val if isinstance(val, list) else [val]):
            b = v.encode()
            tag = nums[name] << 3 | 2                    # 2-byte varint from field 16 on
            out += (bytes([tag]) if tag < 0x80 else bytes([tag & 0x7f | 0x80, tag >> 7])) + bytes([len(b)]) + b
    return bytes(out)


AGENT = dict(client_name="velociraptor", client_version="0.77.1", last_interrogate_flow_id="F.1")


class SnapshotFallback(unittest.TestCase):
    def serve(self, *records):
        stdout = "\n".join(json.dumps(r) for r in records) + "\n"
        vs.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=stdout)

    def setUp(self):
        self._run = vs.subprocess.run
        self.serve({"client_id": "C.1", "info": client_info(
            client_id="C.1", hostname="DESKTOP-ABC12", system="windows", ip_address="10.0.0.5", **AGENT).hex()})

    def tearDown(self):
        vs.subprocess.run = self._run


class SnapshotFallbackNeverClaimsOnline(SnapshotFallback):

    def test_all_clients_listed_as_not_seen(self):
        rows = vs.get_clients_from_snapshot_file(include_offline=True)
        self.assertEqual(["C.1"], [r["client_id"] for r in rows])
        self.assertEqual(0, rows[0]["last_seen_at"])

    def test_online_only_request_gets_none(self):
        self.assertEqual([], vs.get_clients_from_snapshot_file(include_offline=False))


class SnapshotFallbackDecodesClientInfo(SnapshotFallback):
    """Hostnames were guessed by searching the bytes for "DESKTOP-": every other host
    was "Unknown", so a 1,000-host fleet became 1,000 identical rows."""

    def test_any_hostname_os_ip_and_labels_are_decoded(self):
        self.serve({"client_id": "C.2", "info": client_info(
            client_id="C.2", hostname="db-prod-07", system="linux", release="Ubuntu 24.04",
            ip_address="10.1.2.3", labels=["servers", "prod"], **AGENT).hex()})
        [r] = vs.get_clients_from_snapshot_file(include_offline=True)
        self.assertEqual(("db-prod-07", "linux", "Ubuntu 24.04", "10.1.2.3", ["servers", "prod"], False),
                         (r["hostname"], r["os"], r["os_version"], r["last_ip"], r["labels"], r["imported"]))

    def test_base64_info_is_read_too(self):
        import base64
        self.serve({"client_id": "C.3", "info": base64.b64encode(
            client_info(client_id="C.3", hostname="FIN-LAPTOP", **AGENT)).decode()})
        self.assertEqual(["FIN-LAPTOP"], [r["hostname"] for r in vs.get_clients_from_snapshot_file()])

    def test_offline_collection_import_is_marked(self):
        self.serve({"client_id": "C.4", "info": client_info(client_id="C.4", hostname="ADATUM-DC").hex()})
        self.assertTrue(vs.get_clients_from_snapshot_file()[0]["imported"])

    def test_undecodable_snapshot_is_an_error_not_unknown_rows(self):
        self.serve(*({"client_id": f"C.{i}", "info": "C.1 PC windows".encode().hex()} for i in range(5)))
        with self.assertRaisesRegex(RuntimeError, "could not be decoded"):
            vs.get_clients_from_snapshot_file()

    def test_one_bad_record_does_not_hide_the_rest(self):
        good = {"client_id": "C.5", "info": client_info(client_id="C.5", hostname="PC-5", **AGENT).hex()}
        self.serve(good, {"client_id": "C.6", "info": "zz"})
        self.assertEqual(["PC-5"], [r["hostname"] for r in vs.get_clients_from_snapshot_file()])


class OnlineFilterUsesSeconds(unittest.TestCase):
    def test_last_seen_microseconds_are_converted(self):
        # clients() reports last_seen_at in MICROseconds; compared raw with now() - 600
        # every enrolled client passed (10 of 10 "online" on the lab box, 1 real).
        src = open(os.path.join(ROOT, "modules/backend/services/velociraptor_service.py")).read()
        self.assertIn("last_seen_at / 1000000 > now() - 600", src)
        self.assertNotIn('"  AND last_seen_at > now() - 600"', src)


if __name__ == "__main__":
    unittest.main()
