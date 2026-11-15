"""Cloud credentials (Settings -> Cloud) are encrypted at rest and deleted when
they expire (services/storage/cloud_secrets.py).

Before: frontend_config["cloud"] held the AWS key id / secret / session token
and the Azure client secret in clear inside intact.db, kept forever. Runs
against a real throwaway SQLite database and key file.
"""
import copy
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
_BASE = tempfile.mkdtemp(prefix="intact-cloudrest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
from services.storage import base, cloud_secrets, config_store  # noqa: E402

SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
KEY_ID = "AKIAEXAMPLE000000001"
AZURE = "azure-client-secret-value"


def cloud(**over):
    c = {"provider": "aws", "aws": {"access_key_id": KEY_ID, "secret_access_key": SECRET, "session_token": "",
                                    "regions": ["us-east-1", "eu-west-2"]},
         "azure": {"tenant_id": "tenant-1", "client_id": "client-1", "client_secret": AZURE}}
    c.update(over)
    return c


def raw_row():
    row = base.get_connection().execute("SELECT value FROM frontend_config WHERE key='cloud'").fetchone()
    return row["value"] if row else None


def put_raw(value):
    conn = base.get_connection()
    conn.execute("INSERT OR REPLACE INTO frontend_config (key, value, updated_at) VALUES ('cloud', ?, 'x')",
                 (json.dumps(value),))
    conn.commit()


class AtRest(unittest.TestCase):
    def setUp(self):
        base.init_storage()
        base.get_connection().execute("DELETE FROM frontend_config WHERE key='cloud'")
        base.get_connection().commit()

    def test_the_database_never_holds_a_credential_in_clear(self):
        self.assertTrue(config_store.save_cloud_config(cloud()))
        raw = raw_row()
        for v in (SECRET, KEY_ID, AZURE):
            self.assertNotIn(v, raw)
        stored = json.loads(raw)
        self.assertTrue(stored["aws"]["secret_access_key"].startswith("enc:v1:"))
        self.assertEqual(["us-east-1", "eu-west-2"], stored["aws"]["regions"])      # settings stay readable
        # ...and the bytes on disk (DB + WAL) do not contain it either
        base.get_connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for name in os.listdir(_BASE):
            p = os.path.join(_BASE, name)
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    self.assertNotIn(SECRET.encode(), f.read(), name)

    def test_every_reader_gets_the_plaintext(self):
        config_store.save_cloud_config(cloud())
        for got in (config_store.load_cloud_config(), config_store.load_frontend_config()["cloud"]):
            self.assertEqual(SECRET, got["aws"]["secret_access_key"])
            self.assertEqual(KEY_ID, got["aws"]["access_key_id"])
            self.assertEqual(AZURE, got["azure"]["client_secret"])

    def test_the_other_write_path_encrypts_too(self):
        config_store.save_frontend_config({"cloud": cloud()})
        self.assertNotIn(SECRET, raw_row())
        self.assertEqual(SECRET, config_store.load_cloud_config()["aws"]["secret_access_key"])

    def test_the_key_file_is_private_and_outside_the_database(self):
        config_store.save_cloud_config(cloud())
        path = cloud_secrets.key_path()
        self.assertTrue(path.startswith(os.path.join(_BASE, "state", "backend")))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode))
        with open(path, "rb") as f:
            self.assertNotIn(f.read().strip().decode(), raw_row())

    def test_a_wrong_or_lost_key_reads_as_no_credential_never_a_crash(self):
        config_store.save_cloud_config(cloud())
        from cryptography.fernet import Fernet
        saved = cloud_secrets._FERNET[0]
        try:
            cloud_secrets._FERNET[0] = Fernet(Fernet.generate_key())
            got = config_store.load_cloud_config()
            self.assertEqual("", got["aws"]["secret_access_key"])
            self.assertEqual(["us-east-1", "eu-west-2"], got["aws"]["regions"])
        finally:
            cloud_secrets._FERNET[0] = saved

    def test_an_old_plaintext_row_is_encrypted_on_first_read(self):
        put_raw(cloud())
        got = config_store.load_cloud_config()
        self.assertEqual(SECRET, got["aws"]["secret_access_key"])
        self.assertNotIn(SECRET, raw_row())
        self.assertTrue(json.loads(raw_row()).get(cloud_secrets.SAVED_KEY))     # its clock starts now


class Expiry(unittest.TestCase):
    def setUp(self):
        base.init_storage()
        base.get_connection().execute("DELETE FROM frontend_config WHERE key='cloud'")
        base.get_connection().commit()

    def age(self, days, ttl=None):
        """Store a credential saved `days` ago."""
        c = cloud(**({cloud_secrets.TTL_KEY: ttl} if ttl is not None else {}))
        stored = cloud_secrets.protect(c)
        stored[cloud_secrets.SAVED_KEY] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        put_raw(stored)

    def test_default_is_30_days(self):
        self.assertEqual(30, cloud_secrets.ttl_days({}))
        self.age(29)
        self.assertEqual(SECRET, config_store.load_cloud_config()["aws"]["secret_access_key"])

    def test_expired_credentials_are_deleted_and_settings_kept(self):
        self.age(31)
        got = config_store.load_cloud_config()
        for sec, field in (("aws", "access_key_id"), ("aws", "secret_access_key"), ("azure", "client_secret")):
            self.assertEqual("", got[sec][field])
        self.assertEqual(["us-east-1", "eu-west-2"], got["aws"]["regions"])
        self.assertEqual("tenant-1", got["azure"]["tenant_id"])
        self.assertTrue(got.get(cloud_secrets.EXPIRED_KEY))
        stored = json.loads(raw_row())                       # deleted for good, not just hidden
        self.assertEqual("", stored["aws"]["secret_access_key"])
        self.assertNotIn(cloud_secrets.SAVED_KEY, stored)

    def test_a_custom_limit_and_never(self):
        self.age(8, ttl=7)
        self.assertEqual("", config_store.load_cloud_config()["aws"]["secret_access_key"])
        self.age(5000, ttl=0)
        self.assertEqual(SECRET, config_store.load_cloud_config()["aws"]["secret_access_key"])

    def test_resaving_the_same_credentials_keeps_the_clock_a_new_one_restarts_it(self):
        self.age(10)
        before = json.loads(raw_row())[cloud_secrets.SAVED_KEY]
        config_store.save_cloud_config(config_store.load_cloud_config())          # same values
        self.assertEqual(before, json.loads(raw_row())[cloud_secrets.SAVED_KEY])
        c = config_store.load_cloud_config()
        c["aws"]["secret_access_key"] = "NEW-SECRET"
        config_store.save_cloud_config(c)
        self.assertNotEqual(before, json.loads(raw_row())[cloud_secrets.SAVED_KEY])

    def test_the_status_shown_never_holds_a_credential(self):
        config_store.save_cloud_config(cloud())
        st = cloud_secrets.status(config_store.load_cloud_config())
        self.assertEqual(30, st[cloud_secrets.TTL_KEY])
        self.assertTrue(st["credentials_expire_at"])
        for v in (SECRET, KEY_ID, AZURE):
            self.assertNotIn(v, json.dumps(st))

    def test_housekeeping_checks_expiry_every_minute(self):
        with open(os.path.join(os.path.dirname(_HERE), "modules/backend/services/workflow_service.py")) as f:
            src = f.read()
        loop = src[src.index("def start_housekeeping("):src.index("def get_jobs(")]
        self.assertIn("load_cloud_config()", loop)


if __name__ == "__main__":
    unittest.main()
