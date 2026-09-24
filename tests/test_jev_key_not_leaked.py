"""Jev's OpenRouter key never leaves the box through a backup, and an import
cannot replace it.

Every path that already hid the main LLM key had to learn the new one: the
redacted .db download, the JSON export, and the import guard (an import that
sets its own key would send case data to someone else's account).
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.storage import export_import  # noqa: E402

KEY = "sk-or-v1-jevsecret0000"
CFG = {"agentic": {"online_llm": {"api_key": "sk-main"}, "jev": {"enabled": True, "api_key": KEY}}}


class Export(unittest.TestCase):
    def test_export_redacts(self):
        out = export_import._redact_frontend_config_secrets(CFG)
        self.assertNotIn(KEY, json.dumps(out))
        self.assertEqual(out["agentic"]["jev"]["api_key"], "[REDACTED]")
        self.assertEqual(CFG["agentic"]["jev"]["api_key"], KEY)      # a copy, not the live dict

    def test_import_cannot_set_it(self):
        incoming = {"agentic": {"jev": {"enabled": True, "api_key": "sk-or-attacker"}}}
        with mock.patch.object(export_import, "load_frontend_config", return_value=CFG):
            out = export_import._protect_frontend_config_credentials(incoming)
        self.assertEqual(out["agentic"]["jev"]["api_key"], KEY)
        with mock.patch.object(export_import, "load_frontend_config", return_value={}):
            out = export_import._protect_frontend_config_credentials(incoming)
        self.assertEqual(out["agentic"]["jev"]["api_key"], "")


class DbDownload(unittest.TestCase):
    def test_redacted_copy(self):
        try:
            from routes import db_routes
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        d = tempfile.mkdtemp()
        db = os.path.join(d, "intact.db")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE secrets (key TEXT, value TEXT)")
        c.execute("CREATE TABLE frontend_config (key TEXT, value TEXT)")
        c.execute("INSERT INTO frontend_config VALUES ('agentic', ?)", (json.dumps(CFG["agentic"]),))
        c.commit()
        c.close()
        tmp = db_routes._make_redacted_backup_copy(db)
        try:
            with open(tmp, "rb") as fh:
                self.assertNotIn(KEY.encode(), fh.read())
        finally:
            os.unlink(tmp)
        with open(db, "rb") as fh:
            self.assertIn(KEY.encode(), fh.read())                   # live file untouched


if __name__ == "__main__":
    unittest.main()
